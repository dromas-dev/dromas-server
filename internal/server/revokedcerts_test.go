package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Revoking certificates (PROTOCOL.md §10.2) as this server enforces it: the
// identity signs a revocation of every certificate through a serial, with no
// pass, and the address goes on. The server keeps the highest one and serves
// it in every read of the box, takes no pass and no prekey statement under a
// revoked certificate, and sends nobody to a prekey under one.

// certs is the revocation of r's certificates through a serial, signed by its
// identity, in the record that carries it.
func (r *raw) certs(through uint64) protocol.Revocations {
	r.e.t.Helper()
	l, err := protocol.NewRevokedCertificates(r.id.Address(), through)
	if err != nil {
		r.e.t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(r.signer, l)
	if err != nil {
		r.e.t.Fatal(err)
	}
	return protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: l.Statement(), RevokedCertificatesSignature: sig}
}

// sendTo posts an age file sealed to the prekey of to's given serial, naming
// that serial and a certificate serial, with from's pass under its
// certificate of the serial given.
func (e *env) sendTo(to *raw, serial, under uint64, from *raw, fromUnder uint64) reply {
	e.t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return e.do("POST", to.path("/messages"), sealedTo(serial, under, ct.Bytes()), from.pass(fromUnder))
}

// A stored revocation of certificates that does not parse is an error
// wherever it is read, never "nothing revoked": nothing this server writes
// is one, so one in the store is a fault, and a fault must not take back
// what the identity revoked. A pass under the box's certificate, a send to
// the box and a revocation of its certificates each fail and take nothing,
// and Box.revocations, which a store reads when it adds revocations to what
// it holds, is an error too.
func TestAStoredListThatDoesNotParseIsAnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r, other := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	bad := []byte("not a revocation of certificates\n")
	if err := e.store.Revoke(ctx, r.id.Address(), &Revocations{Identity: r.id.Document(), Certs: bad, CertsSig: []byte("x"), Through: 1}, ExpectAnything); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]reply{
		"a list under the box's certificate": e.do("GET", r.path("/messages"), nil, r.pass(1)),
		"a send to the box":                  e.sendTo(r, 1, 1, other, 1),
		"a revocation of its certificates":   e.do("PUT", r.path("/revocations"), r.certs(1), ""),
	} {
		if got.status != 503 {
			t.Errorf("%s, with a stored list that does not parse: %d %s", name, got.status, got.body)
		}
	}
	if n, _ := e.store.Count(ctx, r.id.Address()); n != 0 {
		t.Errorf("the box holds %d messages", n)
	}
	if _, err := (&Box{Identity: r.id.Document(), RevokedCerts: bad}).revocations(); err == nil {
		t.Error("a box whose list does not parse gives its revocations")
	}
}

func TestRevokedCertificates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r, other := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	put := func(serial, under uint64) reply {
		return e.do("PUT", r.path("/prekey"), r.upload(serial), r.pass(under))
	}
	r.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(2, 2), 200, "") // the box stands at certificate 2, prekey 2
	path := r.path("/revocations")
	good := r.certs(1)

	// What is not a revocation of this box's certificates, each of it well
	// signed by someone.
	byWork, err := protocol.Sign(r.work[2], good.RevokedCertificates, protocol.RevokedCertsNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	blank := append(bytes.Clone(good.RevokedCertificates), '\n')
	blankSig, err := protocol.Sign(r.signer, blank, protocol.RevokedCertsNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	asRevocation, err := protocol.Sign(r.signer, good.RevokedCertificates, protocol.RevokeNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	theirs := other.certs(1)
	for name, bad := range map[string]struct {
		body any
		code protocol.Code
	}{
		"a working key of the box, under its certificate":  {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: byWork}, protocol.CodeBadRevocation},
		"another box's, with this box's document":          {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: theirs.RevokedCertificates, RevokedCertificatesSignature: theirs.RevokedCertificatesSignature}, protocol.CodeBadRevocation},
		"the identity's signature in another namespace":    {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: asRevocation}, protocol.CodeBadRevocation},
		"a blank line after it, which the identity signed": {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: blank, RevokedCertificatesSignature: blankSig}, protocol.CodeBadRevocation},
		"another box's whole record":                       {theirs, protocol.CodeIdentityMismatch},
		"a statement and no signature":                     {[]byte(`{"identity":"` + string(mustJSONBytes(t, r.id.Document())) + `","revoked_certificates":"eA=="}`), protocol.CodeBadRequest},
		"a signature and no statement":                     {[]byte(`{"identity":"` + string(mustJSONBytes(t, r.id.Document())) + `","revoked_certificates_signature":"eA=="}`), protocol.CodeBadRequest},
	} {
		if got := e.do("PUT", path, bad.body, ""); got.status != 400 || got.code() != bad.code {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, got.status, got.code(), bad.code, got.body)
		}
	}
	// A pass does not help: the identity's signature is the authority.
	e.want(e.do("PUT", path, protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: byWork}, r.pass(2)), 400, protocol.CodeBadRevocation)
	unrevoked := e.do("GET", r.path(""), nil, "")
	e.want(unrevoked, 200, "")
	if got := held(t, unrevoked); got != nil {
		t.Fatalf("what was refused is shown: %s", unrevoked.body)
	}

	// The revocation, with no pass: the address goes on, and anyone who
	// reads the box is shown it, as it was put.
	e.want(e.do("PUT", path, good, ""), 200, "")
	stored, err := e.store.Box(ctx, r.id.Address())
	if err != nil || stored.State != Active || !bytes.Equal(stored.RevokedCerts, good.RevokedCertificates) || !bytes.Equal(stored.RevokedCertsSig, good.RevokedCertificatesSignature) {
		t.Fatalf("the record after a revocation of certificates: %+v, %v", stored, err)
	}
	shown := e.do("GET", r.path(""), nil, "")
	e.want(shown, 200, "")
	got := held(t, shown)
	if got == nil || !bytes.Equal(got.RevokedCertificates, good.RevokedCertificates) || !bytes.Equal(got.RevokedCertificatesSignature, good.RevokedCertificatesSignature) {
		t.Fatalf("a box with its certificates revoked is not read with what was put: %s", shown.body)
	}
	if l, err := protocol.VerifyRevokedCertificates(r.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || l.Through != 1 || !l.Revokes(1) || l.Revokes(2) {
		t.Fatalf("what the server shows for a box with its certificates revoked does not verify: %+v, %v", l, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(shown.body, &members); err != nil || len(members) != 5 || members["revocation_signature"] != nil || members["type"] != nil ||
		members["revoked_certificates"] == nil || members["revoked_certificates_signature"] == nil {
		t.Errorf("the box is read with %d members, want its identity, prekey and signature, then the statement and its signature: %s", len(members), shown.body)
	}
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")
	e.want(e.sendTo(other, 1, 1, r, 2), 201, "")
	e.want(e.sendTo(r, 2, 2, other, 1), 201, "")

	// The same one again changes nothing.
	e.want(e.do("PUT", path, good, ""), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")

	// One through the box's current certificate. No pass of the box is
	// taken, as an owner or as a sender, though the server took this very
	// pass a moment ago; nobody is sent to its prekey; and nothing under that
	// certificate is taken as a prekey, the current statement included.
	seen := r.pass(2)
	e.want(e.do("GET", r.path("/messages"), nil, seen), 200, "")
	current := r.certs(2)
	e.want(e.do("PUT", path, current, ""), 200, "")
	// The highest stands: one through a lower serial is refused, so what was
	// revoked stays revoked.
	e.want(e.do("PUT", path, good, ""), 409, protocol.CodeConflict)
	e.want(e.do("GET", r.path("/messages"), nil, seen), 401, protocol.CodeCertificateRevoked)
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 401, protocol.CodeCertificateRevoked)
	e.want(e.do("GET", r.path("/acl"), nil, r.pass(2)), 401, protocol.CodeCertificateRevoked)
	e.want(e.sendTo(other, 1, 1, r, 2), 401, protocol.CodeCertificateRevoked)
	e.want(e.sendTo(r, 2, 2, other, 1), 409, protocol.CodePrekeyExpired)
	e.want(put(2, 2), 401, protocol.CodeCertificateRevoked)
	r.prekeyUnder(r.work[2], 3, now.Add(time.Hour), nil)
	e.want(put(3, 2), 401, protocol.CodeCertificateRevoked)
	if n, _ := e.store.Count(ctx, r.id.Address()); n != 1 {
		t.Errorf("the box holds %d messages after its certificate was revoked, want the 1 it had", n)
	}
	shown = e.do("GET", r.path(""), nil, "")
	e.want(shown, 200, "")
	if got = held(t, shown); got == nil || !bytes.Equal(got.RevokedCertificates, current.RevokedCertificates) || !bytes.Equal(got.RevokedCertificatesSignature, current.RevokedCertificatesSignature) {
		t.Fatalf("a box with its current certificate revoked is not read with the highest revocation put: %s", shown.body)
	}

	// It comes back with a prekey under a new certificate, which needs no
	// pass under the old one.
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(3, 3), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(3)), 200, "")
	e.want(e.sendTo(r, 2, 2, other, 1), 409, protocol.CodeStalePrekey)
	e.want(e.sendTo(r, 3, 3, other, 1), 201, "")
	e.want(e.sendTo(other, 1, 1, r, 3), 201, "")

	// One may run through a serial no certificate has yet: none at or below
	// it is then taken, and the next one above is.
	e.want(e.do("PUT", path, r.certs(4), ""), 200, "")
	r.prekey(4, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(4, 4), 401, protocol.CodeCertificateRevoked)
	r.prekey(5, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(5, 5), 200, "")

	// A revocation of the address may come with one of its certificates.
	// Everything in a body is checked before anything is changed: a good
	// revocation of certificates with what is not a revocation of the
	// address, and the other way about, each change nothing.
	both := other.certs(1)
	if both.Revocation, err = protocol.SignRevocation(other.signer, other.id.Address()); err != nil {
		t.Fatal(err)
	}
	halfList, halfRevocation := both, both
	halfList.Revocation = []byte("revoke it")
	halfRevocation.RevokedCertificatesSignature = byWork
	e.want(e.do("PUT", other.path("/revocations"), halfList, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", other.path("/revocations"), halfRevocation, ""), 400, protocol.CodeBadRevocation)
	if stored, err = e.store.Box(ctx, other.id.Address()); err != nil || stored.State != Active || len(stored.RevokedCerts) != 0 || len(stored.Revocation) != 0 {
		t.Fatalf("a body that verified in part changed the record: %+v, %v", stored, err)
	}
	unrevoked = e.do("GET", other.path(""), nil, "")
	e.want(unrevoked, 200, "")
	if got = held(t, unrevoked); got != nil {
		t.Fatalf("a body that verified in part is shown: %s", unrevoked.body)
	}
	// Whole, both are kept, and both are shown: the box's read is 410 with a
	// record of both. A revoked box takes nothing more: whatever is sent for
	// it is answered from its record.
	e.want(e.do("PUT", other.path("/revocations"), both, ""), 201, "")
	shown = e.do("GET", other.path(""), nil, "")
	e.want(shown, 410, protocol.CodeRevoked)
	if got = held(t, shown); got == nil || !bytes.Equal(got.Revocation, both.Revocation) ||
		!bytes.Equal(got.RevokedCertificates, both.RevokedCertificates) || !bytes.Equal(got.RevokedCertificatesSignature, both.RevokedCertificatesSignature) {
		t.Fatalf("a revoked box that had its certificates revoked is not read with both: %s", shown.body)
	}
	if _, err := protocol.VerifyRevocation(other.id.Address(), got.Identity, got.Revocation); err != nil {
		t.Errorf("the revocation in the record does not verify: %v", err)
	}
	if _, err := protocol.VerifyRevokedCertificates(other.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil {
		t.Errorf("the revocation of certificates in the record does not verify: %v", err)
	}
	if written, members := recordOf(t, shown); len(members) != 5 || string(members["type"]) != `"revocation_record"` || !bytes.HasPrefix(written, []byte(`{"type":"revocation_record",`)) {
		t.Errorf("the record served for a revoked box that had its certificates revoked has %d members, want its type first and 4: %s", len(members), shown.body)
	}
	e.want(e.do("PUT", other.path("/revocations"), other.certs(2), ""), 410, protocol.CodeRevoked)
	e.want(e.do("PUT", other.path("/revocations"), both, ""), 410, protocol.CodeRevoked)
}

// A box whose certificates were revoked is read with the revocation: the 200
// carries it beside the box's identity and prekey, the bytes that were put,
// and always the highest held, so a sender has it before it posts with no
// second call. A box nobody revoked carries none.
func TestABoxIsReadWithTheRevocationOfItsCertificates(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekey(10, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(10), r.pass(10)), 200, "") // the box stands at certificate 10
	read := func() protocol.BoxResponse {
		t.Helper()
		rep := e.do("GET", r.path(""), nil, "")
		e.want(rep, 200, "")
		var b protocol.BoxResponse
		if err := protocol.Unmarshal(rep.body, &b); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Identity, r.id.Document()) || !bytes.Equal(b.Prekey, r.stmt[10]) || !bytes.Equal(b.PrekeySignature, r.sig[10]) {
			t.Fatalf("the box is not read as it stands: %s", rep.body)
		}
		return b
	}
	if b := read(); b.Record() != nil || b.RevokedCertificates != nil || b.RevokedCertificatesSignature != nil {
		t.Fatalf("a box nobody revoked is read with a revocation of certificates: %+v", b)
	}
	three, five := r.certs(3), r.certs(5)
	for _, c := range []struct {
		put    protocol.Revocations
		status int
		code   protocol.Code
	}{
		{three, 200, ""},
		{five, 200, ""},
		{three, 409, protocol.CodeConflict}, // the highest stands
	} {
		e.want(e.do("PUT", r.path("/revocations"), c.put, ""), c.status, c.code)
	}
	b := read()
	rec := b.Record()
	if rec == nil || !bytes.Equal(b.RevokedCertificates, five.RevokedCertificates) || !bytes.Equal(b.RevokedCertificatesSignature, five.RevokedCertificatesSignature) {
		t.Fatalf("the box is not read with the highest revocation of certificates put: %+v", b)
	}
	if l, err := protocol.VerifyRevokedCertificates(r.id.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil || l.Through != 5 || l.Revokes(10) {
		t.Fatalf("the revocation of certificates the box is read with does not verify: %+v, %v", l, err)
	}
}

// A body that is not a revocation of certificates costs the server a
// signature check that nothing has paid for, as one that is not a revocation
// of the address does.
func TestJunkRevocationsOfCertificatesAreLimited(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	junk := protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: []byte("every certificate\n"), RevokedCertificatesSignature: []byte("revoke them")}
	path := r.path("/revocations")
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 429, protocol.CodeRateLimited)
	e.clock.Add(protocol.MaxSkew) // long past the limit's minute
	e.want(e.do("PUT", path, r.certs(1), ""), 200, "")
}

// The Go client against this server: a box renews and revokes every
// certificate before its new one. Mail it sent under the old one is refused
// by its reader, who is shown the revocation and checks it; mail under the new one
// is delivered; and the box, whose working key before the renewal is now
// worth nothing here, goes on at its address.
func TestTheClientRevokesItsEarlierCertificates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "under A's first certificate")
	taken, old := worker(t, a), e.pass(a)
	_, first := e.numbers(a.Address())
	if _, err := a.Rekey(ctx, protocol.Classic); err != nil {
		t.Fatal(err)
	}
	_, second := e.numbers(a.Address())
	certs, err := a.RevokeEarlier(ctx)
	if err != nil || certs == nil || second <= first || !certs.Revokes(first) || certs.Revokes(second) {
		t.Fatalf("RevokeEarlier: %+v, %v", certs, err)
	}
	// The working key from before: its pass is refused as under another
	// certificate than the current one, revoked or not, which the answer
	// names (IronGall-dev/irongall-client#263), and a prekey it signs at the
	// highest serial there is, is refused too.
	e.wantNotCurrent(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, old), second)
	key, _ := age.GenerateX25519Identity()
	top := &protocol.Prekey{Address: a.Address(), Serial: protocol.MaxSerial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	sig, err := protocol.Sign(taken, top.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: top.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name())), 401, protocol.CodeCertificateRevoked)

	send(t, a, b, "under A's second certificate")
	res := receive(t, b)
	if len(res.Delivered) != 1 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate || string(res.Delivered[0].Envelope.Body) != `"under A's second certificate"` {
		t.Fatalf("B's drain of mail from a box that revoked its first certificate: %+v", res)
	}
	send(t, b, a, "to A at its second certificate")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("A's drain after its renewal: %+v", res)
	}
}

// A box's statements are ordered by certificate first, so a prekey published
// at the highest serial there is, with a working key someone took, does not
// end the address: the box's next renewal passes it, and its senders follow.
func TestAPrekeyAtTheHighestSerialDoesNotEndTheAddress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	taken := worker(t, a)
	_, first := e.numbers(a.Address())
	key, _ := age.GenerateX25519Identity()
	top := &protocol.Prekey{Address: a.Address(), Serial: protocol.MaxSerial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	sig, err := protocol.Sign(taken, top.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: top.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name())), 200, "")
	send(t, b, a, "encrypted to the prekey the thief published")
	if _, err := a.Rekey(ctx, protocol.Classic); err != nil {
		t.Fatalf("a renewal after a prekey at the highest serial: %v", err)
	}
	stored, err := e.store.Box(ctx, a.Address())
	if err != nil || stored.CertSerial <= first || stored.Prekey.Serial != stored.CertSerial || stored.Prekey.Serial >= protocol.MaxSerial {
		t.Fatalf("the record after the renewal: certificate %d, prekey %d, %v", stored.CertSerial, stored.Prekey.Serial, err)
	}
	send(t, b, a, "to the box's own prekey again")
	res := receive(t, a)
	if len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"to the box's own prekey again"` {
		t.Fatalf("A's drain after the renewal: %+v", res)
	}
}

// The revocation of certificates is in the box's record, so a process that
// starts later serves the same one and refuses the same pass: nothing about a
// revoked certificate lives only in the memory of the process that took the
// revocation. AWS only: the in-memory store has one process.
func TestARevocationOfCertificatesOutlivesTheProcess(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	rec := r.certs(1)
	e.want(e.do("PUT", r.path("/revocations"), rec, ""), 200, "")

	later := startDynamo(t, e.clock.Now) // its memory holds nothing of the box
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: later, Limits: relaxed(), Now: e.clock.Now, Ready: later.Ready}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	r2 := *r
	r2.e = e2
	e2.want(e2.do("GET", r.path("/messages"), nil, r2.pass(1)), 401, protocol.CodeCertificateRevoked)
	shown := e2.do("GET", r.path(""), nil, "")
	e2.want(shown, 200, "")
	got := held(t, shown)
	if got == nil {
		t.Fatalf("a later process reads a box with its certificates revoked without the revocation: %s", shown.body)
	}
	if _, err := protocol.VerifyRevokedCertificates(r.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || !bytes.Equal(got.RevokedCertificates, rec.RevokedCertificates) {
		t.Fatalf("what a later process shows for a box with its certificates revoked: %v", err)
	}
	e2.want(e2.do("PUT", r.path("/revocations"), rec, ""), 200, "")
	r2.prekey(2, e.clock.Now().Add(time.Hour), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r2.upload(2), r2.pass(2)), 200, "")
	e2.want(e2.do("GET", r.path("/messages"), nil, r2.pass(2)), 200, "")
}

// A revocation of certificates is kept apart from the box's record, in its
// address's revocations item, which nothing but a higher one replaces. What
// memory holds of a loaded box and the box read whole say the same of it:
// whether it covers the box's current certificate. The record carries none
// of it.
func TestTheStandingKnowsTheRevokedCertificates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekey(3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "") // the box stands at certificate 3
	if _, err := e.store.Count(ctx, r.id.Address()); err != nil {           // a process that has loaded it
		t.Fatal(err)
	}
	for i, c := range []struct {
		through uint64
		listed  bool
	}{
		{0, false},
		{2, false},
		{3, true},
	} {
		if c.through != 0 {
			e.want(e.do("PUT", r.path("/revocations"), r.certs(c.through), ""), 200, "")
		}
		b, err := e.store.Box(ctx, r.id.Address())
		if err != nil {
			t.Fatal(err)
		}
		whole, ok, err := b.standing()
		mem, held := e.store.Held(r.id.Address())
		if err != nil || !ok || !held || whole.Listed != c.listed || mem.Listed != c.listed {
			t.Errorf("case %d: the box read whole says listed %v (%v), memory says %v (held %v), want %v", i, whole.Listed, err, mem.Listed, held, c.listed)
		}
		if c.through != 0 && (len(b.RevokedCerts) == 0 || len(b.RevokedCertsSig) == 0) {
			t.Errorf("case %d: the box is read without its revocation of certificates", i)
		}
		for _, name := range []string{"revocation", "revoked_certs", "revoked_certs_sig", "through"} {
			if _, ok := boxItem(b)[name]; ok {
				t.Errorf("case %d: the record carries %s", i, name)
			}
		}
	}
}

// A holder of a box's working key spends the box's renewals for the day, and
// holds nothing by it: a renewal under a later certificate is the identity's
// act, counted apart (Limits.CertificatesPerDay), so the owner's remedy renews
// and revokes the taken certificate the same day. From then on this server
// takes nothing more under that certificate.
func TestTheRemedyRenewsWhenATakerSpentTheDaysRenewals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.RenewalsPerDay = DefaultLimits().RenewalsPerDay
	l.CertificatesPerDay = DefaultLimits().CertificatesPerDay
	e := newEnv(t, l)
	a := e.box(protocol.Classic)
	taken := worker(t, a)
	_, inUse := e.numbers(a.Address())
	thief := func(serial uint64) reply {
		key, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		p := &protocol.Prekey{Address: a.Address(), Serial: serial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
		sig, err := protocol.Sign(taken, p.Statement(), protocol.PrekeyNamespace(a.Address()))
		if err != nil {
			t.Fatal(err)
		}
		return e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: p.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name()))
	}
	for i := range l.RenewalsPerDay {
		e.want(thief(inUse+uint64(i)+1), 200, "")
	}
	e.limited(thief(inUse+uint64(l.RenewalsPerDay)+1), protocol.QuotaRenewals) // the taker is out of renewals
	r, err := a.RenewAndRevoke(ctx, protocol.Classic)
	if err != nil || r == nil || r.NotRenewed != nil || r.Prekey == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) || r.Revoked.Revokes(r.Below) {
		t.Fatalf("the owner's remedy after the taker's renewals: %+v, %v", r, err)
	}
	e.want(thief(inUse+100), 401, protocol.CodeCertificateRevoked)
	if _, cert := e.numbers(a.Address()); cert != r.Below {
		t.Fatalf("the box stands at certificate %d, not the one the remedy made, %d", cert, r.Below)
	}
}

// The box's current statement, registered again once its identity revoked
// the certificate it is signed under, is refused before its pass, as the
// same statement sent to PUT …/prekey is (PROTOCOL.md §11.7 step 5, §10.2):
// nothing under that certificate is taken, an identical retry included.
func TestAnIdenticalRegistrationUnderARevokedCertificateIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 200, "")
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), 200, "")
	for _, pass := range []string{r.pass(1), ""} {
		e.want(e.do("PUT", r.path("/prekey"), r.upload(1), pass), 401, protocol.CodeCertificateRevoked)
		e.want(e.do("PUT", r.path(""), r.registration(1), pass), 401, protocol.CodeCertificateRevoked)
	}
}
