package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Revocation (PROTOCOL.md §10.1) as this server enforces it: the identity's
// own signature over the fixed statement ends a mailbox for good, with no pass,
// and nothing else does. The server keeps the signature and serves it, in
// the 410 a read of the mailbox answers, so that nobody has to take its word
// that a mailbox is revoked.

func revocationPath(a protocol.Address) string { return "/v1/" + a.String() + "/revocations" }

func mailboxPath(a protocol.Address) string { return "/v1/" + a.String() }

// held is the revocation record a read of a mailbox (GET /v1/<address>) shows,
// read as a client reads it: the 200's revocation of certificates, or the
// 410's record. Nil when it shows none.
func held(t *testing.T, r reply) *protocol.Revocations {
	t.Helper()
	switch r.status {
	case 200:
		var b protocol.MailboxResponse
		if err := protocol.Unmarshal(r.body, &b); err != nil {
			t.Fatalf("the read of a mailbox: %v: %s", err, r.body)
		}
		return b.Record()
	case 410:
		var p protocol.Problem
		if err := protocol.Unmarshal(r.body, &p); err != nil {
			t.Fatalf("the read of a revoked mailbox: %v: %s", err, r.body)
		}
		return p.Record
	}
	t.Fatalf("the read of a mailbox: %d %s", r.status, r.body)
	return nil
}

// recordOf is the record a 410 carries as it was written, and its members.
func recordOf(t *testing.T, r reply) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	var p struct {
		Record json.RawMessage `json:"record"`
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &p); err != nil || json.Unmarshal(p.Record, &members) != nil {
		t.Fatalf("no record in %s", r.body)
	}
	return p.Record, members
}

// record is a mailbox's own revocation, as its owner makes it.
func record(t *testing.T, b *client.Mailbox) *protocol.Revocations {
	t.Helper()
	rec, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b, c := e.mailbox(), e.mailbox(), e.mailbox()
	send(t, b, a, "waiting in A's mailbox when it is revoked")
	send(t, a, b, "sent by A before it was revoked")
	passA := e.pass(a)
	rec := record(t, a)
	path := revocationPath(a.Address())
	read := mailboxPath(a.Address())

	// Nothing is held about a mailbox that is not revoked: its read is 200 and
	// shows none. There is none of no mailbox.
	unrevoked := e.do("GET", read, nil, "")
	e.want(unrevoked, 200, "")
	if got := held(t, unrevoked); got != nil {
		t.Fatalf("a mailbox nobody revoked is read with a revocation: %s", unrevoked.body)
	}
	e.want(e.do("GET", mailboxPath(protocol.Address{1}), nil, ""), 404, protocol.CodeNoSuchMailbox)

	// What is not a revocation of A, each of it well signed by someone.
	docA, docB := a.Identity().Document(), b.Identity().Document()
	sign := func(by *client.Mailbox, of protocol.Address, namespace string) []byte {
		t.Helper()
		sig, err := protocol.Sign(worker(t, by), protocol.RevocationStatement(of), namespace)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	ofB := record(t, b)
	recJSON, _ := json.Marshal(rec)
	for name, bad := range map[string]struct {
		body any
		code protocol.Code
	}{
		"a working key of A, under A's certificate": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"B's revocation, with A's document":         {protocol.Revocations{Identity: docA, Revocation: ofB.Revocation}, protocol.CodeBadRevocation},
		"a working key of A, as a prekey statement": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.PrekeyNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"not a signature":                           {protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, protocol.CodeBadRevocation},
		"A's own, over the bound":                   {protocol.Revocations{Identity: docA, Revocation: append(append([]byte{}, rec.Revocation...), bytes.Repeat([]byte{'.'}, protocol.MaxSignature+1-len(rec.Revocation))...)}, protocol.CodeBadRevocation},
		"B's document":                              {protocol.Revocations{Identity: docB, Revocation: rec.Revocation}, protocol.CodeIdentityMismatch},
		"B's whole record":                          {ofB, protocol.CodeIdentityMismatch},
		"no signature":                              {[]byte(`{"identity":"` + string(mustJSONBytes(t, docA)) + `"}`), protocol.CodeBadRequest},
		"no document":                               {[]byte(`{"revocation_signature":"eA=="}`), protocol.CodeBadRequest},
		"a member the body does not have":           {[]byte(`{"identity":"eA==","revocation_signature":"eA==","reason":"lost"}`), protocol.CodeBadRequest},
		"not JSON":                                  {[]byte(`revoke`), protocol.CodeBadRequest},
		"a name in another case":                    {bytes.Replace(recJSON, []byte(`"revocation_signature"`), []byte(`"Revocation_Signature"`), 1), protocol.CodeBadRequest},
		"a name twice":                              {bytes.Replace(recJSON, []byte(`{`), []byte(`{"revocation_signature":"eA==",`), 1), protocol.CodeBadRequest},
		"a second value after it":                   {append(append([]byte{}, recJSON...), "{}"...), protocol.CodeBadRequest},
		"base64 with its unused bits set":           {unusedBitsSet(t, recJSON), protocol.CodeBadEncoding},
		"a record of another type":                  {bytes.Replace(recJSON, []byte(`"type":"revocation_record"`), []byte(`"type":"revocation"`), 1), protocol.CodeBadRequest},
	} {
		if r := e.do("PUT", path, bad.body, ""); r.status != 400 || r.code() != bad.code {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, r.status, r.code(), bad.code, r.body)
		}
	}
	// A record of another type is refused by name, as a member the body does
	// not have is.
	other := e.do("PUT", path, bytes.Replace(recJSON, []byte(`"type":"revocation_record"`), []byte(`"type":""`), 1), "")
	var p protocol.Problem
	if err := json.Unmarshal(other.body, &p); err != nil || other.status != 400 || p.Code != protocol.CodeBadRequest || p.Member != "type" {
		t.Errorf("a record whose type is empty: %d %s", other.status, other.body)
	}
	// A pass does not revoke, nor does it help: the signature is the authority.
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, passA), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", revocationPath(protocol.Address{1}), rec, ""), 400, protocol.CodeIdentityMismatch)
	// After all of that the mailbox is as it was.
	unrevoked = e.do("GET", read, nil, "")
	e.want(unrevoked, 200, "")
	if got := held(t, unrevoked); got != nil {
		t.Fatalf("what was refused is shown: %s", unrevoked.body)
	}
	if n, _ := e.store.Count(ctx, a.Address()); n != 1 {
		t.Fatalf("A holds %d messages before it is revoked, want 1", n)
	}
	send(t, c, a, "A still takes messages")

	// The revocation, with no pass: 201, and the mailbox is gone for good.
	first := e.do("PUT", path, rec, "")
	e.want(first, 201, "")
	if string(first.body) != "{}\n" && string(first.body) != "{}" {
		t.Errorf("the answer to a revocation: %q", first.body)
	}
	stored, err := e.store.Mailbox(ctx, a.Address())
	if err != nil || stored.State != Revoked || string(stored.Revocation) != string(rec.Revocation) {
		t.Fatalf("what is held after a revocation: %+v, %v", stored, err)
	}
	if stored.hasRecord() {
		t.Errorf("the mailbox's record outlived the revocation of its address: rev %d", stored.Rev)
	}
	if n, _ := e.store.Count(ctx, a.Address()); n != 0 {
		t.Errorf("a revoked mailbox still holds %d messages", n)
	}

	// Everyone is told, and anyone who reads the mailbox is shown why: its 410
	// carries the record.
	shown := e.do("GET", read, nil, "")
	e.want(shown, 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, passA), 410, protocol.CodeRevoked)
	got := held(t, shown)
	if got == nil {
		t.Fatalf("a revoked mailbox is read with no record: %s", shown.body)
	}
	if id, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || id.Address() != a.Address() || !bytes.Equal(got.Revocation, rec.Revocation) {
		t.Fatalf("what the server shows for a revoked mailbox does not verify: %v", err)
	}
	if written, members := recordOf(t, shown); len(members) != 3 || !bytes.HasPrefix(written, []byte(`{"type":"revocation_record",`)) {
		t.Errorf("the record served has %d members, want its type first, then identity and revocation: %s", len(members), shown.body)
	}

	// The clients meet it and check it for themselves.
	var gone *client.RevokedError
	if _, err := c.Send(ctx, a.Address(), "to a revoked mailbox"); !errors.As(err, &gone) || gone.Address != a.Address() || gone.Own {
		t.Fatalf("a send to a revoked mailbox: %v", err)
	}
	if _, err := a.Send(ctx, c.Address(), "from a revoked mailbox"); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a send from a revoked mailbox: %v", err)
	}
	if _, err := a.Receive(ctx); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a revoked mailbox's poll: %v", err)
	}
	// The message A sent before is refused by its reader, who is shown the same proof.
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("messages from a mailbox revoked since: %+v", res)
	}

	// Nothing brings it back: not a registration, not a new prekey, and a
	// second revocation changes nothing. Whatever is sent for a revoked mailbox
	// is answered from its record, with no check: nothing could change it.
	if _, err := a.Rekey(ctx); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a revoked mailbox's renewal: %v", err)
	}
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, ""), 410, protocol.CodeRevoked)
	e.want(e.do("GET", read, nil, ""), 410, protocol.CodeRevoked)
}

// A server keeps a revocation for an address it has no mailbox for (PROTOCOL.md
// §11.15): of an address never registered, and of one whose mailbox it forgot.
// It serves it at the address's revocations, and at the read of the mailbox too
// once the address itself is revoked, and holds a later registration to it:
// 410 while the address is revoked, and nothing under a certificate its
// identity revoked. A revocation of certificates alone leaves the read 404,
// and a registration above it carries it.
func TestARevocationIsKeptWithNoMailbox(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()

	// Certificates revoked of an address nobody registered: kept, served,
	// and a registration under one of them refused.
	r := e.raw()
	floor := r.certs(5)
	e.want(e.do("PUT", r.path("/revocations"), floor, ""), 200, "")
	e.want(e.do("GET", r.path(""), nil, ""), 404, protocol.CodeNoSuchMailbox)
	got := e.do("GET", r.path("/revocations"), nil, "")
	e.want(got, 200, "")
	var served protocol.Revocations
	if err := json.Unmarshal(got.body, &served); err != nil || !bytes.Equal(served.RevokedCertificates, floor.RevokedCertificates) || served.Revocation != nil {
		t.Fatalf("the revocation of certificates of an address with no mailbox: %s", got.body)
	}
	e.want(e.do("PUT", r.path("/revocations"), floor, ""), 200, "")                         // the same one again changes nothing
	e.want(e.do("PUT", r.path("/revocations"), r.certs(4), ""), 409, protocol.CodeConflict) // nor does one that revokes fewer
	r.prekey(5, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r.registration(5), r.pass(5)), 401, protocol.CodeCertificateRevoked)
	r.prekey(6, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r.registration(6), r.pass(6)), 201, "")
	if b := held(t, e.do("GET", r.path(""), nil, "")); b == nil || !bytes.Equal(b.RevokedCertificates, floor.RevokedCertificates) {
		t.Fatal("a mailbox registered above its identity's revocation of certificates is read without it")
	}

	// Certificates revoked of an address whose mailbox the server forgot: the
	// read of the mailbox answers as if it had never been registered, and its
	// revocations are served (dromas-dev/dromas-server#80).
	d := e.raw().register(protocol.MaxPrekeyLifetime)
	if err := e.store.DeleteMailbox(t.Context(), d.id.Address()); err != nil { // as the TTL deletes it
		t.Fatal(err)
	}
	forgotten := d.certs(1)
	e.want(e.do("PUT", d.path("/revocations"), forgotten, ""), 200, "")
	e.want(e.do("GET", d.path(""), nil, ""), 404, protocol.CodeNoSuchMailbox)
	got = e.do("GET", d.path("/revocations"), nil, "")
	e.want(got, 200, "")
	served = protocol.Revocations{}
	if err := json.Unmarshal(got.body, &served); err != nil || !bytes.Equal(served.RevokedCertificates, forgotten.RevokedCertificates) {
		t.Fatalf("the revocation of certificates of an address whose mailbox was forgotten: %s", got.body)
	}

	// The address revoked with no mailbox: the read is 410 with the record, and
	// a registration of it is too.
	q := e.raw()
	rev, err := protocol.SignRevocation(q.signer, q.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", q.path("/revocations"), protocol.Revocations{Identity: q.id.Document(), Revocation: rev}, ""), 201, "")
	shown := e.do("GET", q.path(""), nil, "")
	e.want(shown, 410, protocol.CodeRevoked)
	if b := held(t, shown); b == nil || !bytes.Equal(b.Revocation, rev) {
		t.Fatalf("an address revoked with no mailbox is read without its record: %s", shown.body)
	}
	q.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", q.path(""), q.registration(1), q.pass(1)), 410, protocol.CodeRevoked)
}

// Keeping a revocation for an address a server holds nothing of is keeping
// a record for good, so it is counted as a registration is, against its
// caller's address; one for an address with a mailbox, or with revocations
// already, is not.
func TestARevocationWithNoMailboxIsCountedAsARegistration(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RegistrationsPerHour = 1
	e := newEnv(t, l)
	boxed := e.raw().register(protocol.MaxPrekeyLifetime) // the address's one registration this hour
	e.clock.Add(time.Hour)
	e.want(e.do("PUT", boxed.path("/revocations"), boxed.certs(1), ""), 200, "") // a mailbox's: counted against nothing
	none := e.raw()
	e.want(e.do("PUT", none.path("/revocations"), none.certs(1), ""), 200, "")
	e.want(e.do("PUT", none.path("/revocations"), none.certs(2), ""), 200, "") // a raise of what is held
	other := e.raw()
	e.want(e.do("PUT", other.path("/revocations"), other.certs(1), ""), 429, protocol.CodeRateLimited)
	other.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", other.path(""), other.registration(2), other.pass(2)), 429, protocol.CodeRateLimited)
}

// A revoked mailbox is read as its record: 410 revoked, carrying all this server
// holds that the identity signed about the address, which is the revocation,
// and the revocation of its certificates beside it when one was put. Each
// part is the bytes that were put, and verifies, so a client takes "revoked"
// from the one read with no second call and on none of the server's word.
func TestARevokedMailboxIsReadAsItsRecord(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	alone, withCerts := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	certs := withCerts.certs(1)
	e.want(e.do("PUT", withCerts.path("/revocations"), certs, ""), 200, "")
	for name, c := range map[string]struct {
		mailbox *raw
		put     protocol.Revocations
		members int
	}{
		"revoked alone":                         {alone, protocol.Revocations{Identity: alone.id.Document()}, 3},
		"revoked with its certificates revoked": {withCerts, certs, 5},
	} {
		var err error
		if c.put.Revocation, err = protocol.SignRevocation(c.mailbox.signer, c.mailbox.id.Address()); err != nil {
			t.Fatal(err)
		}
		e.want(e.do("PUT", c.mailbox.path("/revocations"), c.put, ""), 201, "")
		shown := e.do("GET", c.mailbox.path(""), nil, "")
		e.want(shown, 410, protocol.CodeRevoked)
		got := held(t, shown)
		if got == nil || !bytes.Equal(got.Identity, c.mailbox.id.Document()) || !bytes.Equal(got.Revocation, c.put.Revocation) ||
			!bytes.Equal(got.RevokedCertificates, c.put.RevokedCertificates) || !bytes.Equal(got.RevokedCertificatesSignature, c.put.RevokedCertificatesSignature) {
			t.Errorf("%s: the record is not what was put: %s", name, shown.body)
			continue
		}
		if id, err := protocol.VerifyRevocation(c.mailbox.id.Address(), got.Identity, got.Revocation); err != nil || id.Address() != c.mailbox.id.Address() {
			t.Errorf("%s: the revocation in the record does not verify: %v", name, err)
		}
		if len(c.put.RevokedCertificates) > 0 {
			if l, err := protocol.VerifyRevokedCertificates(c.mailbox.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || l.Through != 1 {
				t.Errorf("%s: the revocation of certificates in the record does not verify: %+v, %v", name, l, err)
			}
		}
		if written, members := recordOf(t, shown); len(members) != c.members || !bytes.HasPrefix(written, []byte(`{"type":"revocation_record",`)) {
			t.Errorf("%s: the record has %d members, want its type first and %d more: %s", name, len(members), c.members-1, shown.body)
		}
	}
}

// The server keeps and serves a revocation of any address (PROTOCOL.md §11.15):
// it answers GET …/revocations with no pass, with the record it holds of the address, in
// the same bytes the read of the mailbox carries, and 404 not_revoked when it
// holds none, for an address with no mailbox as for one with a mailbox and nothing
// revoked.
func TestTheRevocationsOfAnyAddressAreServed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	none, certsOnly, ended := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("GET", revocationPath(protocol.Address{7}), nil, ""), 404, protocol.CodeNotRevoked)
	e.want(e.do("GET", none.path("/revocations"), nil, ""), 404, protocol.CodeNotRevoked)

	certs := certsOnly.certs(1)
	e.want(e.do("PUT", certsOnly.path("/revocations"), certs, ""), 200, "")
	put := ended.certs(1)
	e.want(e.do("PUT", ended.path("/revocations"), put, ""), 200, "")
	var err error
	if put.Revocation, err = protocol.SignRevocation(ended.signer, ended.id.Address()); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", ended.path("/revocations"), put, ""), 201, "")

	for name, c := range map[string]struct {
		mailbox *raw
		put     protocol.Revocations
		members int
	}{
		"certificates revoked":                  {certsOnly, certs, 4},
		"revoked with its certificates revoked": {ended, put, 5},
	} {
		got := e.do("GET", c.mailbox.path("/revocations"), nil, "")
		e.want(got, 200, "")
		var rec protocol.Revocations
		if err := protocol.Unmarshal(got.body, &rec); err != nil {
			t.Fatalf("%s: %v: %s", name, err, got.body)
		}
		if !bytes.Equal(rec.Identity, c.mailbox.id.Document()) || !bytes.Equal(rec.Revocation, c.put.Revocation) ||
			!bytes.Equal(rec.RevokedCertificates, c.put.RevokedCertificates) || !bytes.Equal(rec.RevokedCertificatesSignature, c.put.RevokedCertificatesSignature) {
			t.Errorf("%s: the record is not what was put: %s", name, got.body)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(got.body, &members); err != nil || len(members) != c.members || !bytes.HasPrefix(got.body, []byte(`{"type":"revocation_record",`)) {
			t.Errorf("%s: the record has %d members, want its type first and %d more: %s", name, len(members), c.members-1, got.body)
		}
		if shown := held(t, e.do("GET", c.mailbox.path(""), nil, "")); !bytes.Equal(shown.RevokedCertificates, rec.RevokedCertificates) || !bytes.Equal(shown.Revocation, rec.Revocation) {
			t.Errorf("%s: the read of the mailbox shows another record than the read of its revocations", name)
		}
	}
}

// A body that is not a revocation costs the server a signature check that
// nothing has paid for, so it counts as a lookup of a mailbox that does not
// exist does, and a revocation that verifies is refused, 429, while the
// caller's address has none left.
func TestJunkRevocationsAreLimited(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	a := e.mailbox()
	junk := protocol.Revocations{Identity: a.Identity().Document(), Revocation: []byte("revoke it")}
	path := revocationPath(a.Address())
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	limited := e.do("PUT", path, junk, "")
	e.want(limited, 429, protocol.CodeRateLimited)
	if limited.header.Get("Retry-After") == "" {
		t.Error("a limited revocation carries no Retry-After")
	}
	e.want(e.do("GET", mailboxPath(a.Address()), nil, ""), 200, "")
	e.clock.Add(protocol.MaxSkew) // long past the limit's minute
	e.want(e.do("PUT", path, record(t, a), ""), 201, "")
}

// No cache may keep an answer of the API: a mailbox's prekey changes daily and a
// mailbox can be revoked at any moment, and a 410 is cacheable unless it says
// otherwise. The page a link opens is the one answer that may be kept.
func TestNoAnswerOfTheAPIIsStored(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a := e.mailbox()
	base := "/v1/" + a.Address().String()
	check := func(r reply, what string) {
		t.Helper()
		if got := r.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", what, got)
		}
	}
	check(e.do("GET", base, nil, ""), "a mailbox")
	check(e.do("GET", mailboxPath(protocol.Address{1}), nil, ""), "a 404")
	check(e.do("GET", base+"/messages", nil, e.pass(a)), "a list")
	check(e.do("GET", base+"/messages", nil, ""), "a 401")
	e.want(e.do("PUT", base+"/revocations", record(t, a), ""), 201, "")
	check(e.do("GET", base, nil, ""), "a 410 with its revocation")
	if got := e.do("GET", protocol.LinkPath+a.Address().String(), nil, "").header.Get("Cache-Control"); got == "no-store" || got == "" {
		t.Errorf("the link page: Cache-Control %q", got)
	}
}

func mustJSONBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	j, err := json.Marshal(protocol.Bytes(b))
	if err != nil {
		t.Fatal(err)
	}
	return j[1 : len(j)-1]
}

// The revocation is in the address's revocations item, so a process that starts later, or
// another one beside this, serves the same proof and the same 410: nothing
// about a revoked mailbox lives only in the memory of the process that took the
// revocation. AWS only: the in-memory store has one process.
func TestARevocationOutlivesTheProcess(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	a := e.mailbox()
	rec := record(t, a)
	e.want(e.do("PUT", revocationPath(a.Address()), rec, ""), 201, "")

	later := startDynamo(t, e.clock.Now) // its memory holds nothing of A
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: later, Limits: relaxed(), Now: e.clock.Now, Ready: later.Ready}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	shown := e2.do("GET", mailboxPath(a.Address()), nil, "")
	e2.want(shown, 410, protocol.CodeRevoked)
	got := held(t, shown)
	if got == nil {
		t.Fatalf("a later process reads a revoked mailbox with no record: %s", shown.body)
	}
	if _, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || string(got.Revocation) != string(rec.Revocation) {
		t.Fatalf("what a later process shows for a revoked mailbox: %v", err)
	}
	e2.want(e2.do("PUT", revocationPath(a.Address()), rec, ""), 410, protocol.CodeRevoked) // and answers what is sent for it from that record
}

// watchedStore is a Store whose calls a test watches: each DeleteMessages,
// the read of the messages table a revocation draws, and each Count. The next
// failDeletes deletes fail before the store is asked, as a store down for a
// moment fails, and while forgetful its Held knows no address, as a process
// that has loaded none.
type watchedStore struct {
	Store            // beneath: what is not watched goes straight to it
	deleted, counted atomic.Int32
	failDeletes      atomic.Int32
	forgetful        atomic.Bool
}

// watching is an option of newEnv that puts w between the server and its
// store. The env's own store stays the one beneath, so what a test reads
// through it is not counted.
func watching(w *watchedStore) func(*Config) {
	return func(c *Config) { w.Store, c.Store = c.Store, w }
}

func (w *watchedStore) Held(a protocol.Address) (Standing, bool) {
	if w.forgetful.Load() {
		return Standing{}, false
	}
	return w.Store.Held(a)
}

func (w *watchedStore) Count(ctx context.Context, a protocol.Address) (int, error) {
	w.counted.Add(1)
	return w.Store.Count(ctx, a)
}

func (w *watchedStore) DeleteMessages(ctx context.Context, a protocol.Address) error {
	w.deleted.Add(1)
	for n := w.failDeletes.Load(); n > 0; n = w.failDeletes.Load() {
		if w.failDeletes.CompareAndSwap(n, n-1) {
			return errors.New("the delete failed")
		}
	}
	return w.Store.DeleteMessages(ctx, a)
}

// A mailbox's own revocation is public: whoever holds it may send it back, as it
// is or as the same signature in other bytes that verify. A revoked mailbox takes
// nothing more, so each is answered 410 from its record with no check, and
// none draws another read of the mailbox's messages: the mailbox holds none.
func TestASecondRevocationReadsNoMessages(t *testing.T) {
	t.Parallel()
	w := &watchedStore{}
	e := newEnv(t, relaxed(), watching(w))
	owner := e.mailbox()
	signed := record(t, owner)
	// The same signature with a line feed after its armour, which anyone can
	// add.
	rewrapped := *signed
	rewrapped.Revocation = append(bytes.Clone(signed.Revocation), '\n')
	for _, put := range []struct {
		what   string
		rec    *protocol.Revocations
		status int
		code   protocol.Code
	}{
		{"the revocation, which ends the mailbox and deletes its messages", signed, 201, ""},
		{"the same revocation again", signed, 410, protocol.CodeRevoked},
		{"the same signature in other bytes", &rewrapped, 410, protocol.CodeRevoked},
	} {
		e.want(e.do("PUT", revocationPath(owner.Address()), put.rec, ""), put.status, put.code)
		if n := w.deleted.Load(); n != 1 {
			t.Fatalf("after %s, the mailbox's messages were read %d times in all, want once", put.what, n)
		}
	}
}

// The record is written before the messages are deleted, so a delete that fails
// leaves a revoked mailbox holding messages. The caller is told it failed, and the
// same revocation again finishes it, answered 410 as anything for a revoked
// mailbox is: memory shows the mailbox holding messages, and that is what a second delete
// is for.
func TestARevocationRetriedAfterAFailedDeleteDeletes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := &watchedStore{}
	e := newEnv(t, relaxed(), watching(w))
	a, b := e.mailbox(), e.mailbox()
	send(t, b, a, "waiting in A's mailbox when it is revoked")
	rec := record(t, a)
	path := revocationPath(a.Address())

	w.failDeletes.Store(1)
	if r := e.do("PUT", path, rec, ""); r.status < 500 {
		t.Fatalf("a revocation whose delete failed was answered %d: %s", r.status, r.body)
	}
	if stored, err := e.store.Mailbox(ctx, a.Address()); err != nil || stored.State != Revoked {
		t.Fatalf("after a revocation whose delete failed the mailbox is %+v, %v", stored, err)
	}
	if n, err := e.store.Count(ctx, a.Address()); err != nil || n != 1 {
		t.Fatalf("after a revocation whose delete failed the mailbox holds %d messages (%v), want the 1 it had", n, err)
	}
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n, err := e.store.Count(ctx, a.Address()); err != nil || n != 0 {
		t.Errorf("after the retry the revoked mailbox holds %d messages (%v), want none", n, err)
	}
	// With the mailbox empty, one more reads nothing.
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n := w.deleted.Load(); n != 2 {
		t.Errorf("a revocation, its retry and one more read the messages table %d times, want 2", n)
	}
}

// A revocation of the address deletes every message in its mailbox from the
// store, as acks do (PROTOCOL.md §13): read from the backend, strongly
// consistent, not from memory's count, which the revocation's own retires
// set; and on DynamoDB, every body from the bucket.
func TestARevocationDeletesEveryMessageFromTheStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a := e.mailbox()
	var ids [][32]byte
	for i := range 3 {
		from := e.mailbox()
		var id [32]byte
		copy(id[:], mustHex(t, send(t, from, a, "waiting in A's mailbox when it is revoked, "+string(rune('a'+i))).ID))
		ids = append(ids, id)
	}
	s := e.store.(*Memory)
	if live, err := s.backend.ReadLive(ctx, a.Address()); err != nil || len(live) != len(ids) {
		t.Fatalf("before the revocation the store holds %d messages for A (%v), want %d", len(live), err, len(ids))
	}
	e.want(e.do("PUT", revocationPath(a.Address()), record(t, a), ""), 201, "")
	live, err := s.backend.ReadLive(ctx, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Errorf("after the revocation the store holds %d of A's %d messages, want none", len(live), len(ids))
	}
	for _, id := range ids {
		if _, _, err := s.backend.Message(ctx, a.Address(), id, 0); !errors.Is(err, ErrNotFound) {
			t.Errorf("after the revocation a message of A's reads %v, want ErrNotFound", err)
		}
		if onAWS() && s.bodyExists(t, a.Address(), id) {
			t.Errorf("after the revocation a body of A's is in the bucket")
		}
	}
}

// A revocation sent again carries no pass, so where memory does not hold the
// address it loads nothing and changes nothing: what a failed delete left,
// the messages and the mailbox's record, waits for its expiry there, served to
// nobody. A process whose memory holds the address deletes both
// (dromas-dev/dromas-server#42).
func TestAResentRevocationLoadsNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := &watchedStore{}
	e := newEnv(t, relaxed(), watching(w))
	a, b := e.mailbox(), e.mailbox()
	send(t, b, a, "waiting in A's mailbox when it is revoked")
	rec := record(t, a)
	path := revocationPath(a.Address())
	left := func() (int, bool) {
		t.Helper()
		n, err := e.store.Count(ctx, a.Address())
		if err != nil {
			t.Fatal(err)
		}
		stored, err := e.store.Mailbox(ctx, a.Address())
		if err != nil {
			t.Fatal(err)
		}
		return n, stored.hasRecord()
	}

	w.failDeletes.Store(1)
	if r := e.do("PUT", path, rec, ""); r.status < 500 {
		t.Fatalf("a revocation whose delete failed was answered %d: %s", r.status, r.body)
	}
	w.forgetful.Store(true)
	w.counted.Store(0)
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	w.forgetful.Store(false)
	if counts, n := w.counted.Load(), w.deleted.Load(); counts != 0 || n != 1 {
		t.Errorf("a revocation sent again where memory holds nothing counted the messages %d times and deleted them %d times, want neither", counts, n-1)
	}
	if n, record := left(); n != 1 || !record {
		t.Fatalf("where memory holds nothing, a revocation sent again left %d messages and a record %v, want the 1 and the record", n, record)
	}
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n, record := left(); n != 0 || record {
		t.Errorf("where memory holds the address, a revocation sent again left %d messages and a record %v, want neither", n, record)
	}
}

// A revocation of the address may come with the revocation of its
// certificates the mailbox already holds: the record a server shows for an
// address carries both. That is nothing new, and the revocation of the
// address is taken all the same. A part that is not a revocation of
// certificates is refused, with the revocation beside it, and nothing changes.
// Once the mailbox is revoked, anything sent for it is answered from its record.
func TestARevocationComesWithTheCertificatesHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	path := r.path("/revocations")
	both := r.certs(7)
	e.want(e.do("PUT", path, both, ""), 200, "")
	var err error
	if both.Revocation, err = protocol.SignRevocation(r.signer, r.id.Address()); err != nil {
		t.Fatal(err)
	}
	junk := both
	junk.RevokedCertificates, junk.RevokedCertificatesSignature = []byte("not a revocation"), []byte("not a signature")
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	if stored, err := e.store.Mailbox(ctx, r.id.Address()); err != nil || stored.State == Revoked {
		t.Fatalf("a revocation that came with something that is not one was taken: %+v, %v", stored, err)
	}
	e.want(e.do("PUT", path, both, ""), 201, "")
	if stored, err := e.store.Mailbox(ctx, r.id.Address()); err != nil || stored.State != Revoked || !bytes.Equal(stored.Revocation, both.Revocation) {
		t.Fatalf("a revocation that came with the certificates' already held was not taken: %+v, %v", stored, err)
	}
	e.want(e.do("PUT", path, junk, ""), 410, protocol.CodeRevoked)
}
