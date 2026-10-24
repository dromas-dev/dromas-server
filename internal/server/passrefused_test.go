package server

// How a pass is refused (PROTOCOL.md §6.1b; IronGall-dev/irongall-server#93).
//
// Every certificate_not_current to a pass names, in certificate_serial, the
// certificate the call takes a pass under, at each caller of checkPass and
// checkPassBounded: register for a new box, registered for a box held in
// memory or read, prekey's identical retry and its upload, owner and sender.
// Each test below reaches one caller, and both of passCheck's refusals where
// a caller can reach the second (a record that does not verify).
//
// A box whose current certificate its identity revoked is answered
// certificate_revoked from its record before any pass is checked, at every
// call that takes a pass under that certificate, and the way back is an
// upload under a later certificate, whose pass is read under that one.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// unknownStore is a store whose memory holds no record (Known), as a
// process's that has not loaded the box: a registration of a box that exists
// then reads the record, under the registrations it would spend, which it
// gives back, and is answered from it by registered, as one held in memory
// is.
type unknownStore struct{ Store }

func (unknownStore) Known(protocol.Address) (*Box, bool) { return nil, false }

// at3 is a raw box registered at prekey 1 under certificate 1, then renewed
// to prekey 3 under certificate 3: its current certificate is 3, and work[1]
// is a certificate of its identity that was its current one before.
func at3(e *env) *raw {
	e.t.Helper()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekey(3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "")
	if _, c := e.numbers(r.id.Address()); c != 3 {
		e.t.Fatalf("the box stands at certificate %d, want 3", c)
	}
	return r
}

// otherPasses are passes of r under certificates of its identity other than
// serial n: one below it that r stood at (1), one never on record below it
// (2), and one never on record above it (n+1).
func otherPasses(r *raw, n uint64) map[string]string {
	return map[string]string{
		"under certificate 1, the box's before":      r.e.passFor(r.work[1], r.id.Address(), r.e.name()),
		"under certificate 2, never on record":       r.e.passFor(r.certify(2), r.id.Address(), r.e.name()),
		"under a certificate above, never on record": r.e.passFor(r.certify(n+1), r.id.Address(), r.e.name()),
	}
}

// forgeRecord writes into r's record the hash of a certificate for r's
// address, of the record's serial, in every rule, that another key signed,
// and returns a pass under it: the first two steps of passCheck take it, and
// the identity's check refuses it (the second certificate_not_current).
func forgeRecord(e *env, r *raw) string {
	e.t.Helper()
	ctx := context.Background()
	a := r.id.Address()
	b, err := e.store.Box(ctx, a)
	if err != nil || b == nil {
		e.t.Fatalf("the box's record: %v", err)
	}
	_, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	work, err := ssh.NewSignerFromKey(wpriv)
	if err != nil {
		e.t.Fatal(err)
	}
	unix := uint64(e.clock.Now().Unix()) //nolint:gosec // a test clock
	c := &ssh.Certificate{Key: work.PublicKey(), Serial: b.CertSerial, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
		ValidPrincipals: []string{a.String()}, ValidAfter: unix - 60, ValidBefore: unix + 65*86400}
	if err := c.SignCert(rand.Reader, e.raw().signer); err != nil {
		e.t.Fatal(err)
	}
	under, err := ssh.NewCertSigner(c, work)
	if err != nil {
		e.t.Fatal(err)
	}
	b.Cert = sha256.Sum256(c.Marshal())
	if err := e.store.UpdateBox(ctx, b); err != nil {
		e.t.Fatal(err)
	}
	return e.passFor(under, a, e.name())
}

// notCurrentNaming is wantNotCurrent, and the detail names the same number
// as the member: fail sets the member from the value it formats.
func (e *env) notCurrentNaming(r reply, n uint64) {
	e.t.Helper()
	e.wantNotCurrent(r, n)
	if d := r.problem().Detail; !strings.Contains(d, " "+strconv.FormatUint(n, 10)+",") {
		e.t.Fatalf("the detail names another number than certificate_serial %d: %q", n, d)
	}
}

// register: a new box's registration takes a pass under its statement's
// certificate, and names that one.
func TestARegistrationOfANewBoxNamesItsStatementsCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw()
	r.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	r.certify(1)
	for name, pass := range map[string]string{
		"under certificate 1, below": r.pass(1),
		"under certificate 6, above": e.passFor(r.certify(6), r.id.Address(), e.name()),
	} {
		t.Logf("register %s", name)
		e.notCurrentNaming(e.do("PUT", r.path(""), r.registration(5), pass), 5)
	}
	e.want(e.do("PUT", r.path(""), r.registration(5), r.pass(5)), 201, "")

	// An address whose identity revoked certificates before it registered
	// anything (a record, no box): the same line, with what is kept.
	m := e.raw()
	if got := e.do("PUT", m.path("/revocations"), m.certs(2), ""); got.status >= 300 {
		t.Fatalf("the revocation of certificates of an address with no box: %d %s", got.status, got.body)
	}
	m.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.notCurrentNaming(e.do("PUT", m.path(""), m.registration(5), e.passFor(m.certify(4), m.id.Address(), e.name())), 5)
	e.notCurrentNaming(e.do("PUT", m.path(""), m.registration(5), e.passFor(m.certify(1), m.id.Address(), e.name())), 5)
	e.want(e.do("PUT", m.path(""), m.registration(5), m.pass(5)), 201, "")
}

// registered, read: a registration of a box that exists, which this
// process's memory does not hold, names the box's current certificate, for a
// pass under another certificate and for a record that does not verify.
func TestARegistrationOfABoxNotInMemoryNamesItsCurrentCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed(), func(c *Config) { c.Store = unknownStore{c.Store} })
	r := at3(e)
	for name, pass := range otherPasses(r, 3) {
		t.Logf("registration %s", name)
		e.notCurrentNaming(e.do("PUT", r.path(""), r.registration(3), pass), 3)
	}
	e.want(e.do("PUT", r.path(""), r.registration(3), r.pass(3)), 200, "")
	e.notCurrentNaming(e.do("PUT", r.path(""), r.registration(3), forgeRecord(e, r)), 3)
}

// registered: the same, for a box this process holds.
func TestARegistrationOfABoxInMemoryNamesItsCurrentCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := at3(e)
	for name, pass := range otherPasses(r, 3) {
		t.Logf("registration %s", name)
		e.notCurrentNaming(e.do("PUT", r.path(""), r.registration(3), pass), 3)
	}
	e.want(e.do("PUT", r.path(""), r.registration(3), r.pass(3)), 200, "")
	e.notCurrentNaming(e.do("PUT", r.path(""), r.registration(3), forgeRecord(e, r)), 3)
}

// prekey, an identical retry: the box's current certificate.
func TestAnIdenticalUploadNamesTheCurrentCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := at3(e)
	for name, pass := range otherPasses(r, 3) {
		t.Logf("identical upload %s", name)
		e.notCurrentNaming(e.do("PUT", r.path("/prekey"), r.upload(3), pass), 3)
	}
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "")
	e.notCurrentNaming(e.do("PUT", r.path("/prekey"), r.upload(3), forgeRecord(e, r)), 3)
}

// prekey, an upload: the new statement's certificate, not the box's current
// one, whatever the pass is under.
func TestAnUploadNamesItsStatementsCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := at3(e)
	r.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	for name, pass := range map[string]string{
		"under certificate 3, the box's current": r.pass(3),
		"under certificate 1, the box's before":  r.pass(1),
		"under certificate 4, never on record":   e.passFor(r.certify(4), r.id.Address(), e.name()),
	} {
		t.Logf("upload %s", name)
		e.notCurrentNaming(e.do("PUT", r.path("/prekey"), r.upload(5), pass), 5)
	}
	e.want(e.do("PUT", r.path("/prekey"), r.upload(5), r.pass(5)), 200, "")
}

// owner: every call a box makes about itself names the box's current
// certificate, for a pass under another certificate and for a record that
// does not verify.
func TestEveryOwnerCallNamesTheCurrentCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := at3(e)
	id := strings.Repeat("a", 64)
	calls := []struct {
		method, path string
		body         any
	}{
		{"GET", "/messages", nil},
		{"GET", "/messages/" + id, nil},
		{"DELETE", "/messages/" + id, nil},
		{"GET", "/acl", nil},
		{"PUT", "/acl", []byte(`{"allow":["*"],"deny":[]}`)},
		{"PUT", "/account", []byte(`{"key":"iga1_AAAA"}`)},
		{"DELETE", "/account", nil},
	}
	for _, c := range calls {
		for name, pass := range otherPasses(r, 3) {
			t.Logf("%s %s %s", c.method, c.path, name)
			e.notCurrentNaming(e.do(c.method, r.path(c.path), c.body, pass), 3)
		}
		if got := e.do(c.method, r.path(c.path), c.body, r.pass(3)); got.status == http.StatusUnauthorized {
			t.Fatalf("control: %s %s under the box's current certificate: %d %s", c.method, c.path, got.status, got.body)
		}
	}
	forged := forgeRecord(e, r)
	for _, c := range calls {
		e.notCurrentNaming(e.do(c.method, r.path(c.path), c.body, forged), 3)
	}
}

// sender: a send names the sender's current certificate.
func TestASendNamesTheSendersCurrentCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r, o := at3(e), e.raw().register(protocol.MaxPrekeyLifetime)
	r.certify(2)
	r.certify(4)
	for _, under := range []uint64{1, 2, 4} {
		t.Logf("send under certificate %d", under)
		e.notCurrentNaming(e.sendTo(o, 1, 1, r, under), 3)
	}
	e.want(e.sendTo(o, 1, 1, r, 3), 201, "")
	forged := forgeRecord(e, r)
	got := e.do("POST", o.path("/messages"), sealedTo(1, 1, []byte("x")), forged)
	e.notCurrentNaming(got, 3)
}

// Once the box's identity revokes its current certificate, every call that
// takes a pass under that certificate is certificate_revoked before any pass
// is checked: with no pass, one under the revoked current certificate, one
// under an older one (revoked too), one under a later one never on record,
// and one that is no pass. A send can only know whose pass it is by reading
// it, so a send with no pass, or one that is no pass, is unauthorized
// (PROTOCOL.md §6.1b). The way back is an upload under a later
// certificate, whose pass is read under that one (PROTOCOL.md §6.1b, §6.4).
func TestARevokedCurrentCertificateIsAnsweredBeforeThePass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r, o := at3(e), e.raw().register(protocol.MaxPrekeyLifetime)
	later := e.passFor(r.certify(5), r.id.Address(), e.name())
	seen := r.pass(3)
	e.want(e.do("GET", r.path("/messages"), nil, seen), 200, "")
	e.want(e.do("PUT", r.path("/revocations"), r.certs(3), ""), 200, "")
	passes := map[string]string{
		"no pass":                              "",
		"not a pass":                           "Bearer " + strings.Repeat("a", 50),
		"under certificate 3, taken before":    seen,
		"under certificate 3, new":             r.pass(3),
		"under certificate 1, revoked too":     r.pass(1),
		"under certificate 5, never on record": later,
	}
	id := strings.Repeat("a", 64)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/messages", nil},
		{"GET", "/messages/" + id, nil},
		{"DELETE", "/messages/" + id, nil},
		{"GET", "/acl", nil},
		{"PUT", "/acl", []byte(`{"allow":["*"],"deny":[]}`)},
		{"PUT", "/account", []byte(`{"key":"iga1_AAAA"}`)},
		{"DELETE", "/account", nil},
		{"PUT", "", r.registration(3)},
		{"PUT", "/prekey", r.upload(3)},
	} {
		for name, pass := range passes {
			if got := e.do(c.method, r.path(c.path), c.body, pass); got.status != 401 || got.code() != protocol.CodeCertificateRevoked {
				t.Errorf("%s %s %s: %d %s", c.method, c.path, name, got.status, got.body)
			}
		}
	}
	for name, pass := range passes {
		want := protocol.CodeCertificateRevoked
		if name == "no pass" || name == "not a pass" {
			want = protocol.CodeUnauthorized
		}
		if got := e.do("POST", o.path("/messages"), sealedTo(1, 1, []byte("x")), pass); got.status != 401 || got.code() != want {
			t.Errorf("a send %s: %d %s, want %s", name, got.status, got.body, want)
		}
	}
	// A statement under the revoked certificate at a higher serial is refused
	// before its pass, whatever that is under.
	r.prekeyUnder(r.work[3], 4, e.clock.Now().Add(time.Hour), nil)
	for name, pass := range passes {
		if got := e.do("PUT", r.path("/prekey"), r.upload(4), pass); got.status != 401 || got.code() != protocol.CodeCertificateRevoked {
			t.Errorf("an upload under the revoked certificate, %s: %d %s", name, got.status, got.body)
		}
	}
	// The way back: a statement under a new certificate, with a pass under
	// it. Its pass is read: one under the revoked current certificate is
	// certificate_not_current, naming the statement's.
	r.prekey(6, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.notCurrentNaming(e.do("PUT", r.path("/prekey"), r.upload(6), seen), 6)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(6), r.pass(6)), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(6)), 200, "")
}

// An address with no box whose identity revoked certificates: a registration
// of a statement under one of them is certificate_revoked before its pass is
// read, whatever it carries (PROTOCOL.md §3 step 6, §6.1b). Control: one
// above them has its pass read.
func TestARegistrationUnderARevokedCertificateIsAnsweredBeforeThePass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	m := e.raw()
	e.want(e.do("PUT", m.path("/revocations"), m.certs(4), ""), 200, "")
	m.prekey(3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	for name, pass := range map[string]string{
		"no pass":                          "",
		"not a pass":                       "Bearer " + strings.Repeat("a", 50),
		"under its statement's":            m.pass(3),
		"under certificate 6, not revoked": e.passFor(m.certify(6), m.id.Address(), e.name()),
	} {
		if got := e.do("PUT", m.path(""), m.registration(3), pass); got.status != 401 || got.code() != protocol.CodeCertificateRevoked {
			t.Errorf("a registration under a revoked certificate, its pass %s: %d %s", name, got.status, got.body)
		}
	}
	m.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", m.path(""), m.registration(5), ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", m.path(""), m.registration(5), m.pass(5)), 201, "")
}
