package server

// The two forms of signer at the server (PROTOCOL.md §5, §8, §11.7, §11.9):
// the identity, which ranks 0 and is ended only by revoking the address, and
// a certificate the identity made, which ranks at its serial and is taken
// while it is above the revocation of certificates held. A mailbox's
// statements are ordered by (c, p), so they are one way; its passes are not
// ordered, and the identity's is always taken. A certificate is held to the
// sanity refusals, exact at the server's clock, when it is first taken.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A statement under a certificate is taken with no revocation of
// certificates held, at a registration and at a renewal of a mailbox whose
// identity signed its statements. One at or below the revocation held is
// certificate_revoked before its pass, whatever that is; one above it is
// taken.
func TestACertificateIsTakenAboveTheRevocationHeld(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	until := e.clock.Now().Add(protocol.MaxPrekeyLifetime)

	r := e.raw().certified()
	r.prekey(2, until, nil)
	e.want(e.do("PUT", r.path(""), r.registration(2), r.pass(2)), http.StatusCreated, "")
	if b, _ := e.store.Mailbox(context.Background(), r.id.Address()); b == nil || b.Rank != 2 || len(b.RevokedCerts) != 0 {
		t.Fatalf("a registration under a certificate with no revocation held: %+v", b)
	}

	m := e.raw().register(protocol.MaxPrekeyLifetime)
	m.prekeyUnder(m.certify(5), 2, until, nil)
	e.want(e.do("PUT", m.path("/prekey"), m.upload(2), m.pass(2)), http.StatusOK, "")

	n := e.raw()
	e.want(e.do("PUT", n.path("/revocations"), n.certs(3), ""), http.StatusOK, "")
	identity := e.passFor(n.signer, n.id.Address(), e.name())
	for _, serial := range []uint64{2, 3} {
		n.prekeyUnder(n.certify(serial), 1, until, nil)
		for name, pass := range map[string]string{"no pass": "", "its own pass": n.pass(1), "the identity's pass": identity} {
			if got := e.do("PUT", n.path(""), n.registration(1), pass); got.status != http.StatusUnauthorized || got.code() != protocol.CodeCertificateRevoked {
				t.Errorf("a registration under certificate %d, at or below the revocation of 3, %s: %d %s", serial, name, got.status, got.body)
			}
		}
	}
	n.prekeyUnder(n.certify(4), 1, until, nil)
	e.want(e.do("PUT", n.path(""), n.registration(1), n.pass(1)), http.StatusCreated, "")
}

// Statements are one way: once a statement under a certificate is taken, one
// the identity signs stands below it, rank 0, and is refused
// certificate_not_current, naming the certificate it must be above, whatever
// its prekey serial and whichever pass it carries; as is a statement under a
// lower certificate.
func TestAnIdentityStatementAfterACertificateIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	until := e.clock.Now().Add(protocol.MaxPrekeyLifetime)
	r := e.raw()
	serial := r.registerCertified(protocol.MaxPrekeyLifetime)
	current := r.pass(serial)
	for _, p := range []uint64{serial + 1, protocol.MaxSerial} {
		r.prekeyUnder(r.signer, p, until, nil)
		for name, pass := range map[string]string{"the identity's pass": r.pass(p), "the current certificate's pass": current} {
			t.Logf("an identity statement at prekey %d after certificate %d, %s", p, serial, name)
			e.wantNotCurrent(e.do("PUT", r.path("/prekey"), r.upload(p), pass), serial)
		}
	}
	r.prekeyUnder(r.certify(1), serial+2, until, nil)
	e.wantNotCurrent(e.do("PUT", r.path("/prekey"), r.upload(serial+2), r.pass(serial+2)), serial)
	// Control: a statement under a higher certificate is taken.
	r.prekey(serial+3, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(serial+3), r.pass(serial+3)), http.StatusOK, "")
}

// The identity's pass is always taken (PROTOCOL.md §8): with a certificate
// current, at every call that takes the mailbox's pass and as a sender; and
// with that certificate revoked, when no pass under any certificate is
// taken, and a call with no pass, one that is not a pass and one under any
// certificate are certificate_revoked, with no signature checked and so no
// miss of the caller's address spent.
func TestTheIdentitysPassIsAlwaysTaken(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = DefaultLimits().MissesPerMinute
	e := newEnv(t, l)
	r, o := e.raw(), e.raw().register(protocol.MaxPrekeyLifetime)
	serial := r.registerCertified(protocol.MaxPrekeyLifetime)
	identity := func() string { return e.passFor(r.signer, r.id.Address(), e.name()) }
	id := strings.Repeat("a", 64)
	calls := []struct {
		method, path string
		body         any
	}{
		{"GET", "/messages", nil},
		{"GET", "/messages/" + id, nil},
		{"GET", "/acl", nil},
		{"PUT", "/acl", []byte(`{"allow":["*"],"deny":[]}`)},
		{"PUT", "/prekey", r.upload(serial)},
		{"PUT", "", r.registration(serial)},
	}
	for _, c := range calls {
		if got := e.do(c.method, r.path(c.path), c.body, identity()); got.status == http.StatusUnauthorized {
			t.Errorf("%s %s by the identity, its certificate current: %d %s", c.method, c.path, got.status, got.body)
		}
	}
	e.want(e.do("POST", o.path("/messages"), o.sealed(1, ciphertextTo(t, o)), identity()), http.StatusCreated, "")

	e.want(e.do("PUT", r.path("/revocations"), r.certs(serial), ""), http.StatusOK, "")
	misses := debts(e.server, e.clock.Now())[string(protocol.QuotaMisses)]
	for _, c := range calls[:4] {
		if got := e.do(c.method, r.path(c.path), c.body, identity()); got.status == http.StatusUnauthorized {
			t.Errorf("%s %s by the identity, its certificate revoked: %d %s", c.method, c.path, got.status, got.body)
		}
		for name, pass := range map[string]string{
			"no pass": "", "not a pass": "Bearer " + strings.Repeat("a", 50), "the revoked certificate's": r.pass(serial),
			"another certificate's, never on record": e.passFor(r.certify(serial+5), r.id.Address(), e.name()),
		} {
			if got := e.do(c.method, r.path(c.path), c.body, pass); got.status != http.StatusUnauthorized || got.code() != protocol.CodeCertificateRevoked {
				t.Errorf("%s %s, %s, its certificate revoked: %d %s", c.method, c.path, name, got.status, got.body)
			}
		}
	}
	if spent := debts(e.server, e.clock.Now())[string(protocol.QuotaMisses)] - misses; spent != 0 {
		t.Errorf("the refusals of passes at a mailbox whose certificate is revoked spent %d misses", spent)
	}
	e.want(e.do("POST", o.path("/messages"), o.sealed(1, ciphertextTo(t, o)), identity()), http.StatusCreated, "")
	e.want(e.do("POST", o.path("/messages"), o.sealed(1, ciphertextTo(t, o)), r.pass(serial)), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	// The identical retry of the revoked certificate's statement stays
	// certificate_revoked, whatever pass it carries: it brings that
	// certificate (PROTOCOL.md §11.9).
	e.want(e.do("PUT", r.path("/prekey"), r.upload(serial), identity()), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	// A renewal under a certificate above the revocation, with the
	// identity's pass, is taken.
	r.prekey(serial+1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(serial+1), identity()), http.StatusOK, "")
}

// A revocation of certificates covers certificates only (PROTOCOL.md §10.2):
// a mailbox whose identity signs its statement is never listed by one, in
// memory or read whole; its identity's pass, its statement's identical
// retry, its messages both ways and its next identity statement are taken.
func TestTheIdentityIsNeverListedRevoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r, o := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	if _, err := e.store.Count(ctx, r.id.Address()); err != nil { // a process that has loaded it
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocations"), r.certs(protocol.MaxSerial), ""), http.StatusOK, "")
	b, err := e.store.Mailbox(ctx, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	whole, _, err := b.standing()
	mem, held := e.store.Held(r.id.Address())
	if err != nil || whole.Listed || !held || mem.Listed {
		t.Fatalf("an identity-signed mailbox after a revocation of every certificate: listed %v read whole (%v), %v in memory (held %v)", whole.Listed, err, mem.Listed, held)
	}
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(1)), http.StatusOK, "")
	e.want(e.do("PUT", r.path("/prekey"), r.upload(1), r.pass(1)), http.StatusOK, "")
	e.want(e.sendTo(r, 1, o, 1), http.StatusCreated, "")
	e.want(e.sendTo(o, 1, r, 1), http.StatusCreated, "")
	r.prekeyUnder(r.signer, 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), http.StatusOK, "")
}

// certAt is a certificate of r's identity for a new working key, of serial,
// valid from after to before, as the signer of its signatures.
func certAt(t *testing.T, r *raw, serial uint64, after, before time.Time) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	work, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{Key: work.PublicKey(), Serial: serial, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
		ValidPrincipals: []string{r.id.Address().String()}, ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix())} //nolint:gosec // a test clock
	if err := c.SignCert(rand.Reader, r.signer); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(c, work)
	if err != nil {
		t.Fatal(err)
	}
	r.work[serial] = s
	return s
}

// A certificate is held to the sanity refusals when it is first taken, each
// exact at the server's clock (PROTOCOL.md §11.7 step 6): begun, not ended,
// and no longer than the server's maximum, which the refusal carries in
// max_certificate_lifetime. Nothing more: one begun this second is taken.
// A renewal under the mailbox's current certificate is not held to the
// maximum again, so a lower maximum strands no mailbox.
func TestTheSanityRefusals(t *testing.T) {
	t.Parallel()
	l := relaxed()
	most := l.MaxCertificateLifetime
	e := newEnv(t, l)
	now := e.clock.Now()
	until := now.Add(protocol.MaxPrekeyLifetime)
	for _, c := range []struct {
		name          string
		after, before time.Time
		status        int
		code          protocol.Code
	}{
		{"begun a second from now", now.Add(time.Second), now.Add(time.Hour), http.StatusBadRequest, protocol.CodePrekeyTime},
		{"begun this second", now, now.Add(time.Hour), http.StatusCreated, ""},
		{"ended this second", now.Add(-time.Hour), now, http.StatusBadRequest, protocol.CodePrekeyTime},
		{"ending a second from now", now.Add(-time.Hour), now.Add(time.Second), http.StatusCreated, ""},
		{"the maximum", now.Add(-protocol.MaxSkew), now.Add(-protocol.MaxSkew).Add(most), http.StatusCreated, ""},
		{"a second past the maximum", now.Add(-protocol.MaxSkew), now.Add(-protocol.MaxSkew).Add(most + time.Second), http.StatusBadRequest, protocol.CodeCertificateTooLong},
	} {
		r := e.raw().certified()
		r.prekeyUnder(certAt(t, r, 2, c.after, c.before), 1, until, nil)
		got := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
		if got.status != c.status || got.code() != c.code {
			t.Errorf("a certificate %s: %d %s, want %d %s", c.name, got.status, got.body, c.status, c.code)
		}
		if p := got.problem(); c.code == protocol.CodeCertificateTooLong && (p.MaxCertificateLifetime == nil || *p.MaxCertificateLifetime != uint64(most/time.Second)) {
			t.Errorf("a certificate %s: max_certificate_lifetime %v, want %d", c.name, p.MaxCertificateLifetime, most/time.Second)
		}
	}

	// A renewal under a new certificate is held to it; one under the current
	// certificate is not, at a server whose maximum is now lower than the
	// certificate it took.
	long := relaxed()
	long.MaxCertificateLifetime = 2 * most
	e1 := newEnv(t, long)
	e2 := newEnv(t, l, func(c *Config) { c.Store, c.Now = e1.store, e1.clock.Now })
	r := e1.raw().certified()
	r.prekeyUnder(r.certifyFor(2, 2*most), 1, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e1.want(e1.do("PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
	r.prekeyUnder(r.work[2], 2, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	at2 := func(serial uint64) string { return e2.passFor(r.by[serial], r.id.Address(), e2.name()) }
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(2), at2(2)), http.StatusOK, "")
	r.prekeyUnder(r.certifyFor(3, 2*most), 3, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(3), at2(3)), http.StatusBadRequest, protocol.CodeCertificateTooLong)
	r.prekey(3, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(3), at2(3)), http.StatusOK, "")
}
