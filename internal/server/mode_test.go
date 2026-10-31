package server

// An address's mode at the server (PROTOCOL.md §5, §11.7): the server takes a
// statement under a certificate only while it holds the address's revocation
// of certificates, the trip, and only above it; a certificate is held to the
// sanity refusals, exact at the server's clock, when it is first taken.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// lagging is a store whose memory has not seen address a's revocation of
// certificates, as the memory of a process the trip, made at another
// process, has not reached yet: what it answers from memory or a read of
// memory's (Known, Mailbox, Held) shows none, and only a read past memory
// (Reread) shows it. It counts those reads.
type lagging struct {
	Store
	a       protocol.Address
	rereads atomic.Int32
}

func (s *lagging) hide(b *Mailbox) *Mailbox {
	if b == nil || b.Addr != s.a {
		return b
	}
	c := cloneMailbox(b)
	c.RevokedCerts, c.RevokedCertsSig = nil, nil
	if c.State == NoMailbox {
		return nil
	}
	return c
}

func (s *lagging) Known(a protocol.Address) (*Mailbox, bool) {
	b, ok := s.Store.Known(a)
	if a == s.a && ok && b != nil {
		return s.hide(b), true
	}
	return b, ok
}

func (s *lagging) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	b, err := s.Store.Mailbox(ctx, a)
	if err != nil || a != s.a {
		return b, err
	}
	if b = s.hide(b); b == nil {
		return nil, ErrNotFound
	}
	return b, nil
}

func (s *lagging) Held(a protocol.Address) (Standing, bool) {
	st, ok := s.Store.Held(a)
	if a == s.a {
		st.Listed = false
	}
	return st, ok
}

func (s *lagging) Reread(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.a {
		s.rereads.Add(1)
	}
	return s.Store.Reread(ctx, a)
}

// laggingEnv is a server whose memory has not seen r's trip, on a raw
// mailbox r made for it.
func laggingEnv(t *testing.T, l Limits) (*env, *raw, *lagging) {
	t.Helper()
	s := &lagging{}
	e := newEnv(t, l, func(c *Config) { s.Store, c.Store = c.Store, s })
	r := e.raw()
	s.a = r.id.Address()
	return e, r, s
}

// The trip, then the first statement under a certificate: taken at once by
// the process that took the trip, and by a process whose memory has not seen
// it, which reads the store once, strongly consistent, before it refuses one
// (PROTOCOL.md §11.3, §11.7). Its registration and its renewal alike.
func TestTheFirstCertificateStatementAfterTheTrip(t *testing.T) {
	t.Parallel()
	until := func(e *env) time.Time { return e.clock.Now().Add(protocol.MaxPrekeyLifetime) }

	// At once, at the process that took the trip: no read past its memory.
	e, r, s := laggingEnv(t, relaxed())
	s.a = protocol.Address{} // nothing hidden
	r.trip()
	r.prekey(2, until(e), nil)
	e.want(e.do("PUT", r.path(""), r.registration(2), r.pass(2)), http.StatusCreated, "")

	// A registration at a process that has not seen the trip.
	e, r, s = laggingEnv(t, relaxed())
	r.trip()
	if b, err := e.store.Mailbox(context.Background(), r.id.Address()); err == nil || b != nil {
		t.Fatalf("control: the lagging memory shows the trip: %+v, %v", b, err)
	}
	r.prekey(2, until(e), nil)
	e.want(e.do("PUT", r.path(""), r.registration(2), r.pass(2)), http.StatusCreated, "")
	if n := s.rereads.Load(); n != 1 {
		t.Errorf("the registration read the store past memory %d times, want once", n)
	}

	// A renewal of a mailbox in identity mode at a process that has not seen
	// its trip: its first certificate replaces the identity, which the trip
	// covers.
	e, r, s = laggingEnv(t, relaxed())
	r.register(protocol.MaxPrekeyLifetime)
	r.trip()
	r.prekey(2, until(e), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), http.StatusOK, "")
	if n := s.rereads.Load(); n != 1 {
		t.Errorf("the renewal read the store past memory %d times, want once", n)
	}
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), http.StatusOK, "")
}

// A statement under a certificate on an address whose trip the server does
// not hold is 409 identity_mode, at a registration and at a renewal, once its
// signature verifies and after one read of the store, which a miss of the
// caller's address pays for (LIMITS.md); and before its pass, whatever that
// is. A certificate at or below the trip is certificate_revoked, never
// identity_mode, and so is the identity's statement once the trip is held.
func TestTheModeIsJudgedBeforeThePass(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 2
	e, r, s := laggingEnv(t, l) // with no trip, memory hides nothing
	until := e.clock.Now().Add(protocol.MaxPrekeyLifetime)
	r.prekeyUnder(r.certify(2), 2, until, nil)
	// A statement whose signature does not verify is refused for that, with
	// no read of the store.
	r.prekeyUnder(r.work[2], 3, until, nil)
	bad := r.registration(2)
	bad.PrekeySignature = r.sig[3]
	e.want(e.do("PUT", r.path(""), bad, r.pass(2)), http.StatusBadRequest, protocol.CodeBadKey)
	if n := s.rereads.Load(); n != 0 {
		t.Errorf("a statement that does not verify read the store %d times", n)
	}
	for name, pass := range map[string]string{"no pass": "", "its own pass": r.pass(2)} {
		got := e.do("PUT", r.path(""), r.registration(2), pass)
		if got.status != http.StatusConflict || got.code() != protocol.CodeIdentityMode {
			t.Errorf("a registration under a certificate, %s: %d %s", name, got.status, got.body)
		}
	}
	if n := s.rereads.Load(); n != 2 {
		t.Errorf("two refusals read the store %d times, want once each", n)
	}
	// Each refusal kept the miss its read reserved: the address has none left.
	e.limited(e.do("PUT", r.path(""), r.registration(2), r.pass(2)), protocol.QuotaMisses)

	// A renewal under a certificate of a mailbox in identity mode.
	e = newEnv(t, relaxed())
	m := e.raw().register(protocol.MaxPrekeyLifetime)
	m.prekeyUnder(m.certify(5), 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	for name, pass := range map[string]string{"no pass": "", "its own pass": m.pass(2), "the identity's": m.pass(1)} {
		got := e.do("PUT", m.path("/prekey"), m.upload(2), pass)
		if got.status != http.StatusConflict || got.code() != protocol.CodeIdentityMode {
			t.Errorf("a renewal under a certificate in identity mode, %s: %d %s", name, got.status, got.body)
		}
	}

	// After the trip: a certificate at or below it, and the identity, are
	// certificate_revoked; one above it is taken.
	n := e.raw()
	e.want(e.do("PUT", n.path("/revocations"), n.certs(3), ""), http.StatusOK, "")
	for _, c := range []struct {
		name   string
		signer ssh.Signer
		status int
		code   protocol.Code
	}{
		{"the identity", n.signer, http.StatusUnauthorized, protocol.CodeCertificateRevoked},
		{"certificate 2, below the trip", n.certify(2), http.StatusUnauthorized, protocol.CodeCertificateRevoked},
		{"certificate 3, the trip's", n.certify(3), http.StatusUnauthorized, protocol.CodeCertificateRevoked},
		{"certificate 4, above it", n.certify(4), http.StatusCreated, ""},
	} {
		n.prekeyUnder(c.signer, 1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
		got := e.do("PUT", n.path(""), n.registration(1), n.pass(1))
		if got.status != c.status || got.code() != c.code {
			t.Errorf("a registration after the trip, by %s: %d %s, want %d %s", c.name, got.status, got.body, c.status, c.code)
		}
	}
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
		r := e.raw().trip()
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
	r := e1.raw().trip()
	r.prekeyUnder(r.certifyFor(2, 2*most), 1, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e1.want(e1.do("PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
	r.prekeyUnder(r.work[2], 2, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), http.StatusOK, "")
	r.prekeyUnder(r.certifyFor(3, 2*most), 3, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), http.StatusBadRequest, protocol.CodeCertificateTooLong)
	r.prekey(3, e1.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), http.StatusOK, "")
}
