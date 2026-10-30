package server

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/dromas-dev/dromas-client/protocol"
)

// beforePut runs a hook once, before the next PutMessage: a send held
// between its check of the recipient and its write.
type beforePut struct {
	Store
	mu  sync.Mutex
	put func()
}

func (s *beforePut) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put = f
}

func (s *beforePut) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	f := s.put
	s.put = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Store.PutMessage(ctx, mailbox, h, body)
}

// Every 410 revoked this server answers carries the record it holds of the
// address, its identity's revocation of it beside its revocation of
// certificates, as the read of a mailbox does and as GET …/revocations serves it
// (PROTOCOL.md §11.3; dromas-dev/dromas-client#353), so a client checks
// it with no second call: a send held between its check of the recipient
// and its write while the address is revoked, the read, a registration, a
// prekey upload, the revocation sent again, a send, and each call about the
// mailbox with its own pass, for a mailbox revoked and for an address revoked with
// no mailbox here.
func TestEvery410CarriesTheRecord(t *testing.T) {
	t.Parallel()
	hook := &beforePut{}
	e := newEnv(t, relaxed(), func(c *Config) { hook.Store, c.Store = c.Store, hook })
	until := e.clock.Now().Add(protocol.MaxPrekeyLifetime)
	revocation := func(b *raw) protocol.Revocations {
		sig, err := protocol.SignRevocation(b.signer, b.id.Address())
		if err != nil {
			t.Fatal(err)
		}
		return protocol.Revocations{Identity: b.id.Document(), Revocation: sig}
	}
	r, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	// r renews under certificate 2 and revokes certificate 1, so its record
	// carries a revocation of certificates beside the revocation of the
	// address.
	r.prekey(2, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), http.StatusOK, "")
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
	writing, release := make(chan struct{}), make(chan struct{})
	hook.set(func() { close(writing); <-release })
	sent := make(chan reply, 1)
	go func() { sent <- e.sendTo(r, 2, 2, from, 1) }()
	<-writing
	e.want(e.do("PUT", r.path("/revocations"), revocation(r), ""), http.StatusCreated, "")
	close(release)
	across := <-sent
	q := e.raw() // never registered
	e.want(e.do("PUT", q.path("/revocations"), revocation(q), ""), http.StatusCreated, "")
	q.prekey(1, until, nil)

	id := strings.Repeat("0", 64)
	for _, c := range []struct {
		name    string
		mailbox *raw
		under   uint64 // the certificate its pass is under
		first   []reply
	}{
		{"a mailbox revoked", r, 2, []reply{across}},
		{"an address revoked with no mailbox", q, 1, nil},
	} {
		served := e.do("GET", c.mailbox.path("/revocations"), nil, "")
		e.want(served, http.StatusOK, "")
		var want protocol.Revocations
		if err := protocol.Unmarshal(served.body, &want); err != nil || len(want.Revocation) == 0 || c.mailbox == r && len(want.RevokedCertificates) == 0 {
			t.Fatalf("%s: the record held: %s, %v", c.name, served.body, err)
		}
		pass := c.mailbox.pass(c.under)
		next := c.under + 1
		c.mailbox.prekey(next, until, nil)
		got := map[string]reply{
			"the read":             e.do("GET", c.mailbox.path(""), nil, ""),
			"a registration":       e.do("PUT", c.mailbox.path(""), c.mailbox.registration(next), c.mailbox.pass(next)),
			"a prekey upload":      e.do("PUT", c.mailbox.path("/prekey"), c.mailbox.upload(next), c.mailbox.pass(next)),
			"the revocation again": e.do("PUT", c.mailbox.path("/revocations"), want, ""),
			"a send":               e.sendTo(c.mailbox, c.under, c.under, from, 1),
			"a poll":               e.do("GET", c.mailbox.path("/messages"), nil, pass),
			"a fetch":              e.do("GET", c.mailbox.path("/messages/"+id), nil, pass),
			"an ack":               e.do("DELETE", c.mailbox.path("/messages/"+id), nil, pass),
			"a read of its ACL":    e.do("GET", c.mailbox.path("/acl"), nil, pass),
			"an ACL":               e.do("PUT", c.mailbox.path("/acl"), []byte(`{"allow":["*"]}`), pass),
			"an adopt":             e.do("PUT", c.mailbox.path("/account"), protocol.AdoptRequest{Key: "dra1_AAAA"}, pass),
			"a leave":              e.do("DELETE", c.mailbox.path("/account"), nil, pass),
		}
		for _, f := range c.first {
			got["a send held across the revocation"] = f
		}
		for name, g := range got {
			if g.status != http.StatusGone {
				t.Errorf("%s, %s: %d %s, want 410", c.name, name, g.status, g.body)
				continue
			}
			rec := held(t, g)
			if rec == nil || !bytes.Equal(rec.Identity, want.Identity) || !bytes.Equal(rec.Revocation, want.Revocation) ||
				!bytes.Equal(rec.RevokedCertificates, want.RevokedCertificates) || !bytes.Equal(rec.RevokedCertificatesSignature, want.RevokedCertificatesSignature) {
				t.Errorf("%s, %s: the 410 carries %+v, want the record held, %s", c.name, name, rec, served.body)
			}
		}
	}
}
