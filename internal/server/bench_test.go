package server

// What an empty poll costs: through the handler, and the store's count
// alone. Both run on the test store (in memory, or PostgreSQL with
// DROMAS_TEST_POSTGRES), on a mailbox loaded once, after which a poll makes
// no call of the backend: each benchmark checks that it made none. Run under
// nice, each alone:
//
//	go test -tags dromas_nofsync -run '^$' -bench BenchmarkAnEmptyPoll -benchtime 2s -count 5 ./internal/server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// polledMailbox is a mailbox registered through the handler of a server on the
// test store, and polled once, which loads it: the handler, the store, the
// mailbox's address, how many calls of the backend the store has made, and a
// poll of the mailbox with a pass the server has taken, which answers its
// status.
func polledMailbox(tb testing.TB) (http.Handler, Store, protocol.Address, func() int64, func() int) {
	tb.Helper()
	s := NewMemStore(time.Now)
	if onPostgres() {
		s = startPostgres(tb, time.Now)
	}
	f := injectFaults(s)
	var reads atomic.Int64
	f.read = func(string) { reads.Add(1) }
	calls := func() int64 { return reads.Load() + f.wrote.Load() }
	h := New(Config{Store: s, Limits: relaxed(), Now: time.Now, Ready: s.Ready}).Handler()
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		tb.Fatal(err)
	}
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		tb.Fatal(err)
	}
	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(wpriv)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := protocol.NewCertificate(id, signer, work.PublicKey(), 1, now, DefaultLimits().MaxCertificateLifetime)
	if err != nil {
		tb.Fatal(err)
	}
	under, err := cert.Signer(work)
	if err != nil {
		tb.Fatal(err)
	}
	key, err := age.GenerateHybridIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	a := id.Address()
	p := &protocol.Prekey{Address: a, Rank: rankOf(under), Serial: 1, Key: key.Recipient().String(), NotAfter: now.Add(protocol.MaxPrekeyLifetime)}
	sig, err := protocol.Sign(under, p.Statement(), protocol.PrekeyNamespace(a))
	if err != nil {
		tb.Fatal(err)
	}
	pass, _, err := protocol.NewPass(under, a, "example.com", now)
	if err != nil {
		tb.Fatal(err)
	}
	body, err := json.Marshal(protocol.RegisterRequest{Identity: id.Document(), Prekey: p.Statement(), PrekeySignature: sig})
	if err != nil {
		tb.Fatal(err)
	}
	reg := httptest.NewRequest(http.MethodPut, "/v1/"+a.String(), strings.NewReader(string(body)))
	reg.Header.Set("Authorization", pass)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reg)
	if rec.Code != http.StatusCreated {
		tb.Fatalf("the registration: %d %s", rec.Code, rec.Body)
	}
	path := "/v1/" + a.String() + "/messages"
	poll := func() int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", pass)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := poll(); code != http.StatusOK {
		tb.Fatalf("the first poll: %d", code)
	}
	return h, s, a, calls, poll
}

// An empty poll through the handler, on the test store, of a mailbox loaded
// by a first poll, with a pass the server has taken: it makes no call of the
// backend.
func BenchmarkAnEmptyPoll(b *testing.B) {
	_, _, _, calls, poll := polledMailbox(b)
	before := calls()
	b.ResetTimer()
	for b.Loop() {
		if code := poll(); code != http.StatusOK {
			b.Fatalf("a poll: %d", code)
		}
	}
	b.StopTimer()
	if n := calls() - before; n != 0 {
		b.Fatalf("%d calls of the backend for polls of a loaded mailbox", n)
	}
}

// The store's count of a loaded mailbox, alone: what every poll asks of memory.
func BenchmarkCountOfALoadedMailbox(b *testing.B) {
	_, s, a, calls, _ := polledMailbox(b)
	ctx := context.Background()
	before := calls()
	b.ResetTimer()
	for b.Loop() {
		if n, err := s.Count(ctx, a); err != nil || n != 0 {
			b.Fatalf("the count: %d, %v", n, err)
		}
	}
	b.StopTimer()
	if n := calls() - before; n != 0 {
		b.Fatalf("%d calls of the backend for counts of a loaded mailbox", n)
	}
}
