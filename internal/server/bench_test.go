package server

// What an empty poll costs on the DynamoDB store, the primary one: through
// the handler, and the store's count alone. Both run over the fake of AWS
// (awsfake_test.go), on a mailbox loaded once, after which a poll reads no AWS:
// each benchmark checks that it read none. Run under nice, each alone:
//
//	go test -run '^$' -bench BenchmarkAnEmptyPoll -benchtime 2s -count 5 ./internal/server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// polledMailbox is a mailbox registered through the handler of a server on the
// DynamoDB store over the fake of AWS, and polled once, which loads it: the
// handler, the store, the mailbox's address, the fake, and a poll of the mailbox with
// a pass the server has taken, which answers its status.
func polledMailbox(tb testing.TB) (http.Handler, Store, protocol.Address, *fakeAWS, func() int) {
	tb.Helper()
	tbl := &mailboxesTable{items: map[string]map[string]any{}}
	f := newFakeAWS()
	f.dynamo = tbl.answer
	s := fakeStore(tb, f)
	h := New(Config{Store: s, Limits: relaxed(), Now: time.Now}).Handler()
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
	cert, err := protocol.NewCertificate(id, signer, work.PublicKey(), 1, now)
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
	p := &protocol.Prekey{Address: a, Serial: 1, Key: key.Recipient().String(), NotAfter: now.Add(protocol.MaxPrekeyLifetime)}
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
	return h, s, a, f, poll
}

// callsTo is how many calls the fake of AWS has answered.
func (f *fakeAWS) callsTo() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

// An empty poll through the handler, on the DynamoDB store, of a mailbox loaded
// by a first poll, with a pass the server has taken: it reads no AWS.
func BenchmarkAnEmptyPollOnTheDynamoDBStore(b *testing.B) {
	_, _, _, f, poll := polledMailbox(b)
	before := f.callsTo()
	b.ResetTimer()
	for b.Loop() {
		if code := poll(); code != http.StatusOK {
			b.Fatalf("a poll: %d", code)
		}
	}
	b.StopTimer()
	if n := f.callsTo() - before; n != 0 {
		b.Fatalf("%d calls to AWS for polls of a loaded mailbox", n)
	}
}

// The store's count of a loaded mailbox, alone: what every poll asks of memory.
func BenchmarkCountOfALoadedMailboxOnTheDynamoDBStore(b *testing.B) {
	_, s, a, f, _ := polledMailbox(b)
	ctx := context.Background()
	before := f.callsTo()
	b.ResetTimer()
	for b.Loop() {
		if n, err := s.Count(ctx, a); err != nil || n != 0 {
			b.Fatalf("the count: %d, %v", n, err)
		}
	}
	b.StopTimer()
	if n := f.callsTo() - before; n != 0 {
		b.Fatalf("%d calls to AWS for counts of a loaded mailbox", n)
	}
}
