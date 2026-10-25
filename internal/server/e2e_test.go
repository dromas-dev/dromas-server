package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// clock is a settable clock shared by the server and the clients.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env is a dev server with the clients' view of it. Middleware, when set,
// sits between the clients and the server, to see or change what passes.
type env struct {
	t      *testing.T
	clock  *clock
	store  Store
	server *Server
	srv    *httptest.Server
	mu     sync.Mutex
	middle func(w http.ResponseWriter, r *http.Request, next http.Handler)
}

func relaxed() Limits {
	l := DefaultLimits()
	l.SendsPerDay, l.PollBurst, l.RegistrationsPerHour, l.RenewalsPerDay, l.MissesPerMinute = 0, 0, 0, 0, 0
	l.ReceiveBurst, l.DrainBurst, l.CallBurst, l.CertificatesPerDay, l.CertificateRevocationsPerDay = 0, 0, 0, 0, 0
	l.RangeRegistrationsPerHour, l.RequestBurst = 0, 0
	return l
}

// newEnv is a test server with limits l, on the test store; each of with
// changes its Config first.
func newEnv(t *testing.T, l Limits, with ...func(*Config)) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	var ready func() bool
	e.store, ready = newTestStore(t, e.clock.Now)
	c := Config{Store: e.store, Limits: l, Now: e.clock.Now, Ready: ready}
	for _, f := range with {
		f(&c)
	}
	e.server = New(c)
	h := apitest.Handler(t, e.server.Handler())
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		m := e.middle
		e.mu.Unlock()
		if m != nil {
			m(w, r, h)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) setMiddle(m func(w http.ResponseWriter, r *http.Request, next http.Handler)) {
	e.mu.Lock()
	e.middle = m
	e.mu.Unlock()
}

func (e *env) opts() client.Options {
	return client.Options{Base: e.srv.URL, Now: e.clock.Now}
}

// box makes and registers a box.
func (e *env) box(kt protocol.KeyType) *client.Box {
	e.t.Helper()
	b := e.heldBox(kt)
	landAll(e.t, b)
	return b
}

// landAll gives a box the policy that lands every sender's mail in inbox/:
// the tests that use it are of the server, not of where the client lands
// mail.
func landAll(t *testing.T, b *client.Box) {
	t.Helper()
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		t.Fatal(err)
	}
}

// heldBox makes a box with the client's default policy, which holds mail
// from a sender it has not allowed.
func (e *env) heldBox(kt protocol.KeyType) *client.Box {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), e.opts(), kt)
	if err != nil {
		e.t.Fatalf("init: %v", err)
	}
	return b
}

func send(t *testing.T, from, to *client.Box, body string) *protocol.Receipt {
	t.Helper()
	r, err := from.Send(context.Background(), to.Address(), body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return &r.Receipt
}

func receive(t *testing.T, b *client.Box) *client.Result {
	t.Helper()
	res, err := b.Receive(context.Background())
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return res
}

func bodyOf(t *testing.T, d client.Delivery) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(d.Envelope.Body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// signer loads a box's identity key from its state directory, as an operator
// who stole it, or a test, would.
func signer(t *testing.T, b *client.Box) ssh.Signer {
	t.Helper()
	k, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.PostQuantum), e.box(protocol.Classic)

	body := "hello <b>&é☃ — mail is data"
	r := send(t, a, b, body)
	if len(r.ID) != 64 {
		t.Fatalf("receipt id %q", r.ID)
	}
	res := receive(t, b)
	if len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("delivered %d, refused %v", len(res.Delivered), res.Refused)
	}
	d := res.Delivered[0]
	if got := bodyOf(t, d); got != body {
		t.Fatalf("body %q", got)
	}
	if d.Envelope.From != a.Address() || d.ID != r.ID {
		t.Fatal("wrong sender or id")
	}
	if in, err := os.ReadFile(filepath.Join(b.Dir(), "inbox", r.ID+".json")); err != nil || !bytes.Equal(in, d.Line) {
		t.Fatalf("inbox copy: %v", err)
	}
	if !bytes.Contains(d.Plaintext, []byte("<b>&")) {
		t.Fatal("the envelope is HTML-escaped")
	}

	// Acked: the box is empty, and the client keeps the empty page's ETag;
	// its next poll sends it back and is 304, the interval in Retry-After.
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("delivered twice")
	}
	var polls []int
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if strings.HasSuffix(r.URL.Path, "/messages") {
			polls = append(polls, sw.status)
		}
	})
	if res := receive(t, b); res.PollAfter != int64(DefaultLimits().PollAfter) {
		t.Fatalf("a 304's interval is %d, want the Retry-After, %d", res.PollAfter, DefaultLimits().PollAfter)
	}
	if len(polls) != 1 || polls[0] != http.StatusNotModified {
		t.Fatalf("an empty poll after an empty one got %v, want [304]", polls)
	}
	e.setMiddle(nil)

	// A reply, the other way, PQ this time.
	send(t, b, a, "reply")
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "reply" {
		t.Fatal("no reply")
	}
	// A message arriving after an empty poll is in the next.
	send(t, a, b, "second")
	if res := receive(t, b); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "second" {
		t.Fatal("the poll after an empty one missed new mail")
	}
}

// capture records the next send to box path to, "/v1/<address>", as the
// client made it: its serials and its ciphertext.
func capture(e *env, to string) *sealed {
	got := &sealed{}
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && r.URL.Path == to+"/messages" && got.ciphertext == nil {
			q, err := protocol.ParseSendQuery(r.URL.RawQuery)
			if err != nil {
				e.t.Errorf("the client's send: %v", err)
			}
			got.SendQuery = q
			got.ciphertext, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(got.ciphertext))
		}
		next.ServeHTTP(w, r)
	})
	return got
}

// A send's 201 names the message it made, at the path its recipient fetches
// it from (RFC 9110 §15.3.2); a retry's 200 makes nothing, and names nothing.
func TestASendNamesTheMessageItMade(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	req := e.sealTo(b)
	made := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", req, e.pass(a))
	var r protocol.Receipt
	if err := json.Unmarshal(made.body, &r); err != nil || made.status != http.StatusCreated {
		t.Fatalf("send: %d %s", made.status, made.body)
	}
	at := made.header.Get("Location")
	if at != "/v1/"+b.Address().String()+"/messages/"+r.ID {
		t.Fatalf("Location %q, receipt %s", at, r.ID)
	}
	got := e.do(http.MethodGet, at, nil, e.pass(b))
	if got.status != http.StatusOK || got.header.Get("Content-Type") != protocol.CiphertextContentType || !bytes.Equal(got.body, req.ciphertext) {
		t.Fatalf("fetching the Location: %d %v", got.status, got.header)
	}
	if retry := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", req, e.pass(a)); retry.status != http.StatusOK || retry.header.Get("Location") != "" {
		t.Fatalf("retry: %d, Location %q", retry.status, retry.header.Get("Location"))
	}
}

func TestRetryGetsOriginalReceipt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, "/v1/"+b.Address().String())
	r := send(t, a, b, "once")
	e.setMiddle(nil)

	retry := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a))
	var again protocol.Receipt
	if err := json.Unmarshal(retry.body, &again); err != nil || retry.status != http.StatusOK || again != *r {
		t.Fatalf("retry: %d %s, want 200 and %+v", retry.status, retry.body, *r)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want 1", len(res.Delivered))
	}
	// Still a retry after the ack: the dedupe record outlives it.
	e.want(e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a)), http.StatusOK, "")
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("a retry after the ack was delivered again")
	}
}

// A new prekey comes under a new certificate: the pass the box held before
// it, which the server had taken, is refused.
func TestPassRefusedAfterRekey(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.box(protocol.Classic)
	receive(t, b)
	// A pass under the certificate in use, as the box signs one.
	pass := func() string { return e.pass(b) }
	old := pass()
	messages := "/v1/" + b.Address().String() + "/messages"
	e.want(e.do(http.MethodGet, messages, nil, old), http.StatusOK, "")
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if pass() == old {
		t.Fatal("a new prekey did not bring a new pass")
	}
	e.want(e.do(http.MethodGet, messages, nil, old), http.StatusUnauthorized, protocol.CodeCertificateNotCurrent)
	e.want(e.do(http.MethodGet, messages, nil, pass()), http.StatusOK, "")
	// The client signing a new pass when one is refused is tested in
	// dromas-client.
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c - 'a' + 10)
			default:
				t.Fatalf("not hex: %q", s)
			}
		}
		b[i] = v
	}
	return b
}

// A box whose prekey expired still works for its owner, and renews. (Senders
// refusing the expired prekey is tested in dromas-client.)
func TestRenewalAfterExpiry(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	e.clock.Add(protocol.MaxPrekeyLifetime)
	// Both renew: b for a prekey mail can be sent to, a for a certificate
	// with long enough left to sign mail under.
	for _, x := range []*client.Box{a, b} {
		if _, err := x.Rekey(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
	}
	send(t, a, b, "after renewal")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after renewal")
	}
}

func TestRecoveryWithIdentityAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.PostQuantum), e.box(protocol.PostQuantum)
	// A restored machine: the identity, nothing else.
	for _, g := range []string{"prekeys/*", "work/*", "state"} {
		names, _ := filepath.Glob(filepath.Join(b.Dir(), g))
		for _, n := range names {
			if err := os.Remove(n); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, b, "after recovery")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after recovery")
	}
}

func TestPagination(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PairCap = 0
	l.PollBurst = 1 // a drain of two pages is one poll, and a continuation
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	const n = pageSize + 5
	for i := range n {
		send(t, a, b, strings.Repeat("x", i))
		e.clock.Add(time.Millisecond) // oldest first is by receipt time, then id
	}
	res := receive(t, b)
	if len(res.Delivered) != n {
		t.Fatalf("delivered %d, want %d", len(res.Delivered), n)
	}
	// Oldest first.
	for i, d := range res.Delivered {
		if got := bodyOf(t, d); len(got) != i {
			t.Fatalf("message %d out of order", i)
		}
	}
}

func TestLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("pair_full", func(t *testing.T) {
		l := relaxed()
		l.PairCap = 2
		e := newEnv(t, l)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, a, b, "2")
		_, err := a.Send(ctx, b.Address(), "3")
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodePairFull || ae.Status != 429 ||
			ae.RetryAfter == 0 || ae.Problem.Unacked == nil || *ae.Problem.Unacked != 2 || ae.Problem.OldestExpiresAt == "" {
			t.Fatalf("third send: %v %+v", err, ae)
		}
		// Nothing is dropped to make room; the message waits in the outbox.
		receive(t, b)
		if rs, err := a.Flush(ctx); err != nil || len(rs) != 1 {
			t.Fatalf("flush: %v", err)
		}
	})
	t.Run("mailbox_full", func(t *testing.T) {
		l := relaxed()
		l.BoxCap = 2
		e := newEnv(t, l)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, c, b, "2")
		_, err := c.Send(ctx, b.Address(), "3")
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeMailboxFull || ae.Status != 429 || ae.RetryAfter == 0 ||
			ae.Problem.Count == nil || *ae.Problem.Count != 2 {
			t.Fatalf("send to a full box: %v %+v", err, ae)
		}
	})
	t.Run("sends per day", func(t *testing.T) {
		l := relaxed()
		l.SendsPerDay = 2
		e := newEnv(t, l)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, a, b, "2")
		if _, err := a.Send(ctx, b.Address(), "3"); !limitedBy(err, protocol.QuotaSends) {
			t.Fatalf("third send: %v", err)
		}
	})
	t.Run("polls", func(t *testing.T) {
		// A burst of 10 (a new box, or after a restart), then one more
		// every 50 s: a poll a minute never runs dry, one every 30 s does.
		l := relaxed()
		d := DefaultLimits()
		l.PollBurst, l.PollRefill = d.PollBurst, d.PollRefill
		e := newEnv(t, l)
		b := e.box(protocol.Classic)
		for range 10 {
			receive(t, b)
		}
		_, err := b.Receive(ctx)
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited || ae.RetryAfter != 50*time.Second {
			t.Fatalf("eleventh poll at once: %v", err)
		}
		e.clock.Add(50 * time.Second)
		receive(t, b)
		for range 60 { // an hour of polls once a minute
			e.clock.Add(time.Minute)
			receive(t, b)
		}
		e.clock.Add(10 * 50 * time.Second) // full again
		for i := range 23 {                // 11.5 minutes
			e.clock.Add(30 * time.Second)
			if _, err := b.Receive(ctx); err != nil {
				t.Fatalf("poll %d every 30 s: %v", i, err)
			}
		}
		e.clock.Add(30 * time.Second)
		if _, err := b.Receive(ctx); codeOf(err) != protocol.CodeRateLimited {
			t.Fatalf("polls every 30 s outlasted the burst: %v", err)
		}
	})
}

// The Go client against this server: a block reaches the server, which
// refuses the blocked sender's next send for good and deleted what it held
// from it; under "server allowed" a send to a new address tells the server
// first, so the reply is taken and a stranger's send is refused.
func TestTheGoClientsACL(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b, c, stranger := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "waits on the server")
	if _, err := b.Block(ctx, a.Address()); err != nil {
		t.Fatal(err)
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 0 {
		t.Fatalf("the box still holds %d messages, %v", n, err)
	}
	_, err := a.Send(ctx, b.Address(), "refused")
	if codeOf(err) != protocol.CodeSenderNotAllowed || !strings.Contains(err.Error(), "moved to outbox/failed/") {
		t.Fatalf("a send from a blocked sender: %v", err)
	}
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
		t.Fatal(err)
	}
	send(t, b, c, "hello")
	send(t, c, b, "the reply")
	if _, err := stranger.Send(ctx, b.Address(), "refused"); codeOf(err) != protocol.CodeSenderNotAllowed {
		t.Fatalf("a stranger's send: %v", err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("b received %+v", res)
	}
	rec, err := e.store.Box(ctx, b.Address())
	if err != nil || rec.ACL == nil || rec.ACL.Allow.Any || !rec.ACL.Allow.Has(c.Address()) || !rec.ACL.Deny.Has(a.Address()) || rec.ACL.Allow.Len() != 1 {
		t.Fatalf("the record holds %+v, %v", rec.ACL, err)
	}
}
