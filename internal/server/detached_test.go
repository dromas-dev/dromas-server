package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5/pgconn"
)

// heldTillGone holds a write, while armed, until its request's context has
// ended, then makes it and returns the error its own context gives, as the
// store's database client does when its caller goes after the statement
// went out. The in-memory store ignores contexts, so this is what shows whose
// context a write runs on.
type heldTillGone struct {
	Store
	armed   atomic.Bool
	req     chan context.Context // the request's, from the middleware
	entered chan struct{}
	cut     atomic.Int32 // writes whose own context ended with their request's
}

func (h *heldTillGone) hold(ctx context.Context) bool {
	if !h.armed.Load() {
		return false
	}
	rc := <-h.req
	h.entered <- struct{}{}
	<-rc.Done()
	if ctx.Err() != nil {
		h.cut.Add(1)
	}
	return true
}

func (h *heldTillGone) PutMessage(ctx context.Context, mailbox protocol.Address, hd *Header, body []byte) (*Header, error) {
	held := h.hold(ctx)
	orig, err := h.Store.PutMessage(ctx, mailbox, hd, body)
	if err != nil || orig != nil || !held {
		return orig, err
	}
	return nil, ctx.Err()
}

func (h *heldTillGone) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	held := h.hold(ctx)
	if err := h.Store.UpdateMailbox(ctx, b); err != nil || !held {
		return err
	}
	return ctx.Err()
}

// A write runs to its end however its caller goes, and what it changed is
// counted (dromas-dev/dromas-server#14): a send and a renewal whose
// callers hang up while each is being written are stored, and each spends
// its count, so the next one is refused.
func TestAWriteOutlivesItsCallersHangUp(t *testing.T) {
	t.Parallel()
	ctx0 := context.Background()
	l := relaxed()
	l.SendsPerDay, l.RenewalsPerDay, l.SendsBurst, l.RenewalsBurst = 1, 1, 1, 1
	h := &heldTillGone{req: make(chan context.Context, 1), entered: make(chan struct{}, 1)}
	e := newEnv(t, l, func(c *Config) { h.Store, c.Store = c.Store, h })
	done := make(chan struct{}, 8)
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		held := h.armed.Load()
		if held {
			h.req <- r.Context()
		}
		next.ServeHTTP(w, r)
		if held {
			done <- struct{}{}
		}
	})
	hangUp := func(method, path, ctype string, body []byte, pass string) {
		t.Helper()
		ctx, cancel := context.WithCancel(ctx0)
		h.armed.Store(true)
		gone := make(chan struct{})
		go func() {
			defer close(gone)
			req, _ := http.NewRequestWithContext(ctx, method, e.srv.URL+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", ctype)
			req.Header.Set("Authorization", pass)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-h.entered
		h.armed.Store(false)
		cancel()
		<-gone
		<-done // the handler has returned
		if n := h.cut.Swap(0); n != 0 {
			t.Errorf("%s %s: the write ran on its request's context, which ended with it", method, path)
		}
	}

	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	hangUp("POST", to.path("/messages?")+to.sealed(1, nil).Encode(), protocol.CiphertextContentType, sealFor(t, to, 1), from.pass(1))
	if n, _ := e.store.Count(ctx0, to.id.Address()); n != 1 {
		t.Fatalf("a send whose caller hung up mid-write: the mailbox holds %d messages", n)
	}
	e.want(e.sendTo(to, 1, from, 1), http.StatusTooManyRequests, protocol.CodeRateLimited)

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekeyUnder(r.by[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	up, _ := json.Marshal(r.upload(2))
	hangUp("PUT", r.path("/prekey"), "application/json", up, r.pass(1))
	if b, _ := e.store.Mailbox(ctx0, r.id.Address()); b.Prekey.Serial != 2 {
		t.Fatalf("a renewal whose caller hung up mid-write: the mailbox is at prekey %d", b.Prekey.Serial)
	}
	r.prekeyUnder(r.by[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1)), http.StatusTooManyRequests, protocol.CodeRateLimited)

	// An ACL put whose caller hangs up while it is written still refuses
	// the sender its deny list matches.
	denied := e.raw().register(protocol.MaxPrekeyLifetime)
	acl, _ := json.Marshal(aclOf([]string{"*"}, []string{denied.id.Address().String()}))
	hangUp("PUT", r.path("/acl"), "application/json", acl, r.pass(1))
	e.want(e.sendTo(r, 2, denied, 1), http.StatusForbidden, protocol.CodeSenderNotAllowed)
}

// heldPut runs a hook before the next PutMessage, once.
type heldPut struct {
	Store
	mu  sync.Mutex
	put func()
}

func (s *heldPut) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	f := s.put
	s.put = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Store.PutMessage(ctx, mailbox, h, body)
}

// A message sent around a revocation of its mailbox's address does not outlive it
// (dromas-dev/dromas-server#15): a send that passed its check of the mailbox
// before the revocation and writes after it deletes what it wrote, and is
// answered 410.
func TestAMessageSentAroundARevocationDoesNotOutliveIt(t *testing.T) {
	t.Parallel()
	ctx0 := context.Background()
	s := &heldPut{}
	e := newEnv(t, relaxed(), func(c *Config) { s.Store, c.Store = c.Store, s })
	owner, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	writing, release := make(chan struct{}), make(chan struct{})
	s.mu.Lock()
	s.put = func() { close(writing); <-release }
	s.mu.Unlock()
	sent := make(chan reply, 1)
	go func() { sent <- e.sendTo(owner, 1, from, 1) }()
	<-writing
	sig, err := protocol.SignRevocation(owner.signer, owner.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", owner.path("/revocations"), protocol.Revocations{Identity: owner.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	close(release)
	e.want(<-sent, http.StatusGone, protocol.CodeRevoked)
	if n, _ := e.store.Count(ctx0, owner.id.Address()); n != 0 {
		t.Errorf("a send that wrote after the revocation left %d messages", n)
	}
}

// failPut fails each PutMessage with err, while err is set, and writes
// nothing.
type failPut struct {
	Store
	mu  sync.Mutex
	err error
}

func (s *failPut) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.PutMessage(ctx, mailbox, h, body)
}

// answering is a backend whose sends' writes answer err, and write nothing.
type answering struct {
	Backend
	err error
}

func (b answering) PutMessage(context.Context, protocol.Address, *Header, []byte) error {
	return b.err
}

// A count reserved for a write is kept when the write may have been applied,
// whatever error it returned, and given back only for a refusal the store
// stated (dromas-dev/dromas-server#14, #90): a send whose write met a
// timeout mid-statement, lost its answer, was applied and then lost it, or
// whose backend answered an error it states nothing of, spends its send a
// day; one PostgreSQL refused, or pgx never sent, or whose body's PUT failed
// before its row, does not. Each error is the one the store returns when its
// backend answers so: PostgreSQL's as pgOutcome reads it, or the injector's
// (faults).
func TestACountIsKeptWhenItsWriteMayHaveBeenApplied(t *testing.T) {
	t.Parallel()
	ctx := context.WithoutCancel(t.Context())
	// put is the error of a send's PutMessage when its backend answers err.
	put := func(err error) func() error {
		return func() error {
			s := NewMemStore(time.Now)
			s.backend = answering{s.backend, err}
			now := time.Now().UTC().Truncate(time.Millisecond)
			_, err := s.PutMessage(ctx, protocol.Address{4}, &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}, []byte("abc"))
			return err
		}
	}
	// injected is the error of a send's PutMessage when the injector makes it x.
	injected := func(x fault) func() error {
		return func() error {
			s := NewMemStore(time.Now)
			injectFaults(s).set("PutMessage", x)
			now := time.Now().UTC().Truncate(time.Millisecond)
			_, err := s.PutMessage(ctx, protocol.Address{4}, &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}, []byte("abc"))
			return err
		}
	}
	cases := []struct {
		name string
		err  func() error
		kept bool
	}{
		{"a timeout mid-statement", put(pgOutcome(context.DeadlineExceeded)), true},
		{"an answer lost", put(pgOutcome(io.ErrUnexpectedEOF)), true},
		{"applied, then its answer lost", injected(unknownAfter), true},
		{"an error of no kind its backend states", injected(unknownBefore), true},
		{"a refusal PostgreSQL stated", put(pgOutcome(&pgconn.PgError{Severity: "ERROR", Code: "40001"})), false},
		{"a write pgx never sent", put(pgOutcome(unsent(true))), false},
		{"a refusal of the body", injected(refusedBefore), false},
		{"a stale record", func() error { return ErrStale }, false},
	}
	errs := make([]error, len(cases))
	var wg sync.WaitGroup
	for i, c := range cases {
		wg.Go(func() { errs[i] = c.err() })
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := relaxed()
			l.SendsPerDay, l.SendsBurst = 1, 1
			s := &failPut{}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			s.mu.Lock()
			s.err = errs[i]
			s.mu.Unlock()
			e.want(e.sendTo(to, 1, from, 1), http.StatusServiceUnavailable, protocol.CodeUnavailable)
			s.mu.Lock()
			s.err = nil
			s.mu.Unlock()
			got := e.sendTo(to, 1, from, 1)
			t.Logf("the write's error: %v; the next send %d %s", errs[i], got.status, got.code())
			if (got.status == http.StatusTooManyRequests) != c.kept {
				t.Errorf("the next send %d %s; want the count kept %v", got.status, got.code(), c.kept)
			}
		})
	}
}
