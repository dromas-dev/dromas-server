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

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/protocol"
)

// heldTillGone holds a write, while armed, until its request's context has
// ended, then makes it and returns the error its own context gives, as the
// AWS SDK does when its caller goes after the request went out. The
// in-memory store ignores contexts, so this is what shows whose context a
// write runs on.
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

func (h *heldTillGone) PutMessage(ctx context.Context, box protocol.Address, hd *Header, body []byte) (*Header, error) {
	held := h.hold(ctx)
	orig, err := h.Store.PutMessage(ctx, box, hd, body)
	if err != nil || orig != nil || !held {
		return orig, err
	}
	return nil, ctx.Err()
}

func (h *heldTillGone) UpdateBox(ctx context.Context, b *Box) error {
	held := h.hold(ctx)
	if err := h.Store.UpdateBox(ctx, b); err != nil || !held {
		return err
	}
	return ctx.Err()
}

// sealFor is an age file sealed to raw box to's prekey of the given serial.
func sealFor(t *testing.T, to *raw, serial uint64) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return ct.Bytes()
}

// A write runs to its end however its caller goes, and what it changed is
// counted (dromas-dev/dromas-server#14): a send and a renewal whose
// callers hang up while each is being written are stored, and each spends
// its count, so the next one is refused.
func TestAWriteOutlivesItsCallersHangUp(t *testing.T) {
	t.Parallel()
	ctx0 := context.Background()
	l := relaxed()
	l.SendsPerDay, l.RenewalsPerDay = 1, 1
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
	hangUp("POST", to.path("/messages?")+sealedTo(1, 1, nil).Encode(), protocol.CiphertextContentType, sealFor(t, to, 1), from.pass(1))
	if n, _ := e.store.Count(ctx0, to.id.Address()); n != 1 {
		t.Fatalf("a send whose caller hung up mid-write: the box holds %d messages", n)
	}
	e.want(e.sendTo(to, 1, 1, from, 1), http.StatusTooManyRequests, protocol.CodeRateLimited)

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekeyUnder(r.work[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	up, _ := json.Marshal(r.upload(2))
	hangUp("PUT", r.path("/prekey"), "application/json", up, r.pass(1))
	if b, _ := e.store.Box(ctx0, r.id.Address()); b.Prekey.Serial != 2 {
		t.Fatalf("a renewal whose caller hung up mid-write: the box is at prekey %d", b.Prekey.Serial)
	}
	r.prekeyUnder(r.work[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1)), http.StatusTooManyRequests, protocol.CodeRateLimited)

	// An ACL put whose caller hangs up while it is written still refuses
	// the sender its deny list matches.
	denied := e.raw().register(protocol.MaxPrekeyLifetime)
	acl, _ := json.Marshal(aclOf([]string{"*"}, []string{denied.id.Address().String()}))
	hangUp("PUT", r.path("/acl"), "application/json", acl, r.pass(1))
	e.want(e.sendTo(r, 2, 1, denied, 1), http.StatusForbidden, protocol.CodeSenderNotAllowed)
}

// heldPut runs a hook before the next PutMessage, once.
type heldPut struct {
	Store
	mu  sync.Mutex
	put func()
}

func (s *heldPut) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	f := s.put
	s.put = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Store.PutMessage(ctx, box, h, body)
}

// Mail sent around a revocation of its box's address does not outlive it
// (dromas-dev/dromas-server#15): a send that passed its check of the box
// before the revocation and writes after it deletes what it wrote, and is
// answered 410.
func TestMailSentAroundARevocationDoesNotOutliveIt(t *testing.T) {
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
	go func() { sent <- e.sendTo(owner, 1, 1, from, 1) }()
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

func (s *failPut) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.PutMessage(ctx, box, h, body)
}

// A count reserved for a write is kept when the write may have been applied,
// whatever error it returned, and given back only for a refusal the store or
// AWS stated (dromas-dev/dromas-server#14, #90): a send whose write timed
// out, or met a fault of AWS's own, or whose backend answered an error it
// states nothing of, spends its send a day; one AWS throttled, or refused
// for the call itself, or whose body's PUT failed before its item, does
// not. Each error is the one the store returns when the fake of AWS answers
// so, as the SDK makes it, or when its backend answers so (faults).
func TestACountIsKeptWhenItsWriteMayHaveBeenApplied(t *testing.T) {
	t.Parallel()
	every := func(a answer) func(string, int, []byte) answer { return func(string, int, []byte) answer { return a } }
	everyS3 := func(a answer) func(string, int) answer { return func(string, int) answer { return a } }
	// put is the error of a send's PutMessage on ctx when AWS answers so.
	put := func(ctx context.Context, dynamo func(string, int, []byte) answer, s3 func(string, int) answer) func() error {
		return func() error {
			f := newFakeAWS()
			f.dynamo, f.s3 = dynamo, s3
			now := time.Now().UTC().Truncate(time.Millisecond)
			h := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
			_, err := fakeStore(t, f).PutMessage(ctx, protocol.Address{4}, h, []byte("abc"))
			return err
		}
	}
	ctx := context.WithoutCancel(t.Context())
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	cases := []struct {
		name string
		err  func() error
		kept bool
	}{
		{"a timeout", put(short, every(answer{hang: true}), nil), true},
		{"a fault of AWS's own", put(ctx, every(answer500), nil), true},
		{"an error of no kind its backend states", func() error {
			s := NewMemStore(time.Now)
			injectFaults(s).set("PutMessage", unknownBefore)
			now := time.Now().UTC().Truncate(time.Millisecond)
			_, err := s.PutMessage(ctx, protocol.Address{4}, &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}, []byte("abc"))
			return err
		}, true},
		{"a throttle", put(ctx, every(answerPTEE), nil), false},
		{"a refusal of the call", put(ctx, every(answer{status: http.StatusBadRequest, body: dynErr("ValidationException", "")}), nil), false},
		{"a refusal of the body", put(ctx, nil, everyS3(answer{status: http.StatusForbidden, body: s3Err("AccessDenied")})), false},
		{"a fault of AWS's own at the body", put(ctx, nil, everyS3(answer{status: http.StatusInternalServerError, body: s3Err("InternalError")})), false},
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
			l.SendsPerDay = 1
			s := &failPut{}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			s.mu.Lock()
			s.err = errs[i]
			s.mu.Unlock()
			e.want(e.sendTo(to, 1, 1, from, 1), http.StatusServiceUnavailable, protocol.CodeUnavailable)
			s.mu.Lock()
			s.err = nil
			s.mu.Unlock()
			got := e.sendTo(to, 1, 1, from, 1)
			t.Logf("the write's error: %v (%s); the next send %d %s", errs[i], faultOf(errs[i]), got.status, got.code())
			if (got.status == http.StatusTooManyRequests) != c.kept {
				t.Errorf("the next send %d %s; want the count kept %v", got.status, got.code(), c.kept)
			}
		})
	}
}
