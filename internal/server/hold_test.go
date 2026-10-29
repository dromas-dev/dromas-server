package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// emptyTag registers a box and returns it with its empty first page's tag.
func emptyTag(e *env) (*raw, *raw, string) {
	e.t.Helper()
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	r := e.do("GET", to.path("/messages"), nil, to.pass(1))
	e.want(r, http.StatusOK, "")
	return from, to, r.header.Get("ETag")
}

// heldList lists to's first page asking to wait, in a goroutine: its reply
// and how long it took come on the channel.
func heldList(e *env, to *raw, tag, query string) <-chan struct {
	r    reply
	took time.Duration
} {
	c := make(chan struct {
		r    reply
		took time.Duration
	}, 1)
	pass := to.pass(1)
	go func() {
		start := time.Now()
		r := e.doWith("GET", to.path("/messages?"+query), nil, pass, "If-None-Match", tag)
		c <- struct {
			r    reply
			took time.Duration
		}{r, time.Since(start)}
	}()
	return c
}

// A held list is answered the moment the box changes: here, a send stored
// by this process (PROTOCOL.md §11.11).
func TestAHeldListIsAnsweredWhenMailArrives(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to, tag := emptyTag(e)
	c := heldList(e, to, tag, "wait=60")
	time.Sleep(300 * time.Millisecond)
	select {
	case got := <-c:
		t.Fatalf("the held list was answered %d before anything changed", got.r.status)
	default:
	}
	e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	got := <-c
	e.want(got.r, http.StatusOK, "")
	if got.took > 10*time.Second || got.r.header.Get("ETag") == tag {
		t.Fatalf("the held list took %v, tag %q", got.took, got.r.header.Get("ETag"))
	}
}

// With nothing new, a held list is answered 304 once -max-wait passes,
// whatever longer wait it asked; it is one poll.
func TestAHeldListWithNothingNewIs304AtMaxWait(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = time.Second
	l.PollBurst, l.PollRefill = 100, time.Hour
	e := newEnv(t, l)
	_, to, tag := emptyTag(e)
	before := debts(e.server, e.clock.Now())
	got := <-heldList(e, to, tag, "wait=60")
	e.want(got.r, http.StatusNotModified, "")
	if got.took < l.MaxWait || got.took > l.MaxWait+5*time.Second || got.r.header.Get("ETag") != tag || got.r.header.Get("Retry-After") == "" {
		t.Fatalf("the held list took %v, tag %q, Retry-After %q", got.took, got.r.header.Get("ETag"), got.r.header.Get("Retry-After"))
	}
	if p := debts(e.server, e.clock.Now())[string(protocol.QuotaPolls)] - before[string(protocol.QuotaPolls)]; p != 1 {
		t.Errorf("a held list spent %d polls, want 1", p)
	}
}

// A wait with no If-None-Match naming the page, or of 0, has nothing to
// wait for and is answered at once.
func TestAWaitWithNothingToWaitForIsAnsweredAtOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, tag := emptyTag(e)
	for _, c := range []struct{ tag, query string }{{"", "wait=60"}, {`"another"`, "wait=60"}, {tag, "wait=0"}} {
		got := <-heldList(e, to, c.tag, c.query)
		if got.took > 5*time.Second {
			t.Errorf("If-None-Match %q, %s: answered after %v", c.tag, c.query, got.took)
		}
	}
}

// A wait that is not delay-seconds, or comes with a cursor, is refused.
func TestAWaitOfAnotherFormIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, _ := emptyTag(e)
	for _, q := range []string{"wait=", "wait=-1", "wait=1.5", "wait=1&wait=2", "wait=5&cursor=abc"} {
		r := e.do("GET", to.path("/messages?"+q), nil, to.pass(1))
		e.want(r, http.StatusBadRequest, protocol.CodeBadRequest)
	}
}

// Past -max-held-lists, a list that asks to wait is answered 503 with Retry-After,
// and the lists held go on.
func TestAHoldPastTheCapIs503(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxHeldLists = 1
	e := newEnv(t, l)
	_, to, tag := emptyTag(e)
	c := heldList(e, to, tag, "wait=60")
	deadline := time.Now().Add(5 * time.Second)
	for e.server.holding.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r := e.doWith("GET", to.path("/messages?wait=60"), nil, to.pass(1), "If-None-Match", tag)
	e.want(r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if r.header.Get("Retry-After") == "" {
		t.Error("a hold refused at the cap carries no Retry-After")
	}
	e.server.StopHolds()
	e.want((<-c).r, http.StatusNotModified, "")
	if n := e.server.holding.Load(); n != 0 {
		t.Fatalf("%d lists still counted held after a refusal at the cap and the held one's answer", n)
	}
}

// When the server stops, every held list is answered 304 at once.
func TestStoppingAnswersEveryHeldList(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, tag := emptyTag(e)
	c := heldList(e, to, tag, "wait=60")
	time.Sleep(300 * time.Millisecond)
	e.server.StopHolds()
	got := <-c
	e.want(got.r, http.StatusNotModified, "")
	if got.took > 5*time.Second {
		t.Fatalf("a held list took %v to answer once the server stopped", got.took)
	}
	if n := e.server.holding.Load(); n != 0 {
		t.Fatalf("%d lists still counted held", n)
	}
}

// holdingNow waits until s holds n lists, or fails.
func holdingNow(t *testing.T, s *Server, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.holding.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d lists held, want %d", s.holding.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A message's expiry is no change memory applies, and it changes the page:
// a list held on a page that holds the message is answered as it expires,
// not at -max-wait (PROTOCOL.md §11.11).
func TestAHeldListIsAnsweredWhenAMessageExpires(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = 4 * time.Second
	e := newEnv(t, l)
	from, to, _ := emptyTag(e)
	e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	const left = 500 * time.Millisecond
	e.clock.Add(protocol.Retention - left) // the message has half a second left
	r := e.do("GET", to.path("/messages"), nil, to.pass(1))
	e.want(r, http.StatusOK, "")
	if !bytes.Contains(r.body, []byte(`"count":1`)) {
		t.Fatalf("control: the page does not hold the message: %s", r.body)
	}
	tag := r.header.Get("ETag")
	c := heldList(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	e.clock.Add(left) // it expires now, by the server's clock
	got := <-c
	e.want(got.r, http.StatusOK, "")
	if got.took >= l.MaxWait-time.Second || got.r.header.Get("ETag") == tag || !bytes.Contains(got.r.body, []byte(`"count":0`)) {
		t.Fatalf("the held list was answered after %v, tag %q, %s; want the empty page as the message expired", got.took, got.r.header.Get("ETag"), got.r.body)
	}
}

// laggingList is a backend whose eventually consistent page lags every
// write: it misses every message, as a Query read just after a write can.
type laggingList struct{ *memBackend }

func (b laggingList) List(ctx context.Context, box protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	if !consistent {
		return nil, nil
	}
	return b.memBackend.List(ctx, box, after, limit, consistent)
}

// The page of a list asked to wait is read strongly consistent: a held list
// woken by a send is answered a page that holds it, never one that lags the
// count, whose tag a client could hold on with no later change to wake it.
func TestAHeldListIsAnsweredAPageThatHoldsWhatWokeIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed(), func(c *Config) {
		m := newMemory(c.Now, DefaultBoxCache, nil, nil)
		b := laggingList{newMemBackend(m.clock)}
		m.backend = b
		if err := b.Start(context.Background(), m.apply); err != nil {
			t.Fatal(err)
		}
		c.Store, c.Ready = m, b.Ready
	})
	from, to, tag := emptyTag(e)
	c := heldList(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	got := <-c
	e.want(got.r, http.StatusOK, "")
	var page protocol.MessageList
	if err := protocol.Unmarshal(got.r.body, &page); err != nil || page.Count != 1 || len(page.Messages) != 1 {
		t.Fatalf("the woken page: %s (%v); want the message the count holds", got.r.body, err)
	}
	// Control: a list not asked to wait reads the page eventually consistent.
	r := e.do("GET", to.path("/messages"), nil, to.pass(1))
	e.want(r, http.StatusOK, "")
	if err := protocol.Unmarshal(r.body, &page); err != nil || page.Count != 1 || len(page.Messages) != 0 {
		t.Fatalf("control: a list not asked to wait: %s; want the lagging page", r.body)
	}
}

// A held list woken by changes that leave its page as it was is held again:
// it is one poll, and one held list, counted once by how it ended, and it is
// no longer counted held once answered.
func TestAHeldListWokenToTheSamePageIsOnePollAndOneHold(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = 2 * time.Second
	l.PollBurst, l.PollRefill = 100, time.Hour
	e, m, _ := metered(t, l)
	_, to, tag := emptyTag(e)
	before := debts(e.server, e.clock.Now())
	c := heldList(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	mem := e.store.(*Memory)
	for range 3 {
		mem.idx.setRevocations(to.id.Address(), false, 0) // a change that moves nothing in the page
		time.Sleep(100 * time.Millisecond)
	}
	got := <-c
	e.want(got.r, http.StatusNotModified, "")
	if p := debts(e.server, e.clock.Now())[string(protocol.QuotaPolls)] - before[string(protocol.QuotaPolls)]; p != 1 {
		t.Errorf("a held list woken three times spent %d polls, want 1", p)
	}
	changed, waited := testutil.ToFloat64(m.held.WithLabelValues("changed")), testutil.ToFloat64(m.held.WithLabelValues("waited"))
	if changed != 0 || waited != 1 {
		t.Errorf("one held list, woken three times to the same page: held_lists_total changed=%v waited=%v, want waited=1 alone", changed, waited)
	}
	if n := e.server.holding.Load(); n != 0 {
		t.Errorf("%d lists still counted held", n)
	}
}

// A caller that leaves a held list is no longer counted held, and is
// recorded as nginx records it, 499 with nothing sent, never as a 503.
func TestACallerThatLeavesAHeldListIsReleasedAndRecordedGone(t *testing.T) {
	t.Parallel()
	e, m, _ := metered(t, relaxed())
	_, to, tag := emptyTag(e)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+to.path("/messages?wait=60"), nil)
	req.Header.Set("Authorization", to.pass(1))
	req.Header.Set("If-None-Match", tag)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	holdingNow(t, e.server, 1)
	cancel()
	<-done
	holdingNow(t, e.server, 0)
	const route = "GET /v1/{addr}/messages"
	gone := func() float64 { return testutil.ToFloat64(m.requests.WithLabelValues(route, "499", "")) }
	deadline := time.Now().Add(5 * time.Second)
	for gone() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g, u := gone(), testutil.ToFloat64(m.requests.WithLabelValues(route, "503", string(protocol.CodeUnavailable))); g != 1 || u != 0 {
		t.Errorf("a caller that left a held list: requests_total 499=%v, 503=%v; want 499 once", g, u)
	}
	if g := testutil.ToFloat64(m.held.WithLabelValues("gone")); g != 1 {
		t.Errorf("held_lists_total{gone}=%v, want 1", g)
	}
}

// failingCount fails the box's count once fail is set: a read of the box,
// after a wake, that fails.
type failingCount struct {
	Store
	fail atomic.Bool
}

func (s *failingCount) Count(ctx context.Context, box protocol.Address) (int, error) {
	if s.fail.Load() {
		return 0, errors.New("injected: a read that fails")
	}
	return s.Store.Count(ctx, box)
}

// A held list whose read after a wake fails is answered 503, and is no
// longer counted held.
func TestAHeldListWhoseReadFailsIsReleased(t *testing.T) {
	t.Parallel()
	var fc *failingCount
	e := newEnv(t, relaxed(), func(c *Config) { fc = &failingCount{Store: c.Store}; c.Store = fc })
	_, to, tag := emptyTag(e)
	c := heldList(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	fc.fail.Store(true)
	e.store.(*Memory).idx.setRevocations(to.id.Address(), false, 0) // wakes it
	got := <-c
	e.want(got.r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if n := e.server.holding.Load(); n != 0 {
		t.Fatalf("%d lists still counted held after a read that failed", n)
	}
}

// The API's HTTP server answers every held list 304 when it shuts down, so
// Shutdown waits for none of them.
func TestShuttingTheAPIServerDownAnswersEveryHeldList(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, tag := emptyTag(e)
	srv := e.server.HTTPServer("", time.Minute)
	srv.Handler = apitest.Handler(t, srv.Handler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+to.path("/messages?wait=60"), nil)
	req.Host = e.name() // the name the pass is for
	req.Header.Set("Authorization", to.pass(1))
	req.Header.Set("If-None-Match", tag)
	answered := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			answered <- 0
			return
		}
		_ = resp.Body.Close()
		answered <- resp.StatusCode
	}()
	holdingNow(t, e.server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown under a held list: %v after %v", err, time.Since(start))
	}
	if status := <-answered; status != http.StatusNotModified {
		t.Fatalf("the held list was answered %d, want 304", status)
	}
}
