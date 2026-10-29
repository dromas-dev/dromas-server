package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
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
