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

// emptyTag registers a mailbox and returns it with its empty first page's tag.
func emptyTag(e *env) (*raw, *raw, string) {
	e.t.Helper()
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	r := e.do("GET", to.path("/messages"), nil, to.pass(1))
	e.want(r, http.StatusOK, "")
	return from, to, r.header.Get("ETag")
}

// longPoll lists to's first page asking to wait, in a goroutine: its reply
// and how long it took come on the channel.
func longPoll(e *env, to *raw, tag, query string) <-chan struct {
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

// A long poll is answered the moment the mailbox changes: here, a send stored
// by this process (PROTOCOL.md §11.11).
func TestALongPollIsAnsweredWhenAMessageArrives(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to, tag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	time.Sleep(300 * time.Millisecond)
	select {
	case got := <-c:
		t.Fatalf("the long poll was answered %d before anything changed", got.r.status)
	default:
	}
	e.want(e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	got := <-c
	e.want(got.r, http.StatusOK, "")
	if got.took > 10*time.Second || got.r.header.Get("ETag") == tag {
		t.Fatalf("the long poll took %v, tag %q", got.took, got.r.header.Get("ETag"))
	}
}

// With nothing new, a long poll is answered 304 once max_wait passes,
// whatever longer wait it asked; it is one poll.
func TestALongPollWithNothingNewIs304AtMaxWait(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = time.Second
	l.PollBurst, l.PollRefill = 100, time.Hour
	e := newEnv(t, l)
	_, to, tag := emptyTag(e)
	before := debts(e.server, e.clock.Now())
	got := <-longPoll(e, to, tag, "wait=60")
	e.want(got.r, http.StatusNotModified, "")
	if got.took < l.MaxWait || got.took > l.MaxWait+5*time.Second || got.r.header.Get("ETag") != tag || got.r.header.Get("Retry-After") == "" {
		t.Fatalf("the long poll took %v, tag %q, Retry-After %q", got.took, got.r.header.Get("ETag"), got.r.header.Get("Retry-After"))
	}
	if p := debts(e.server, e.clock.Now())[string(protocol.QuotaPolls)] - before[string(protocol.QuotaPolls)]; p != 1 {
		t.Errorf("a long poll spent %d polls, want 1", p)
	}
}

// A wait with no If-None-Match naming the page, or of 0, has nothing to
// wait for and is answered at once.
func TestAWaitWithNothingToWaitForIsAnsweredAtOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, tag := emptyTag(e)
	for _, c := range []struct{ tag, query string }{{"", "wait=60"}, {`"another"`, "wait=60"}, {tag, "wait=0"}} {
		got := <-longPoll(e, to, c.tag, c.query)
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

// Past max_long_polls, a list of another mailbox that asks to wait is
// answered 503 with Retry-After, and the long polls go on.
func TestAHoldPastTheCapIs503(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxLongPolls = 1
	e := newEnv(t, l)
	_, to, tag := emptyTag(e)
	_, other, otherTag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	r := e.doWith("GET", other.path("/messages?wait=60"), nil, other.pass(1), "If-None-Match", otherTag)
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

// A mailbox holds one list: a later one that asks to wait is held in its
// place, the earlier is answered 304 at once and recorded replaced, and the
// pair is counted one long poll, even at max_long_polls.
func TestALaterLongPollOfTheSameMailboxTakesThePlaceOfTheEarlier(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxLongPolls = 1
	e, m, _ := metered(t, l)
	_, to, tag := emptyTag(e)
	first := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	second := longPoll(e, to, tag, "wait=60")
	var got struct {
		r    reply
		took time.Duration
	}
	select {
	case got = <-first:
	case <-time.After(10 * time.Second):
		e.server.StopHolds()
		t.Fatal("the earlier list was still held 10 s after a later one of its mailbox")
	}
	e.want(got.r, http.StatusNotModified, "")
	if got.r.header.Get("ETag") != tag {
		t.Fatalf("the earlier list was answered tag %q, want %q", got.r.header.Get("ETag"), tag)
	}
	if n := testutil.ToFloat64(m.held.WithLabelValues("replaced")); n != 1 {
		t.Errorf("%v holds recorded replaced, want 1", n)
	}
	holdingNow(t, e.server, 1)
	select {
	case got := <-second:
		t.Fatalf("the later list was answered %d before anything changed", got.r.status)
	case <-time.After(300 * time.Millisecond):
	}
	e.server.StopHolds()
	e.want((<-second).r, http.StatusNotModified, "")
	holdingNow(t, e.server, 0)
}

// Past max_long_polls_per_range, a list from that range that asks to wait is
// answered 503 with Retry-After, and recorded refused_range, while the pool
// has room; the long polls go on.
func TestAHoldPastItsRangesShareIs503(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxLongPollsPerRange = 1
	e, m, _ := metered(t, l)
	_, to, tag := emptyTag(e)
	_, other, otherTag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	r := e.doWith("GET", other.path("/messages?wait=60"), nil, other.pass(1), "If-None-Match", otherTag)
	e.want(r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if r.header.Get("Retry-After") == "" {
		t.Error("a hold refused at its range's share carries no Retry-After")
	}
	if n := testutil.ToFloat64(m.held.WithLabelValues(refusedRange)); n != 1 {
		t.Errorf("%v holds recorded %s, want 1", n, refusedRange)
	}
	e.server.StopHolds()
	e.want((<-c).r, http.StatusNotModified, "")
	holdingNow(t, e.server, 0)
}

// A range's share counts the long polls from it: a mailbox's later list from
// the same range takes its earlier's place even at the share, one from a
// full range is refused and leaves the earlier held, one from a range with
// room moves the count to it, and a list's end gives its range's back.
func TestARangesShareCountsTheListsHeldFromIt(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxLongPollsPerRange = 1
	e := newEnv(t, l)
	_, a, _ := emptyTag(e)
	_, b, _ := emptyTag(e)
	s := e.server
	first, why := s.hold(a.id.Address(), "192.0.2.1")
	if why != "" {
		t.Fatalf("the first hold of 192.0.2.1 was %s", why)
	}
	if _, why := s.hold(b.id.Address(), "192.0.2.1"); why != refusedRange {
		t.Fatalf("a second mailbox's hold from a full range was %q, want %s", why, refusedRange)
	}
	again, why := s.hold(a.id.Address(), "192.0.2.1")
	if why != "" {
		t.Fatalf("a mailbox's later hold from its own full range was %s", why)
	}
	select {
	case <-first:
	default:
		t.Fatal("the earlier hold was not ended by the later one")
	}
	other, why := s.hold(b.id.Address(), "2001:db8:1::/48")
	if why != "" {
		t.Fatalf("a hold from a range with room was %s", why)
	}
	if _, why := s.hold(a.id.Address(), "2001:db8:1::/48"); why != refusedRange {
		t.Fatalf("a mailbox's later hold from another, full range was %q, want %s", why, refusedRange)
	}
	select {
	case <-again:
		t.Fatal("a refused hold ended the one it would have replaced")
	default:
	}
	s.unhold(a.id.Address(), first) // replaced: gives nothing back
	if _, why := s.hold(b.id.Address(), "192.0.2.1"); why != refusedRange {
		t.Fatalf("a replaced hold's end gave its range back: %q", why)
	}
	s.unhold(a.id.Address(), again)
	if _, why := s.hold(a.id.Address(), "192.0.2.1"); why != "" {
		t.Fatalf("a hold's end did not give its range back: %s", why)
	}
	now, _ := s.hold(a.id.Address(), "192.0.2.1")
	s.unhold(b.id.Address(), other)
	if _, why := s.hold(a.id.Address(), "2001:db8:1::/48"); why != "" {
		t.Fatalf("a mailbox's later hold from another range with room was %s", why)
	}
	select {
	case <-now:
	default:
		t.Fatal("the earlier hold was not ended by the later one from another range")
	}
	if _, why := s.hold(b.id.Address(), "192.0.2.1"); why != "" {
		t.Fatalf("a hold that moved to another range left its count in the first: %s", why)
	}
	if n := s.holding.Load(); n != 2 {
		t.Fatalf("%d lists counted held, want 2", n)
	}
}

// A caller's range is its IPv4 address or its IPv6 /48.
func TestALongPollsRangeIsItsIPv4AddressOrIPv6Slash48(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]string{
		"192.0.2.9":           "192.0.2.9",
		"::ffff:192.0.2.9":    "192.0.2.9",
		"2001:db8:1:2::3":     "2001:db8:1::/48",
		"2001:db8:1:ffff::9":  "2001:db8:1::/48",
		"fe80::1%eth0":        "fe80::/48",
		"not an address here": "not an address here",
	} {
		if got := longPollRange(host); got != want {
			t.Errorf("longPollRange(%q) = %q, want %q", host, got, want)
		}
	}
}

// When the server stops, every long poll is answered 304 at once.
func TestStoppingAnswersEveryLongPoll(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	_, to, tag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	time.Sleep(300 * time.Millisecond)
	e.server.StopHolds()
	got := <-c
	e.want(got.r, http.StatusNotModified, "")
	if got.took > 5*time.Second {
		t.Fatalf("a long poll took %v to answer once the server stopped", got.took)
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
			t.Fatalf("%d long polls, want %d", s.holding.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A message's expiry is no change memory applies, and it changes the page:
// a long poll on a page that holds the message is answered as it expires,
// not at max_wait (PROTOCOL.md §11.11).
func TestALongPollIsAnsweredWhenAMessageExpires(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = 4 * time.Second
	e := newEnv(t, l)
	from, to, _ := emptyTag(e)
	e.want(e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	const left = 500 * time.Millisecond
	e.clock.Add(protocol.Retention - left) // the message has half a second left
	r := e.do("GET", to.path("/messages"), nil, to.pass(1))
	e.want(r, http.StatusOK, "")
	if !bytes.Contains(r.body, []byte(`"count":1`)) {
		t.Fatalf("control: the page does not hold the message: %s", r.body)
	}
	tag := r.header.Get("ETag")
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	e.clock.Add(left) // it expires now, by the server's clock
	got := <-c
	e.want(got.r, http.StatusOK, "")
	if got.took >= l.MaxWait-time.Second || got.r.header.Get("ETag") == tag || !bytes.Contains(got.r.body, []byte(`"count":0`)) {
		t.Fatalf("the long poll was answered after %v, tag %q, %s; want the empty page as the message expired", got.took, got.r.header.Get("ETag"), got.r.body)
	}
}

// laggingList is a backend whose eventually consistent page lags every
// write: it misses every message, as a Query read just after a write can.
type laggingList struct{ *memBackend }

func (b laggingList) List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	if !consistent {
		return nil, nil
	}
	return b.memBackend.List(ctx, mailbox, after, limit, consistent)
}

// The page of a list asked to wait is read strongly consistent: a long poll
// woken by a send is answered a page that holds it, never one that lags the
// count, whose tag a client could hold on with no later change to wake it.
func TestALongPollIsAnsweredAPageThatHoldsWhatWokeIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed(), func(c *Config) {
		m := newMemory(c.Now, DefaultMailboxCache, nil, nil)
		b := laggingList{newMemBackend(m.clock)}
		m.backend = b
		if err := b.Start(context.Background(), m.apply); err != nil {
			t.Fatal(err)
		}
		c.Store, c.Ready = m, b.Ready
	})
	from, to, tag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	e.want(e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
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

// A long poll woken by changes that leave its page as it was is held again:
// it is one poll, and one long poll, counted once by how it ended, and it is
// no longer counted held once answered.
func TestALongPollWokenToTheSamePageIsOnePollAndOneHold(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxWait = 2 * time.Second
	l.PollBurst, l.PollRefill = 100, time.Hour
	e, m, _ := metered(t, l)
	_, to, tag := emptyTag(e)
	before := debts(e.server, e.clock.Now())
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	mem := e.store.(*Memory)
	for range 3 {
		mem.idx.setRevocations(to.id.Address(), false, 0) // a change that moves nothing in the page
		time.Sleep(100 * time.Millisecond)
	}
	got := <-c
	e.want(got.r, http.StatusNotModified, "")
	if p := debts(e.server, e.clock.Now())[string(protocol.QuotaPolls)] - before[string(protocol.QuotaPolls)]; p != 1 {
		t.Errorf("a long poll woken three times spent %d polls, want 1", p)
	}
	changed, waited := testutil.ToFloat64(m.held.WithLabelValues("changed")), testutil.ToFloat64(m.held.WithLabelValues("waited"))
	if changed != 0 || waited != 1 {
		t.Errorf("one long poll, woken three times to the same page: long_polls_total changed=%v waited=%v, want waited=1 alone", changed, waited)
	}
	if n := e.server.holding.Load(); n != 0 {
		t.Errorf("%d lists still counted held", n)
	}
}

// A caller that leaves a long poll is no longer counted held, and is
// recorded as nginx records it, 499 with nothing sent, never as a 503.
func TestACallerThatLeavesALongPollIsReleasedAndRecordedGone(t *testing.T) {
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
		t.Errorf("a caller that left a long poll: requests_total 499=%v, 503=%v; want 499 once", g, u)
	}
	if g := testutil.ToFloat64(m.held.WithLabelValues("gone")); g != 1 {
		t.Errorf("long_polls_total{gone}=%v, want 1", g)
	}
}

// failingCount fails the mailbox's count once fail is set: a read of the mailbox,
// after a wake, that fails.
type failingCount struct {
	Store
	fail atomic.Bool
}

func (s *failingCount) Count(ctx context.Context, mailbox protocol.Address) (int, error) {
	if s.fail.Load() {
		return 0, errors.New("injected: a read that fails")
	}
	return s.Store.Count(ctx, mailbox)
}

// A long poll whose read after a wake fails is answered 503, and is no
// longer counted held.
func TestALongPollWhoseReadFailsIsReleased(t *testing.T) {
	t.Parallel()
	var fc *failingCount
	e := newEnv(t, relaxed(), func(c *Config) { fc = &failingCount{Store: c.Store}; c.Store = fc })
	_, to, tag := emptyTag(e)
	c := longPoll(e, to, tag, "wait=60")
	holdingNow(t, e.server, 1)
	fc.fail.Store(true)
	e.store.(*Memory).idx.setRevocations(to.id.Address(), false, 0) // wakes it
	got := <-c
	e.want(got.r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if n := e.server.holding.Load(); n != 0 {
		t.Fatalf("%d lists still counted held after a read that failed", n)
	}
}

// The API's HTTP server answers every long poll 304 when it shuts down, so
// Shutdown waits for none of them.
func TestShuttingTheAPIServerDownAnswersEveryLongPoll(t *testing.T) {
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
		t.Fatalf("Shutdown under a long poll: %v after %v", err, time.Since(start))
	}
	if status := <-answered; status != http.StatusNotModified {
		t.Fatalf("the long poll was answered %d, want 304", status)
	}
}
