package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// caller makes requests from any address straight to e's server, wrapped as
// every test server is (apitest): a request comes from the address ip, as
// its peer, and is answered whatever it is, a router's plain 404 among them.
func (e *env) caller() func(ip, method, path string, body any, pass string) reply {
	return e.callerOf(apitest.Handler(e.t, e.server.Handler()))
}

// callerOf is caller, through h.
func (e *env) callerOf(h http.Handler) func(ip, method, path string, body any, pass string) reply {
	return func(ip, method, path string, body any, pass string) reply {
		e.t.Helper()
		var rd io.Reader = http.NoBody
		if body != nil {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Host = e.name()
		req.RemoteAddr = net.JoinHostPort(ip, "40000")
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
	}
}

// waits reports r's Retry-After, in seconds.
func waits(r reply) int {
	n, _ := strconv.Atoi(r.header.Get("Retry-After"))
	return n
}

// Every limit a rate_limited answers for names itself in quota_id, and whom
// it counted the call against in subject (PROTOCOL.md §11.5): the mailbox for a
// call with its pass, the address for one with none.
func TestEveryRefusalNamesItsLimit(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill = 1, time.Minute
	l.CallBurst, l.CallRefill = 1, time.Minute
	l.MissesPerMinute, l.SendsPerMinutePerIP, l.RegistrationsPerHour = 2, 1, 1
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)

	e.want(e.do("GET", b.path("/messages"), nil, b.pass(1)), http.StatusOK, "")
	e.limited(e.do("GET", b.path("/messages"), nil, b.pass(1)), protocol.QuotaPolls)

	e.want(e.do("GET", b.path("/acl"), nil, b.pass(1)), http.StatusOK, "")
	e.limited(e.do("GET", b.path("/acl"), nil, b.pass(1)), protocol.QuotaCalls)

	// The send's count is taken before its pass is read; a send with none is
	// a check that failed, one of the address's misses.
	e.want(e.do("POST", b.path("/messages"), nil, ""), http.StatusUnauthorized, "")
	e.limited(e.do("POST", b.path("/messages"), nil, ""), protocol.QuotaSendsBeforePass)

	e.want(e.do("GET", "/v1/"+strings.Repeat("c", 77), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e.limited(e.do("GET", "/v1/"+strings.Repeat("e", 77), nil, ""), protocol.QuotaMisses)

	// The registration came from this address, so its count is spent. With
	// it spent, a registration's read of its address is a lookup's, under a
	// miss: the misses come back first, so that read is made and finds
	// nothing.
	e.clock.Add(time.Minute)
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
	e.limited(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), protocol.QuotaRegistrations)
}

// A refusal of a mailbox's calls gives the longest wait among the mailbox's other
// counts in memory that the same call would spend, under that count's name
// (RFC 8555 §6.6; dromas-dev/dromas-server#56): a renewal's renewals a
// day. A send's sends a day are not among them: only the dedupe, behind the
// body, shows whether a send is a new message that spends them, so a send past
// its calls is told their wait, and one past its sends too meets them once
// that wait is over (dromas-dev/dromas-server#61).
func TestARefusalGivesTheLongestWait(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.CallBurst, l.CallRefill = 1, time.Minute
	l.SendsPerDay, l.RenewalsPerDay = 1, 1
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	to := "/v1/" + b.Address().String()

	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), http.StatusCreated, "")
	got := e.do("POST", to+"/messages", e.sealTo(b), e.pass(a))
	e.limited(got, protocol.QuotaCalls)
	if w := waits(got); w > 60 {
		t.Fatalf("a send past its calls and its sends waits %d s, want the calls' minute", w)
	}
	e.clock.Add(time.Minute)
	got = e.do("POST", to+"/messages", e.sealTo(b), e.pass(a))
	e.limited(got, protocol.QuotaSends)
	if w := waits(got); w < 23*3600 || w > 24*3600 {
		t.Fatalf("a send past its sends waits %d s, want the sends' day", w)
	}
	var p protocol.Problem
	if err := json.Unmarshal(got.body, &p); err != nil || p.Limit == nil || *p.Limit != 1 {
		t.Fatalf("the sends' refusal carries no limit: %s", got.body)
	}

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekeyUnder(r.by[1], 2, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1)), http.StatusOK, "")
	r.prekeyUnder(r.by[1], 3, until, nil)
	got = e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1))
	e.limited(got, protocol.QuotaRenewals)
	if w := waits(got); w < 23*3600 {
		t.Fatalf("a renewal past its calls and its renewals waits %d s, want the renewals' day", w)
	}
}

// The same ciphertext posted again, of a send the server holds, is never
// refused by a quota; a budget may defer it (PROTOCOL.md §11.5, §11.10 step 6). A
// retry past its sender's calls, with its sends a day spent, is told the
// calls' wait, and is then answered with the original receipt
// (dromas-dev/dromas-server#61).
func TestARetryPastTheCallsIsDeferredByTheCalls(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.CallBurst, l.CallRefill = 2, time.Minute
	l.SendsPerDay = 1
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	to := "/v1/" + b.Address().String() + "/messages"
	x := e.sealTo(b)

	first := e.do("POST", to, x, e.pass(a)) // the day's one send
	e.want(first, http.StatusCreated, "")
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/acl", nil, e.pass(a)), http.StatusOK, "") // and the last call
	got := e.do("POST", to, x, e.pass(a))
	e.limited(got, protocol.QuotaCalls)
	if w := waits(got); w > 60 {
		t.Fatalf("a retry past its calls waits %d s, want the calls' minute", w)
	}
	e.clock.Add(time.Minute)
	again := e.do("POST", to, x, e.pass(a))
	e.want(again, http.StatusOK, "")
	if !bytes.Equal(again.body, first.body) {
		t.Fatalf("the retry's receipt %s, want the original %s", again.body, first.body)
	}
}

// A registration is counted by the caller's IPv6 /48 as well as by its /64
// (dromas-dev/dromas-server#57): a /48 cannot register more by moving
// from one /64 to the next, a refusal by either spends neither, and an IPv4
// address has no /48 count. The operator's clear forgets both.
func TestRegistrationsAreCountedByTheRange(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RegistrationsPerHour, l.RangeRegistrationsPerHour = 2, 3
	e := newEnv(t, l)
	call := e.caller()
	register := func(ip string) reply {
		t.Helper()
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
		return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1))
	}
	e.want(register("2001:db8:1:1::1"), http.StatusCreated, "")
	e.want(register("2001:db8:1:1::2"), http.StatusCreated, "") // the same /64
	e.limited(register("2001:db8:1:1::3"), protocol.QuotaRegistrations)
	e.want(register("2001:db8:1:2::1"), http.StatusCreated, "") // another /64, the same /48: its third
	e.limited(register("2001:db8:1:3::1"), protocol.QuotaRegistrationsRange)
	e.limited(register("2001:db8:1:3::1"), protocol.QuotaRegistrationsRange) // what was refused spent nothing of its /64
	e.want(register("2001:db8:2:1::1"), http.StatusCreated, "")              // another /48
	for range 2 {
		e.want(register("192.0.2.9"), http.StatusCreated, "")
	}
	e.limited(register("192.0.2.9"), protocol.QuotaRegistrations)

	if _, cleared, _ := e.server.ClearAddress("2001:db8:1:3::5"); strings.Join(cleared, ",") != "registrations_range" {
		t.Fatalf("clearing an address in a spent /48 cleared %v", cleared)
	}
	e.want(register("2001:db8:1:3::1"), http.StatusCreated, "")
}

// Every call with no pass, and every request no route matches, the link page
// and a site's pages among them, spends one flood budget of its caller's
// address (dromas-dev/dromas-server#58), refused rate_limited naming
// requests. So do a registration and a renewal, whose bodies are read before
// any pass, and they are refused before their bodies are read
// (dromas-dev/dromas-server#34). A call whose pass comes first spends its
// mailbox's budgets, never this one, and another address's budget is its own.
func TestTheFloodBudget(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 8, time.Second
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	call := e.caller()
	const ip = "198.51.100.4"
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", b.path(""), http.StatusOK},
		{"GET", b.path("/revocations"), http.StatusNotFound},
		{"PUT", b.path("/revocations"), http.StatusBadRequest},
		{"PUT", b.path(""), http.StatusBadRequest},
		{"PUT", b.path("/prekey"), http.StatusBadRequest},
		{"GET", protocol.LinkPath + b.id.Address().String(), http.StatusOK},
		{"GET", "/v1/" + b.id.Address().String() + "/nothing/here", http.StatusNotFound},
		{"GET", "/nothing", http.StatusNotFound},
	} {
		if got := call(ip, c.method, c.path, nil, ""); got.status != c.status {
			t.Fatalf("%s %s: %d, want %d: %s", c.method, c.path, got.status, c.status, got.body)
		}
	}
	got := call(ip, "GET", b.path(""), nil, "")
	e.limited(got, protocol.QuotaRequests)
	if w := waits(got); w != 1 {
		t.Fatalf("the flood budget's wait: %d s, want 1", w)
	}
	e.limited(call(ip, "GET", "/nothing", nil, ""), protocol.QuotaRequests)
	e.limited(call(ip, "GET", protocol.LinkPath+b.id.Address().String(), nil, ""), protocol.QuotaRequests)
	// Each of these is answered from what its body holds, from an address
	// with its budget, and refused before its body is read from one without.
	b.prekeyUnder(b.by[1], 2, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
	e.want(e.do("PUT", b.path("/prekey"), b.upload(2), b.pass(1)), http.StatusOK, "")
	for _, c := range []struct {
		path   string
		body   any
		pass   string
		status int
	}{
		{b.path(""), b.registration(2), "", http.StatusUnauthorized},                       // sent again with no pass
		{b.path("/prekey"), b.upload(1), "", http.StatusConflict},                          // the mailbox's previous statement
		{b.path("/prekey"), strings.Repeat("A", 60<<10), b.pass(1), http.StatusBadRequest}, // not an object
	} {
		if got := call("198.51.100.6", "PUT", c.path, c.body, c.pass); got.status != c.status {
			t.Fatalf("PUT %s: %d, want %d: %s", c.path, got.status, c.status, got.body)
		}
		e.limited(call(ip, "PUT", c.path, c.body, c.pass), protocol.QuotaRequests)
	}
	if got := call(ip, "GET", b.path("/messages"), nil, b.pass(1)); got.status != http.StatusOK {
		t.Fatalf("a call with a pass from a flooding address: %d %s", got.status, got.body)
	}
	if got := call("198.51.100.5", "GET", b.path(""), nil, ""); got.status != http.StatusOK {
		t.Fatalf("another address: %d %s", got.status, got.body)
	}
	e.clock.Add(time.Second)
	e.want(call(ip, "GET", b.path(""), nil, ""), http.StatusOK, "")
	if _, cleared, _ := e.server.ClearAddress(ip); strings.Join(cleared, ",") != "requests" {
		t.Fatalf("clearing a flooding address cleared %v", cleared)
	}
}

// A request no route answers spends the flood budget whatever the router
// answers it with: a 405 for a method no route takes, the redirect of a path
// not in its canonical form or of a subtree named without its slash. A route
// that takes HEAD as GET answers it as itself.
func TestWhatNoRouteAnswersIsCounted(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	call := e.caller()
	direct := e.callerOf(e.server.Handler()) // the router's redirects, which no description holds
	for i, c := range []struct {
		method, path string
		status       int
		call         func(ip, method, path string, body any, pass string) reply
	}{
		{"POST", protocol.LinkPath + b.id.Address().String(), http.StatusMethodNotAllowed, call},
		{"DELETE", b.path("/revocations"), http.StatusMethodNotAllowed, call},
		{"GET", "/v1", http.StatusTemporaryRedirect, direct},
		{"GET", b.path("/messages/../acl"), http.StatusTemporaryRedirect, direct},
		{"HEAD", b.path(""), http.StatusOK, call}, // the read of a mailbox with no pass, which spends it as a route
	} {
		ip := "198.51.100." + strconv.Itoa(i+1)
		if got := c.call(ip, c.method, c.path, nil, ""); got.status != c.status {
			t.Fatalf("%s %s: %d, want %d", c.method, c.path, got.status, c.status)
		}
		e.limited(call(ip, "GET", "/nothing", nil, ""), protocol.QuotaRequests)
	}
	// A route a call with its pass reaches spends nothing of it.
	const ip = "198.51.100.99"
	e.want(call(ip, "GET", b.path("/acl"), nil, b.pass(1)), http.StatusOK, "")
	if got := call(ip, "GET", "/nothing", nil, ""); got.status != http.StatusNotFound {
		t.Fatalf("after a call with its pass, a request no route answers: %d", got.status)
	}
}

// A request is counted once, by the router or by the route it reaches, never
// by both, whatever its path escapes and whatever its method: the router
// matches the path as sent, where an escaped dot or slash is no separator,
// and leaves a CONNECT's path as sent (dromas-dev/dromas-server#60). A
// route that takes a pass spends none of the flood budget.
func TestARequestIsCountedOnceWhateverItsPathEscapes(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 3, time.Hour
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	direct := e.callerOf(e.server.Handler()) // a router's answers, which no description holds
	for i, c := range []struct {
		method, path, pass string
		status, spends     int
	}{
		{"GET", "/v1/%2e%2e/x", "", http.StatusNotFound, 1},                         // the router's 404, under /v1/
		{"CONNECT", "/v1/x/../y", "", http.StatusNotFound, 1},                       // the one method whose path the router leaves as sent
		{"GET", "/v1/%2e", "", http.StatusBadRequest, 1},                            // the read of a mailbox, with no pass: a route
		{"GET", "/to/%2e", "", http.StatusNotFound, 1},                              // the link page: a route
		{"GET", b.path("/messages/%2e%2e"), b.pass(1), http.StatusNotFound, 0},      // a route that takes a pass
		{"GET", b.path("/messages/.."), b.pass(1), http.StatusTemporaryRedirect, 1}, // the router's redirect
		{"GET", "*", "", http.StatusBadRequest, 1},                                  // the router's 400, given before it looks
	} {
		ip := "198.51.100." + strconv.Itoa(i+1)
		if got := direct(ip, c.method, c.path, nil, c.pass); got.status != c.status {
			t.Fatalf("%s %s: %d, want %d: %s", c.method, c.path, got.status, c.status, got.body)
		}
		left := 0
		for left < l.RequestBurst && direct(ip, "GET", "/nothing", nil, "").status == http.StatusNotFound {
			left++
		}
		if spent := l.RequestBurst - left; spent != c.spends {
			t.Errorf("%s %s spent %d of the flood budget, want %d", c.method, c.path, spent, c.spends)
		}
	}
}

// The operator lists the keys a limit holds deepest in debt now, deepest
// first, by the limit's name (limits top): which mailbox takes the most new messages,
// say. It keeps nothing, and knows every limit by the name a refusal gives it.
func TestLimitsTop(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.ReceiveBurst, l.ReceiveRefill = 10, time.Minute
	e := newEnv(t, l)
	a, b, c := e.mailbox(), e.mailbox(), e.mailbox()
	for range 3 {
		e.want(e.do("POST", "/v1/"+b.Address().String()+"/messages", e.sealTo(b), e.pass(a)), http.StatusCreated, "")
	}
	e.want(e.do("POST", "/v1/"+c.Address().String()+"/messages", e.sealTo(c), e.pass(a)), http.StatusCreated, "")
	top, ok := e.server.Top(string(protocol.CodeMailboxBusy), 1)
	if !ok || len(top) != 1 || top[0].Key != b.Address().String() || top[0].FullIn != 180 {
		t.Fatalf("the top of mailbox_busy: %+v %v, want b, full in 180 s", top, ok)
	}
	if top, _ := e.server.Top(string(protocol.CodeMailboxBusy), 5); len(top) != 2 || top[1].Key != c.Address().String() {
		t.Fatalf("the top two of mailbox_busy: %+v", top)
	}
	for _, q := range protocol.Quotas() {
		if _, ok := e.server.Top(string(q), 1); !ok {
			t.Errorf("limits top does not know the limit %s", q)
		}
	}
	if _, ok := e.server.Top("nonsense", 1); ok {
		t.Fatal("limits top knows a limit that is none")
	}
}

// limits top orders by the exact time to full, not by the seconds it shows
// (dromas-dev/dromas-server#63). With the flood budget at its defaults,
// 100 at once and one back each 20 ms, an address that spent 100 of 100 is
// deeper in debt than one that spent 51, though both show 2 s, and is the
// one --count 1 lists.
func TestLimitsTopListsTheDeepestInDebtFirst(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = DefaultLimits().RequestBurst, DefaultLimits().RequestRefill
	e := newEnv(t, l)
	call := e.caller()
	const deep, shallow = "198.51.100.9", "198.51.100.10" // as strings, the shallow one sorts first
	for range 100 {
		call(deep, "GET", "/nothing", nil, "")
	}
	for range 51 {
		call(shallow, "GET", "/nothing", nil, "")
	}
	full := func(key string) time.Duration {
		bs := e.server.requests
		bs.mu.Lock()
		defer bs.mu.Unlock()
		return bs.full[key].Sub(e.clock.Now())
	}
	if full(deep) <= full(shallow) {
		t.Fatalf("the setup: %s full in %s, %s in %s", deep, full(deep), shallow, full(shallow))
	}
	two, _ := e.server.Top(string(protocol.QuotaRequests), 2)
	one, _ := e.server.Top(string(protocol.QuotaRequests), 1)
	if len(one) != 1 || one[0].Key != deep || len(two) != 2 || two[1].Key != shallow || two[0].FullIn != two[1].FullIn {
		t.Fatalf("limits top --limit requests --count 1 lists %+v and --count 2 %+v, want %s (full in %s) before %s (full in %s), both shown as the same second",
			one, two, deep, full(deep), shallow, full(shallow))
	}
}
