package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Every limit keyed by a caller's address counts it by its IPv4 address or
// IPv6 /64 and by its IPv6 /48, and a refusal names the count that refused it
// (dromas-dev/dromas-server#202). The limits are read from the code
// (addressLimits): one added there is held to this too.
func TestEveryAddressLimitIsCountedByTheSlash64AndTheSlash48(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	for _, l := range New(Config{Store: NewMemStore(nil), Limits: relaxed()}).addressLimits() {
		t.Run(l.ip.name, func(t *testing.T) {
			for _, name := range []string{l.ip.name, l.rng.name} {
				if s := protocol.Quota(name).Subject(); s != protocol.SubjectIP {
					t.Fatalf("the count %s is no quota counted against an IP (%q)", name, s)
				}
			}
			l.resize(2, time.Hour, 3, time.Hour)
			take := func(host string) *problem {
				t.Helper()
				return l.take(context.Background(), host, clock, "")
			}
			refusedBy := func(host, want string) {
				t.Helper()
				if p := take(host); p == nil || string(p.quota) != want {
					t.Fatalf("a call from %s past its count: refused by %v, want %s", host, p, want)
				}
			}
			for _, host := range []string{"2001:db8:1:1::1", "2001:db8:1:1::2", "2001:db8:1:2::1"} {
				if p := take(host); p != nil {
					t.Fatalf("a call from %s within both counts: %v", host, p)
				}
			}
			refusedBy("2001:db8:1:1::3", l.ip.name)  // its /64's third
			refusedBy("2001:db8:1:3::1", l.rng.name) // its /48's fourth
			refusedBy("2001:db8:1:3::1", l.rng.name) // and what was refused spent nothing of its /64
			if p := take("2001:db8:2:1::1"); p != nil {
				t.Fatalf("a call from another /48: %v", p)
			}
			if cleared := l.clear("2001:db8:1:3::9", now); strings.Join(cleared, ",") != l.rng.name {
				t.Fatalf("clearing an address of a spent /48 cleared %v, want %s alone", cleared, l.rng.name)
			}
			for range 2 {
				if p := take("2001:db8:1:3::1"); p != nil {
					t.Fatalf("a call from a /64 the refusals never counted: %v", p)
				}
			}
			for range 2 {
				if p := take("192.0.2.9"); p != nil {
					t.Fatalf("a call from an IPv4 address, which has no /48 count: %v", p)
				}
			}
			refusedBy("192.0.2.9", l.ip.name)
		})
	}
}

// Lookups of mailboxes that do not exist, from many /64s of one /48, are
// refused past the /48's misses, misses_range, each a read of the mailboxes
// table (dromas-dev/dromas-server#202).
func TestMissesAreCountedByTheRange(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute, l.RangeMissesPerMinute = 2, 3
	e := newEnv(t, l)
	call := e.caller()
	lookup := func(ip string) reply {
		t.Helper()
		return call(ip, "GET", e.raw().path(""), nil, "") // a new address each time: no remembered miss
	}
	e.want(lookup("2001:db8:7:1::1"), http.StatusNotFound, "")
	e.want(lookup("2001:db8:7:1::1"), http.StatusNotFound, "")
	e.limited(lookup("2001:db8:7:1::1"), protocol.QuotaMisses)
	e.want(lookup("2001:db8:7:2::1"), http.StatusNotFound, "")
	e.limited(lookup("2001:db8:7:3::1"), protocol.QuotaMissesRange)
	e.want(lookup("2001:db8:8:1::1"), http.StatusNotFound, "")
}

// The flood budget is counted by the /48 too: requests no route matches,
// from many /64s of one /48, are refused past the /48's, requests_range
// (dromas-dev/dromas-server#202).
func TestTheFloodBudgetIsCountedByTheRange(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill, l.RangeRequestBurst, l.RangeRequestRefill = 2, time.Hour, 3, time.Hour
	e := newEnv(t, l)
	call := e.caller()
	for _, ip := range []string{"2001:db8:9:1::1", "2001:db8:9:1::1", "2001:db8:9:2::1"} {
		e.want(call(ip, "GET", "/nothing", nil, ""), http.StatusNotFound, "")
	}
	e.limited(call("2001:db8:9:1::1", "GET", "/nothing", nil, ""), protocol.QuotaRequests)
	e.limited(call("2001:db8:9:3::1", "GET", "/nothing", nil, ""), protocol.QuotaRequestsRange)
	e.want(call("2001:db8:a:1::1", "GET", "/nothing", nil, ""), http.StatusNotFound, "")
}

// A call that is its address's holds a place among the bodies its address
// has open while its route reads its body, before any pass is checked: past
// MaxBodiesBeforePass of its /64, or MaxBodiesBeforePassPerRange of its
// /48, a call with a body is answered 503 before its route reads anything,
// and the place comes back once the route has answered
// (dromas-dev/dromas-server#204). A call with no body takes no place.
func TestABodyPastItsAddressesOpenBodiesIs503(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxBodiesBeforePass, l.MaxBodiesBeforePassPerRange = 1, 2
	e := newEnv(t, l)
	h := e.server.Handler()
	var wg sync.WaitGroup
	// slow starts a registration from ip whose body has not arrived, and
	// returns what sends the rest of it.
	slow := func(ip string) (finish func()) {
		t.Helper()
		pr, pw := io.Pipe()
		req := httptest.NewRequest("PUT", e.raw().path(""), pr)
		req.Host, req.RemoteAddr, req.ContentLength = e.name(), net.JoinHostPort(ip, "40000"), -1
		wg.Go(func() { h.ServeHTTP(httptest.NewRecorder(), req) })
		return func() { _ = pw.CloseWithError(io.ErrUnexpectedEOF) }
	}
	open := func(host string) int {
		b := e.server.bodies
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.ip[ipKey(host)]
	}
	waitOpen := func(host string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); open(host) == 0; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("a slow body from %s never took its place", host)
			}
		}
	}
	call := e.caller()
	withBody := func(ip string) reply {
		t.Helper()
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
		return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1))
	}
	finishA := slow("2001:db8:b:1::1")
	waitOpen("2001:db8:b:1::1")
	e.want(withBody("2001:db8:b:1::2"), http.StatusServiceUnavailable, protocol.CodeUnavailable) // its /64's second
	e.want(call("2001:db8:b:1::2", "GET", e.raw().path(""), nil, ""), http.StatusNotFound, "")   // no body, no place
	finishB := slow("2001:db8:b:2::1")
	waitOpen("2001:db8:b:2::1")
	r := withBody("2001:db8:b:3::1") // its /48's third
	e.want(r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if !strings.Contains(string(r.body), "/48") {
		t.Fatalf("a body past its /48's: %s, want the refusal to name the /48", r.body)
	}
	e.want(withBody("2001:db8:c:1::1"), http.StatusCreated, "") // another /48
	e.want(withBody("192.0.2.7"), http.StatusCreated, "")
	finishA()
	finishB()
	wg.Wait()
	if n := open("2001:db8:b:1::1") + open("2001:db8:b:2::1"); n != 0 {
		t.Fatalf("after both slow bodies were answered: %d places still taken", n)
	}
	e.want(withBody("2001:db8:b:1::3"), http.StatusCreated, "")
}
