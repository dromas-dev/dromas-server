package server

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The operator clears what the limits keyed by an address hold of one
// caller (AdminHandler): an address that spent its misses makes them again at
// once, the answer names the limits that held anything, and nothing else is
// touched. The interface is never on the API's routes.
func TestTheOperatorClearsAnAddress(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	l.MissesPerMinute = 2
	s := New(Config{Store: e.store, Limits: l, Now: e.clock.Now})
	srv := httptest.NewServer(apitest.Handler(t, s.Handler()))
	t.Cleanup(srv.Close)
	api := &env{t: t, clock: e.clock, srv: srv}
	n := 0
	missing := func() string { n++; return "/v1/" + nth(n).String() } // a mailbox nobody registered, a new one each time
	clear := func(ip string) (int, string, []string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.AdminHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/limits/clear?ip="+ip, nil))
		var got struct {
			Address string   `json:"address"`
			Cleared []string `json:"cleared"`
		}
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Cleared == nil {
				t.Fatalf("the answer: %v: %s", err, w.Body)
			}
		}
		return w.Code, got.Address, got.Cleared
	}

	for range l.MissesPerMinute {
		api.want(api.do(http.MethodGet, missing(), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	}
	api.want(api.do(http.MethodGet, missing(), nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	if code, key, cleared := clear("127.0.0.1"); code != http.StatusOK || key != "127.0.0.1" || !slices.Equal(cleared, []string{"misses"}) {
		t.Fatalf("clear: %d %q %v, want the address's misses", code, key, cleared)
	}
	for range l.MissesPerMinute {
		api.want(api.do(http.MethodGet, missing(), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	}
	api.want(api.do(http.MethodGet, missing(), nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)

	// Another address's counts are its own: clearing it clears nothing here.
	if code, _, cleared := clear("192.0.2.1"); code != http.StatusOK || len(cleared) != 0 {
		t.Fatalf("clear of an address that holds nothing: %d %v", code, cleared)
	}
	api.want(api.do(http.MethodGet, missing(), nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	// An IPv6 address is cleared as the limits count it, by its /64.
	if code, key, _ := clear("2001:db8:1:2:3:4:5:6"); code != http.StatusOK || key != "2001:db8:1:2::/64" {
		t.Fatalf("an IPv6 address: %d %q", code, key)
	}
	for _, bad := range []string{"", "nonsense", "127.0.0.1/8", "dromas.dev"} {
		if code, _, _ := clear(bad); code != http.StatusBadRequest {
			t.Errorf("clear %q: %d, want 400", bad, code)
		}
	}
	for _, r := range s.routes() {
		if r.pattern == "POST /limits/clear" {
			t.Fatal("the operator's interface is on the API's routes")
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/limits/clear?ip=127.0.0.1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("the API's handler answers the operator's command: %d", w.Code)
	}
}

// A caller's address is keyed without its IPv6 zone, which names an
// interface of this host and is no part of the address
// (dromas-dev/dromas-server#48): a link-local caller is counted by its
// /64 and its /48 as any other IPv6 caller is, the operator's clear reaches
// it written either way, and a trusted proxy reached over a link-local
// address is believed.
func TestAZonedCallerIsKeyedByItsSlash64(t *testing.T) {
	t.Parallel()
	peer := (&net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 1234}).String() // as net/http fills RemoteAddr
	l := relaxed()
	l.MissesPerMinute = 2
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, Now: time.Now, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("fe80::/64")}})
	h := apitest.Handler(t, s.Handler())
	n := 0
	miss := func(remote string) int {
		n++
		r := httptest.NewRequest(http.MethodGet, "/v1/"+nth(n).String(), nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if k, rk := ipKey("fe80::1%eth0"), rangeKey("2001:db8::1%eth0"); k != "fe80::/64" || rk != "2001:db8::/48" {
		t.Fatalf("a zoned address is keyed %q, its range %q; want fe80::/64 and 2001:db8::/48", k, rk)
	}
	for _, ip := range []string{"fe80::1", "fe80::1%eth0"} {
		for range l.MissesPerMinute {
			if c := miss(peer); c != http.StatusNotFound {
				t.Fatalf("a miss from %s: %d", peer, c)
			}
		}
		other := (&net.TCPAddr{IP: net.ParseIP("fe80::2"), Zone: "eth1", Port: 1234}).String()
		if c := miss(other); c != http.StatusTooManyRequests {
			t.Fatalf("%s, of the same /64: %d, want 429", other, c)
		}
		w := httptest.NewRecorder()
		s.AdminHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/limits/clear?ip="+url.QueryEscape(ip), nil))
		if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusOK || got != `{"address":"fe80::/64","cleared":["misses"]}` {
			t.Fatalf("clear %q: %d %s", ip, w.Code, got)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Forwarded-For", "192.0.2.7")
	if got := s.clientIP(r); got != "192.0.2.7" {
		t.Fatalf("a trusted proxy at %s: the client is %q", peer, got)
	}
}

// nth is the address whose last bytes are n: one nobody registered.
func nth(n int) protocol.Address {
	var a protocol.Address
	binary.BigEndian.PutUint64(a[len(a)-8:], uint64(n)) //nolint:gosec // a test's count
	return a
}
