package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// base64urlAlphabet is RFC 4648 §5's, each character at its value: what a
// reverse proxy in front matches a path's characters against, apart from how
// Shard reads an address's bytes.
const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// proxyShard is the shard of n a reverse proxy in front sends a path to, as
// a map over the path does, counted from 0 (shard I is index I-1): the first
// character after /v1/d_, by its base64url value; a path naming no mailbox
// goes to the first shard.
func proxyShard(path string, n int) int {
	rest, ok := strings.CutPrefix(path, "/v1/"+protocol.AddressForm+"_")
	if !ok || rest == "" {
		return 0
	}
	v := strings.IndexByte(base64urlAlphabet, rest[0])
	if v < 0 {
		return 0
	}
	return v * n / maxShards
}

// Every address is one shard's of every N, and the one a reverse proxy
// matching its first character sends it to; and so is it of shards of
// different N side by side. What is not an address is every shard's, for its
// route to refuse.
func TestEveryAddressIsOneShards(t *testing.T) {
	t.Parallel()
	layouts := [][]Shard{{{1, 4}, {2, 4}, {2, 2}}}
	for n := 1; n <= maxShards; n *= 2 {
		var l []Shard
		for i := 1; i <= n; i++ {
			l = append(l, Shard{i, n})
		}
		layouts = append(layouts, l)
	}
	for b := range 256 { // every first byte, so every first character
		var a protocol.Address
		a[0] = byte(b)
		addr := a.String()
		for _, l := range layouts {
			var owners []Shard
			for _, s := range l {
				if s.owns(addr) {
					owners = append(owners, s)
				}
			}
			if len(owners) != 1 {
				t.Fatalf("%s… is owned by %v of %v: want one", addr[:3], owners, l)
			}
			if o := owners[0]; o.N > 1 && proxyShard("/v1/"+addr+"/messages", o.N) != o.I-1 {
				t.Fatalf("%s… is shard %s's, and a proxy matching its first character sends it to %d of %d", addr[:3], o, proxyShard("/v1/"+addr, o.N)+1, o.N)
			}
		}
	}
	for _, s := range []string{"", "d_", "d_!", "x_AAAA", "not an address"} {
		if !(Shard{1, 2}).owns(s) {
			t.Errorf("%q, no address, is not every shard's", s)
		}
	}
}

func TestAShardIsIOfAPowerOfTwo(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"1/1", "1/2", "2/2", "4/4", "64/64"} {
		sh, err := ParseShard(s)
		if err != nil || sh.String() != s {
			t.Errorf("%q: %v, %v", s, sh, err)
		}
	}
	if sh, err := ParseShard(""); err != nil || sh.N > 1 || !sh.owns("d_x") {
		t.Errorf(`"": %v, %v: want every address`, sh, err)
	}
	for _, s := range []string{"1", "/2", "0/2", "3/2", "-1/2", "1/3", "1/0", "0/0", "1/128", "a/b", "1/2/4", " 1/2"} {
		if _, err := ParseShard(s); err == nil {
			t.Errorf("%q is taken as a shard", s)
		}
	}
}

// sharded is n processes, procs[i] shard i+1 of n, behind a reverse proxy that
// sends each mailbox's calls to its own (proxyShard), as the one in front
// does. On PostgreSQL each process is a store of its own, following the
// feed; in memory they share one store, which is the tables.
type sharded struct {
	t     *testing.T
	clock *clock
	mu    sync.Mutex
	procs []*env
	front *env // the clients' view: its srv is the reverse proxy
}

// fedOn waits until process i holds mailbox a's standing as a's own
// process holds it: the feed has brought a's latest record. Process i must
// hold something of a, loaded or in its record cache, as a sender's
// recipient's process does: one that holds nothing reads a afresh, and the
// wait would show nothing of the feed.
func (s *sharded) fedOn(i int, a protocol.Address) {
	s.t.Helper()
	own := s.procs[proxyShard("/v1/"+a.String(), len(s.procs))].store
	want, ok := own.Held(a)
	if !ok {
		s.t.Fatalf("%s's own process does not hold it", a)
	}
	held := func() (Standing, bool) {
		st := s.procs[i].store
		if h, ok := st.Held(a); ok {
			return h, true
		}
		if b, _ := st.Known(a); b != nil {
			if h, ok, err := b.standing(); err == nil && ok {
				return h, true
			}
		}
		return Standing{}, false
	}
	if _, ok := held(); !ok {
		s.t.Fatalf("process %d holds nothing of %s: the wait would show nothing of the feed", i, a)
	}
	for range 500 {
		if h, ok := held(); ok && h.Signer == want.Signer {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.t.Fatalf("after five seconds process %d holds %s's standing from before its renewal", i, a)
}

func newSharded(t *testing.T, n int) *sharded {
	t.Helper()
	s := &sharded{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}, procs: make([]*env, n)}
	var shared Store
	if !onPostgres() {
		shared = NewMemStore(s.clock.Now)
	}
	for i := range n {
		s.procs[i] = s.start(i, shared)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		p := s.procs[proxyShard(r.URL.Path, n)]
		s.mu.Unlock()
		to, _ := url.Parse(p.srv.URL)
		httputil.NewSingleHostReverseProxy(to).ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	s.front = &env{t: t, clock: s.clock, store: s.procs[0].store, server: s.procs[0].server, srv: proxy}
	return s
}

// start starts procs[i], shard i+1, on shared, or on a store of its own
// when shared is nil.
func (s *sharded) start(i int, shared Store) *env {
	s.t.Helper()
	p := &env{t: s.t, clock: s.clock, store: shared}
	var ready func() bool
	if shared == nil {
		m := startPostgres(s.t, s.clock.Now)
		p.store, ready = m, m.Ready
	}
	p.server = New(Config{Store: p.store, Limits: relaxed(), Now: s.clock.Now, Ready: ready,
		Shard: Shard{I: i + 1, N: len(s.procs)}, Metrics: NewMetrics(prometheus.NewRegistry())})
	p.srv = httptest.NewServer(apitest.Handler(s.t, p.server.Handler()))
	s.t.Cleanup(p.srv.Close)
	return p
}

// restart replaces the process of shard i with a new one: empty memory, on
// the tables.
func (s *sharded) restart(i int) {
	s.t.Helper()
	var shared Store
	if !onPostgres() {
		shared = s.procs[i].store
	}
	p := s.start(i, shared)
	s.mu.Lock()
	old := s.procs[i]
	s.procs[i] = p
	s.mu.Unlock()
	old.srv.Close()
}

// in makes mailboxes until it has one in shard i, made by mk, and returns it.
func (s *sharded) in(i int, mk func() *client.Mailbox) *client.Mailbox {
	s.t.Helper()
	for range 64 {
		if b := mk(); proxyShard("/v1/"+b.Address().String(), len(s.procs)) == i {
			return b
		}
	}
	s.t.Fatalf("no mailbox in shard %d of %d in 64", i, len(s.procs))
	return nil
}

// Two processes, half the addresses each, behind a reverse proxy that routes
// by address: mail goes both ways, a renewal on one half is taken at once by
// a send to the other, a call sent to the wrong process is refused there, and
// a restarted process reads what the other half changed while it was gone.
func TestTwoShardsBehindAProxy(t *testing.T) {
	t.Parallel()
	s := newSharded(t, 2)
	e := s.front
	a := s.in(0, e.mailbox)
	b := s.in(1, e.certifiedMailbox) // renews under a new certificate
	ctx := context.Background()

	exchange := func(what string) {
		t.Helper()
		send(t, a, b, what+": to b")
		send(t, b, a, what+": to a")
		for _, x := range []*client.Mailbox{a, b} {
			if res := receive(t, x); len(res.Delivered) != 1 {
				t.Fatalf("%s: %s took %d messages: %+v", what, x.Address(), len(res.Delivered), res)
			}
		}
	}
	exchange("across the halves")

	// b renews on its own process, then sends under the new certificate to
	// a, whose process held b's record from before and takes the renewal
	// from the feed: a's process reads b's standing from memory, so the
	// send waits until the feed has brought it (ARCHITECTURE.md § Routing
	// by address).
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	s.fedOn(0, b.Address())
	exchange("after b's renewal")

	// A call for a's mailbox sent to b's process is refused there, and
	// counted: the proxy, not the mailbox, is wrong.
	wrong := &env{t: t, clock: s.clock, srv: s.procs[1].srv}
	r := wrong.do(http.MethodGet, "/v1/"+a.Address().String()+"/messages", nil, wrong.passFor(signer(t, a), a.Address(), e.name()))
	wrong.want(r, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if r.header.Get("Retry-After") == "" {
		t.Error("a misrouted call's 503 has no Retry-After")
	}
	if n := testutil.ToFloat64(s.procs[1].server.metrics.misroutes); n != 1 {
		t.Errorf("misrouted_total %v: want 1", n)
	}
	if n := testutil.ToFloat64(s.procs[0].server.metrics.misroutes); n != 0 {
		t.Errorf("misrouted_total %v on the process that owns the mailbox: want 0", n)
	}

	// a's process restarts while b renews again: b's next send is checked
	// on the new process against b's record as it is now.
	s.restart(0)
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	exchange("after a's process restarted")
}
