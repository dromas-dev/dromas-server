package server

import (
	"cmp"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The operator's interface: commands for whoever runs this server, never
// part of the API. It is served on a Unix socket that only the server's own
// user can open (dromas-server serve --admin-socket), and never on the API's
// listener, so nothing that reaches the API reaches it.

// ClearAddress forgets what the limits keyed by a caller's address hold of
// ip: its misses, its registrations, by its IPv4 address or IPv6 /64 and by
// its IPv6 /48, its sends before their pass and its calls with no checked pass, each
// bucket full again as if the address had never been seen. ip is an IPv4
// address or any IPv6 address of a /64, with or without a zone, which is how
// the limits key a caller (ipKey). It returns that key and the names of the
// limits that held anything of it, and false if ip is no address.
func (s *Server) ClearAddress(ip string) (key string, cleared []string, ok bool) {
	if _, ok := hostAddr(ip); !ok {
		return "", nil, false
	}
	key, now := ipKey(ip), s.now()
	for _, l := range []struct {
		bs  *buckets
		key string
	}{
		{s.misses, key},
		{s.regs, key},
		{s.rangeRegs, rangeKey(ip)},
		{s.sendIPs, key},
		{s.requests, key},
	} {
		if l.key != "" && l.bs.clear(l.key, now) {
			cleared = append(cleared, l.bs.name)
		}
	}
	return key, cleared, true
}

// limitsByName are the server's limits, each by its name: the quota a
// rate_limited names, or the code its refusal has of its own. A limit with a
// refill an account lifts to has the buckets of each (receivesAt).
func (s *Server) limitsByName() map[string][]*buckets {
	m := map[string][]*buckets{}
	for _, bs := range []*buckets{s.polls, s.pages, s.repeats, s.regs, s.rangeRegs, s.sendIPs, s.misses, s.requests, s.calls, s.receives, s.lifted, s.drained, s.sends, s.renewals, s.certs, s.raises} {
		m[bs.name] = append(m[bs.name], bs)
	}
	return m
}

// Indebted is a key a limit holds, and how long until its bucket is full
// again: the deeper in debt, the longer.
type Indebted struct {
	Key    string `json:"key"`
	FullIn int64  `json:"full_in"` // seconds, rounded up
}

// Top returns, for the limit named name, the n keys it holds deepest in debt
// now, deepest first: which mailboxes or addresses spend it most. It reads memory
// and keeps nothing (dromas-dev/dromas-server#59). ok is false for a
// name that is no limit's.
func (s *Server) Top(name string, n int) (top []Indebted, ok bool) {
	sets, ok := s.limitsByName()[name]
	if !ok {
		return nil, false
	}
	type debt struct {
		key string
		in  time.Duration // until the key's bucket is full again
	}
	// A mailbox that has just joined or left an account is in the buckets of
	// each refill: the deeper debt is its.
	deepest := map[string]time.Duration{}
	now := s.now()
	for _, bs := range sets {
		bs.mu.Lock()
		for k, full := range bs.full {
			if in := full.Sub(now); in > deepest[k] {
				deepest[k] = in
			}
		}
		bs.mu.Unlock()
	}
	debts := make([]debt, 0, len(deepest))
	for k, in := range deepest {
		debts = append(debts, debt{k, in})
	}
	// By the exact time, and only what is shown rounded: rounded first, keys
	// within a second of each other would be listed by name
	// (dromas-dev/dromas-server#63).
	slices.SortFunc(debts, func(a, b debt) int { return cmp.Or(cmp.Compare(b.in, a.in), cmp.Compare(a.key, b.key)) })
	if len(debts) > n {
		debts = debts[:n]
	}
	for _, d := range debts {
		top = append(top, Indebted{d.key, int64(retrySeconds(d.in))})
	}
	return top, true
}

// topDefault and topMost bound how many keys limits top lists.
const topDefault, topMost = 20, 1000

// AdminHandler is the operator's interface:
//   - POST /limits/clear?ip=<address> answers {"address":"<the key
//     cleared>","cleared":[<the limits that held anything of it>]}
//     (ClearAddress);
//   - GET /limits/top?limit=<name>&n=<count> answers {"limit":"<name>",
//     "keys":[{"key":"<a mailbox or an address>","full_in":<seconds>}]}, deepest
//     in debt first (Top).
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /limits/clear", func(w http.ResponseWriter, r *http.Request) {
		key, cleared, ok := s.ClearAddress(r.URL.Query().Get("ip"))
		if !ok {
			http.Error(w, "ip: not an IPv4 or IPv6 address", http.StatusBadRequest)
			return
		}
		if cleared == nil {
			cleared = []string{}
		}
		if s.log != nil {
			s.log.Printf("the operator cleared one address's limits: %v", cleared) // never the address: this server logs none
		}
		writeJSON(w, http.StatusOK, struct {
			Address string   `json:"address"`
			Cleared []string `json:"cleared"`
		}{key, cleared})
	})
	mux.HandleFunc("GET /limits/top", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		n := topDefault
		if v := q.Get("n"); v != "" {
			var err error
			if n, err = strconv.Atoi(v); err != nil || n < 1 || n > topMost {
				http.Error(w, "n: a count from 1 to "+strconv.Itoa(topMost), http.StatusBadRequest)
				return
			}
		}
		name := q.Get("limit")
		top, ok := s.Top(name, n)
		if !ok {
			names := slices.Sorted(maps.Keys(s.limitsByName()))
			http.Error(w, "limit: one of "+strings.Join(names, ", "), http.StatusBadRequest)
			return
		}
		if top == nil {
			top = []Indebted{}
		}
		if s.log != nil {
			s.log.Printf("the operator listed the top of the limit %s", name) // never a key: the answer is the operator's alone
		}
		writeJSON(w, http.StatusOK, struct {
			Limit string     `json:"limit"`
			Keys  []Indebted `json:"keys"`
		}{name, top})
	})
	return mux
}
