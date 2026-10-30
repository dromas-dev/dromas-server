package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A fetch or an ack of a held message whose precondition is false is a call
// like any other, and spends one of the mailbox's calls (LIMITS.md rule 1;
// dromas-dev/dromas-server#102, the client repo's #412 item 1): with
// them spent, the next is refused, so a mailbox cannot ask without end whether
// its message is still held.
func TestAFalsePreconditionOnAHeldMessageSpendsOneOfTheMailboxsCalls(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		method, field, value string
		status               int
	}{
		{http.MethodGet, "If-None-Match", "*", http.StatusNotModified},
		{http.MethodGet, "If-Match", `"x"`, http.StatusPreconditionFailed},
		{http.MethodDelete, "If-Match", `"x"`, http.StatusPreconditionFailed},
		{http.MethodDelete, "If-None-Match", "*", http.StatusPreconditionFailed},
	} {
		t.Run(c.method+" "+c.field+" "+c.value, func(t *testing.T) {
			l := relaxed()
			l.CallBurst, l.CallRefill = 1, time.Hour
			e := newEnv(t, l)
			to, msg := holding(e)
			pass := to.pass(1)
			if got := e.doWith(c.method, msg, nil, pass, c.field, c.value); got.status != c.status {
				t.Fatalf("the first, with %s: %s: %d %s, want %d", c.field, c.value, got.status, got.body, c.status)
			}
			e.limited(e.doWith(c.method, msg, nil, pass, c.field, c.value), protocol.QuotaCalls)
		})
	}
}

// A page after the first whose precondition is false takes no cursor and
// puts none (the client repo's #412 item 2): the mailbox still holds the cursor
// it was handed, and the page it names, asked for next, is a continuation.
func TestAListWhosePreconditionIsFalseTakesNoCursor(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, field, value string }{
		{"If-None-Match: *", "If-None-Match", "*"},
		{`If-Match: "x"`, "If-Match", `"x"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := relaxed()
			l.PollBurst, l.PollRefill = 2, time.Hour
			e := newEnv(t, l)
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			for range pageSize + 1 {
				e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
			}
			pass := to.pass(1)
			first := e.do("GET", to.path("/messages"), nil, pass)
			e.want(first, http.StatusOK, "")
			var page protocol.MessageList
			if err := json.Unmarshal(first.body, &page); err != nil || page.NextCursor == nil {
				t.Fatalf("the first page: %v %s", err, first.body)
			}
			next := to.path("/messages?cursor=" + *page.NextCursor)
			handed := e.server.drains.held(to.id.Address())
			if r := e.doWith("GET", next, nil, pass, c.field, c.value); r.status != http.StatusNotModified && r.status != http.StatusPreconditionFailed {
				t.Fatalf("the page after the first, with %s: %d %s", c.name, r.status, r.body)
			}
			if got := e.server.drains.held(to.id.Address()); got != handed {
				t.Errorf("after a page with %s, the mailbox holds the cursor %q, not the one it was handed, %q", c.name, got, handed)
			}
			if r := e.do("GET", next, nil, pass); r.status != http.StatusOK {
				q, _ := r.quota()
				t.Errorf("the page the mailbox was handed, after one with %s: %d %s %s, want 200", c.name, r.status, r.code(), q)
			}
		})
	}
}

// held is the cursor mailbox a was handed last, "" for none.
func (d *drains) held(a protocol.Address) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.next[a]
}

// revokeRace runs then just before the first Revoke through serial through
// reaches the store beneath.
type revokeRace struct {
	Store
	through uint64
	then    func()
	ran     atomic.Bool
}

func (s *revokeRace) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) error {
	if rv.Through == s.through && s.ran.CompareAndSwap(false, true) {
		s.then()
	}
	return s.Store.Revoke(ctx, a, rv, want)
}

// A revocation's If-None-Match: *, evaluated while none is held, is held to
// what its write replaces (the client repo's #412 item 3): a revocation
// written by another request between the evaluation and the write fails it,
// 409 mailbox_changed, and what that other request wrote stands.
func TestARevocationsIfNoneMatchIsHeldToWhatItsWriteReplaces(t *testing.T) {
	t.Parallel()
	race := &revokeRace{through: 2}
	e := newEnv(t, relaxed(), func(c *Config) { race.Store = c.Store; c.Store = race })
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	race.then = func() { e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "") }
	got := e.doWith("PUT", r.path("/revocations"), r.certs(2), "", "If-None-Match", "*")
	var held protocol.Revocations
	_ = json.Unmarshal(e.do("GET", r.path("/revocations"), nil, "").body, &held)
	through := uint64(0)
	if f, err := protocol.ParseRevokedCertificates(held.RevokedCertificates); err == nil {
		through = f.Through
	}
	if got.status != http.StatusConflict || got.code() != protocol.CodeMailboxChanged || through != 1 {
		t.Errorf("PUT …/revocations through 2 with If-None-Match: *, a revocation through 1 written after its evaluation: %d %s, held through %d; want 409 mailbox_changed, held through 1", got.status, got.code(), through)
	}
}

// head is a HEAD of path through e's server, as net/http answers it, with
// header fields as name and value pairs: its content is none.
func (e *env) head(path, pass string, hdr ...string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodHead, e.srv.URL+path, nil)
	if pass != "" {
		req.Header.Set("Authorization", pass)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Add(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(b) > 0 {
		e.t.Errorf("HEAD %s: %d bytes of content", path, len(b))
	}
	return resp
}

// A HEAD of every GET route is that GET without content (RFC 9110 §9.3.2;
// the client repo's #412 item 4): the same status and header fields, but a
// message's Content-Length, which its HEAD leaves out (§8.6), and an answer
// of the description's, which api/apitest, which every test server is
// wrapped in, holds it to. The routes are read from routes().
func TestAHeadIsItsGetWithoutContent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	to, msg := holding(e)
	revoking := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", revoking.path("/revocations"), revoking.certs(1), ""), http.StatusOK, "")
	pass := to.pass(1)
	paths := map[string]string{
		"GET /v1/{$}":                  protocol.DocumentPath,
		"GET /v1/{addr}":               to.path(""),
		"GET /v1/{addr}/revocations":   revoking.path("/revocations"),
		"GET /v1/{addr}/acl":           to.path("/acl"),
		"GET /v1/{addr}/messages":      to.path("/messages"),
		"GET /v1/{addr}/messages/{id}": msg,
		linkRoute:                      protocol.LinkPath + to.id.Address().String(),
	}
	patterns := []string{linkRoute}
	for _, r := range e.server.routes() {
		patterns = append(patterns, r.pattern)
	}
	for _, p := range patterns {
		if !strings.HasPrefix(p, http.MethodGet+" ") {
			continue
		}
		path, ok := paths[p]
		if !ok {
			t.Errorf("%s: no case here", p)
			continue
		}
		h := e.head(path, pass, "Accept-Encoding", "gzip")
		get := e.doWith(http.MethodGet, path, nil, pass, "Accept-Encoding", "gzip")
		if h.StatusCode != http.StatusOK || get.status != http.StatusOK {
			t.Errorf("%s: HEAD %d, GET %d", p, h.StatusCode, get.status)
		}
		message := p == "GET /v1/{addr}/messages/{id}"
		if message && h.Header.Get("Content-Length") != "" {
			t.Errorf("HEAD %s: Content-Length %s", p, h.Header.Get("Content-Length"))
		}
		for name := range get.header {
			if name == "Content-Length" && message {
				continue
			}
			if h.Header.Get(name) != get.header.Get(name) {
				t.Errorf("HEAD %s: %s %q, the GET's %q", p, name, h.Header.Get(name), get.header.Get(name))
			}
		}
		for name := range h.Header {
			if _, ok := get.header[name]; !ok {
				t.Errorf("HEAD %s: %s, which the GET does not carry", p, name)
			}
		}
	}
}

// A message's HEAD takes no token of new messages and marks nothing (the client
// repo's #412 item 4): after three, with a budget of two tokens, the mailbox's
// first fetch is its first, and only the one after it is a repeat, within
// an allowance of one.
func TestAMessagesHeadTakesNoTokenAndMarksNothing(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.DrainBurst, l.DrainRefill = 2, time.Hour
	l.PollBurst, l.PollRefill = 1, time.Hour // the repeat allowance: one
	e := newEnv(t, l)
	to, msg := holding(e)
	pass := to.pass(1)
	for i := range 3 {
		if h := e.head(msg, pass); h.StatusCode != http.StatusOK {
			t.Fatalf("HEAD %d: %d", i+1, h.StatusCode)
		}
	}
	e.want(e.do(http.MethodGet, msg, nil, pass), http.StatusOK, "")
	e.want(e.do(http.MethodGet, msg, nil, pass), http.StatusOK, "")
	e.want(e.do(http.MethodGet, msg, nil, pass), http.StatusTooManyRequests, protocol.CodeRefetchSpent)
}

// A send's retry, the same bytes the mailbox holds, whose precondition is false
// is 412, not its first receipt (PROTOCOL.md §11.4; the client repo's #412
// item 5): the send evaluates them before its dedupe, and takes no MAY of
// RFC 9110 §13.1.1.
func TestASendsRetryWithAFalsePreconditionIs412(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	post := sealedTo(1, 1, ciphertextTo(t, to))
	e.want(e.do("POST", to.path("/messages"), post, from.pass(1)), http.StatusCreated, "")
	for _, h := range [][2]string{{"If-Match", `"x"`}, {"If-None-Match", "*"}} {
		if got := e.doWith("POST", to.path("/messages"), post, from.pass(1), h[0], h[1]); got.status != http.StatusPreconditionFailed {
			t.Errorf("the same bytes again, with %s: %s: %d %s, want 412", h[0], h[1], got.status, got.body)
		}
	}
}

// A fetch whose precondition is false leaves the message unfetched (the
// client repo's #412 item 6): the mailbox's next fetch of it is its first, and
// only the one after that spends the repeat allowance, here one.
func TestAFetchWithAFalsePreconditionLeavesTheMessageUnfetched(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill = 1, time.Hour // the repeat allowance: one
	e := newEnv(t, l)
	to, msg := holding(e)
	pass := to.pass(1)
	for _, h := range [][2]string{{"If-None-Match", "*"}, {"If-Match", `"x"`}} {
		if got := e.doWith("GET", msg, nil, pass, h[0], h[1]); got.status != http.StatusNotModified && got.status != http.StatusPreconditionFailed {
			t.Fatalf("a fetch with %s: %s: %d", h[0], h[1], got.status)
		}
	}
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		if got := e.do("GET", msg, nil, pass); got.status != want {
			t.Errorf("fetch %d after the two with a false precondition: %d %s, want %d (the first, one repeat, then refetch_spent)", i+1, got.status, got.code(), want)
		}
	}
}

// A revocation's write holds what its request's preconditions held
// (Expect): one that asks for revocations held where none are, or for none
// where some are, is refused ErrStale and writes nothing, on the store the
// tests run on, DynamoDB's where it is set.
func TestARevocationsWriteHoldsWhatItsPreconditionsHeld(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := t.Context()
	r := e.raw()
	a := r.id.Address()
	through := func(n uint64) *Revocations {
		c := r.certs(n)
		return &Revocations{Identity: c.Identity, Certs: c.RevokedCertificates, CertsSig: c.RevokedCertificatesSignature, Through: n}
	}
	for i, c := range []struct {
		rv   *Revocations
		want Expect
		err  error
	}{
		{through(1), ExpectHeld, ErrStale}, // none held
		{through(1), ExpectNone, nil},
		{through(2), ExpectNone, ErrStale}, // one held
		{through(2), ExpectHeld, nil},
		{through(3), ExpectAnything, nil},
	} {
		if err := e.store.Revoke(ctx, a, c.rv, c.want); !errors.Is(err, c.err) || (err == nil) != (c.err == nil) {
			t.Errorf("write %d, through %d: %v, want %v", i+1, c.rv.Through, err, c.err)
		}
	}
	b, err := e.store.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := protocol.ParseRevokedCertificates(b.RevokedCerts); err != nil || held.Through != 3 {
		t.Errorf("held through %v: %v, want 3", held, err)
	}
}

// debts is how many tokens each of s's limits has taken and not had back,
// at now, by the limit's name: a full bucket owes none.
func debts(s *Server, now time.Time) map[string]int {
	d := map[string]int{}
	for name, sets := range s.limitsByName() {
		for _, bs := range sets {
			bs.mu.Lock()
			for _, full := range bs.full {
				if bs.every > 0 && full.After(now) {
					d[name] += int((full.Sub(now) + bs.every - 1) / bs.every)
				}
			}
			bs.mu.Unlock()
		}
	}
	return d
}

// cursors is the cursor each mailbox was handed last.
func (d *drains) cursors() map[protocol.Address]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.next)
}

// served is how many times this process has served each live message memory
// holds, by its mailbox and tag: the mark a fetch makes.
func (x *index) served() map[string]uint8 {
	m := map[string]uint8{}
	for i := range x.shards {
		sh := &x.shards[i]
		sh.mu.Lock()
		for a, b := range sh.mailboxes {
			for _, k := range b.marks {
				m[fmt.Sprintf("%x/%x", a, k.tag)] = k.n
			}
		}
		sh.mu.Unlock()
	}
	return m
}

// warmed is pass checked by e's server, by a read of r's ACL, which makes a
// call with it its mailbox's at the gate (boxsCall), and the ACL's tag.
func warmed(e *env, r *raw, pass string) string {
	e.t.Helper()
	got := e.do(http.MethodGet, r.path("/acl"), nil, pass)
	e.want(got, http.StatusOK, "")
	return got.header.Get("ETag")
}

// reach is a state of a route that reaches its preconditions: the call that
// does, made once setup has made the state, whether its target exists and
// its tag, and what the call spends before it reads its target, beside the
// address's flood budget a call with no pass of its mailbox's spends at the gate.
type reach struct {
	name   string
	exists bool
	spends map[string]int
	setup  func(e *env) (q call, tag string)
}

// A false precondition is a call like any other, and does nothing else (the
// client repo's #412 items 1, 2, 5 and 6; dromas-dev/dromas-server#102):
// on every route of routes(), the link page and, on each that answers GET,
// HEAD, in each state that reaches its preconditions, a false If-Match, and
// an If-None-Match that matches, are answered 412, or 304 to a GET or a
// HEAD; and the call spends the call's own budget and nothing else (every
// limit of the server, read from limitsByName), takes and puts no cursor,
// marks no message fetched and makes no write of the store. A state refused
// before its preconditions, a revocation of certificates through a serial
// lower than the one held, is answered so whatever they are (PROTOCOL.md
// §11.4 rule 3; dromas-dev/dromas-client#448 item 2), and spends and changes
// the same nothing. The routes are read from the code: one without its
// states here fails.
func TestAFalsePreconditionIsACallThatDoesNothingElse(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1000, time.Hour
	l.CallBurst, l.CallRefill = 1000, time.Hour
	l.PollBurst, l.PollRefill = 1000, time.Hour
	l.DrainBurst, l.DrainRefill = 1000, time.Hour
	l.ReceiveBurst, l.ReceiveRefill = 1000, time.Hour
	l.SendsPerDay, l.SendsPerMinutePerIP, l.MissesPerMinute = 1000, 1000, 1000
	l.RegistrationsPerHour, l.RangeRegistrationsPerHour = 1000, 1000
	l.RenewalsPerDay, l.CertificatesPerDay, l.CertificateRevocationsPerDay = 1000, 1000, 1000
	calls := map[string]int{string(protocol.QuotaCalls): 1}
	none := map[string]int{}
	live := func(e *env) *raw { return e.raw().register(protocol.MaxPrekeyLifetime) }
	states := map[string][]reach{
		// The server's document answers the same to every caller, and the
		// client repo's api/openapi.yaml gives it no 304 and no 412.
		"GET /v1/{$}": nil,
		"GET /v1/{addr}": {{"a live mailbox", true, none, func(e *env) (call, string) {
			return call{"GET", live(e).path(""), nil, ""}, ""
		}}},
		"PUT /v1/{addr}": {
			{"a mailbox not registered", false, map[string]int{string(protocol.QuotaRegistrations): 1}, func(e *env) (call, string) {
				r := e.raw()
				r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
				return call{"PUT", r.path(""), r.registration(1), r.pass(1)}, ""
			}},
			{"an identical retry", true, calls, func(e *env) (call, string) {
				r := live(e)
				return call{"PUT", r.path(""), r.registration(1), r.pass(1)}, ""
			}},
		},
		"PUT /v1/{addr}/prekey": {
			{"an identical retry", true, calls, func(e *env) (call, string) {
				r := live(e)
				return call{"PUT", r.path("/prekey"), r.upload(1), r.pass(1)}, ""
			}},
			{"a renewal", true, calls, func(e *env) (call, string) {
				r := live(e)
				r.prekey(2, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
				return call{"PUT", r.path("/prekey"), r.upload(2), r.pass(2)}, ""
			}},
			{"a renewal that replaces a revoked certificate", true, none, func(e *env) (call, string) {
				r := live(e)
				e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
				r.prekey(2, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
				return call{"PUT", r.path("/prekey"), r.upload(2), r.pass(2)}, ""
			}},
		},
		"PUT /v1/{addr}/revocations": {
			{"through the serial held again", true, none, func(e *env) (call, string) {
				r := live(e)
				e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
				return call{"PUT", r.path("/revocations"), r.certs(1), ""}, ""
			}},
			{"a raise", true, none, func(e *env) (call, string) {
				r := live(e)
				e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
				return call{"PUT", r.path("/revocations"), r.certs(2), ""}, ""
			}},
			{"through a lower serial", true, none, func(e *env) (call, string) {
				r := live(e)
				e.want(e.do("PUT", r.path("/revocations"), r.certs(2), ""), http.StatusOK, "")
				return call{"PUT", r.path("/revocations"), r.certs(1), ""}, ""
			}},
			{"the address's, with its certificates revoked", true, none, func(e *env) (call, string) {
				r := live(e)
				e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
				rev, err := protocol.SignRevocation(r.signer, r.id.Address())
				if err != nil {
					e.t.Fatal(err)
				}
				return call{"PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""}, ""
			}},
			{"of a mailbox with none held", false, none, func(e *env) (call, string) {
				r := live(e)
				return call{"PUT", r.path("/revocations"), r.certs(1), ""}, ""
			}},
			{"of an address the server holds nothing of", false, map[string]int{string(protocol.QuotaMisses): 1}, func(e *env) (call, string) {
				r := e.raw()
				return call{"PUT", r.path("/revocations"), r.certs(1), ""}, ""
			}},
		},
		"GET /v1/{addr}/revocations": {{"revocations held", true, none, func(e *env) (call, string) {
			r := live(e)
			e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
			return call{"GET", r.path("/revocations"), nil, ""}, ""
		}}},
		"PUT /v1/{addr}/acl": {{"a live mailbox", true, calls, func(e *env) (call, string) {
			r := live(e)
			return call{"PUT", r.path("/acl"), aclOf([]string{}, []string{"*"}), r.pass(1)}, warmed(e, r, r.pass(1))
		}}},
		"GET /v1/{addr}/acl": {{"a live mailbox", true, calls, func(e *env) (call, string) {
			r := live(e)
			return call{"GET", r.path("/acl"), nil, r.pass(1)}, warmed(e, r, r.pass(1))
		}}},
		"PUT /v1/{addr}/account": {
			{"a mailbox in an account", true, calls, func(e *env) (call, string) {
				r := live(e)
				key := inAccount(e, r, 1)
				warmed(e, r, r.pass(1))
				return call{"PUT", r.path("/account"), protocol.AdoptRequest{Key: key}, r.pass(1)}, ""
			}},
			{"a mailbox in none", false, calls, func(e *env) (call, string) {
				r := live(e)
				_, key := accountEnv(e.t, e, false, 1)
				warmed(e, r, r.pass(1))
				return call{"PUT", r.path("/account"), protocol.AdoptRequest{Key: key}, r.pass(1)}, ""
			}},
		},
		"DELETE /v1/{addr}/account": {
			{"a mailbox in an account", true, calls, func(e *env) (call, string) {
				r := live(e)
				inAccount(e, r, 0)
				warmed(e, r, r.pass(1))
				return call{"DELETE", r.path("/account"), nil, r.pass(1)}, ""
			}},
			{"a mailbox in none", false, calls, func(e *env) (call, string) {
				r := live(e)
				warmed(e, r, r.pass(1))
				return call{"DELETE", r.path("/account"), nil, r.pass(1)}, ""
			}},
		},
		"POST /v1/{addr}/messages": {
			{"a first post", true, map[string]int{string(protocol.QuotaCalls): 1, string(protocol.QuotaSendsBeforePass): 1}, func(e *env) (call, string) {
				from, to := live(e), live(e)
				warmed(e, from, from.pass(1))
				return call{"POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(e.t, to)), from.pass(1)}, ""
			}},
			{"a post of bytes the mailbox holds", true, map[string]int{string(protocol.QuotaCalls): 1, string(protocol.QuotaSendsBeforePass): 1}, func(e *env) (call, string) {
				from, to := live(e), live(e)
				post := sealedTo(1, 1, ciphertextTo(e.t, to))
				e.want(e.do("POST", to.path("/messages"), post, from.pass(1)), http.StatusCreated, "")
				warmed(e, from, from.pass(1))
				return call{"POST", to.path("/messages"), post, from.pass(1)}, ""
			}},
		},
		"GET /v1/{addr}/messages": {
			{"a first page of a mailbox with none", true, map[string]int{string(protocol.QuotaPolls): 1}, func(e *env) (call, string) {
				r := live(e)
				warmed(e, r, r.pass(1))
				return call{"GET", r.path("/messages"), nil, r.pass(1)}, e.do("GET", r.path("/messages"), nil, r.pass(1)).header.Get("ETag")
			}},
			{"a first page with messages", true, map[string]int{string(protocol.QuotaPolls): 1}, func(e *env) (call, string) {
				r, _ := holding(e)
				warmed(e, r, r.pass(1))
				return call{"GET", r.path("/messages"), nil, r.pass(1)}, e.do("GET", r.path("/messages"), nil, r.pass(1)).header.Get("ETag")
			}},
			{"a page after the first, at the cursor the mailbox was handed", true, map[string]int{string(protocol.QuotaPolls): 1}, func(e *env) (call, string) {
				from, to := live(e), live(e)
				for range pageSize + 1 {
					e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(e.t, to)), from.pass(1)), http.StatusCreated, "")
				}
				warmed(e, to, to.pass(1))
				var page protocol.MessageList
				if err := json.Unmarshal(e.do("GET", to.path("/messages"), nil, to.pass(1)).body, &page); err != nil || page.NextCursor == nil {
					e.t.Fatalf("the first page: %v", err)
				}
				return call{"GET", to.path("/messages?cursor=" + *page.NextCursor), nil, to.pass(1)}, ""
			}},
			{"a page after the first, at a cursor the mailbox was not handed", true, map[string]int{string(protocol.QuotaPolls): 1}, func(e *env) (call, string) {
				to, _ := holding(e)
				warmed(e, to, to.pass(1))
				return call{"GET", to.path("/messages?cursor=" + formatCursor(Header{ReceivedAt: e.clock.Now()})), nil, to.pass(1)}, ""
			}},
		},
		"GET /v1/{addr}/messages/{id}": {
			{"a message never fetched", true, calls, func(e *env) (call, string) {
				to, msg := holding(e)
				warmed(e, to, to.pass(1))
				return call{"GET", msg, nil, to.pass(1)}, ""
			}},
			{"a message fetched before", true, calls, func(e *env) (call, string) {
				to, msg := holding(e)
				e.want(e.do("GET", msg, nil, to.pass(1)), http.StatusOK, "")
				return call{"GET", msg, nil, to.pass(1)}, ""
			}},
		},
		"DELETE /v1/{addr}/messages/{id}": {{"a message held", true, calls, func(e *env) (call, string) {
			to, msg := holding(e)
			warmed(e, to, to.pass(1))
			return call{"DELETE", msg, nil, to.pass(1)}, ""
		}}},
		linkRoute: {{"any address", true, none, func(*env) (call, string) {
			return call{"GET", protocol.LinkPath + strings.Repeat("ab", 38) + "a", nil, ""}, ""
		}}},
	}
	// refusedFirst is the refusal of each state refused before its
	// preconditions, by its route's pattern and its name.
	refusedFirst := map[string]protocol.Code{"PUT /v1/{addr}/revocations through a lower serial": protocol.CodeConflict}
	type route struct {
		pattern string // the pattern its states are kept under
		method  string
		gate    bool // the call spends its address's flood budget at the gate
	}
	routes := []route{{linkRoute, http.MethodHead, true}, {linkRoute, http.MethodGet, true}}
	for _, r := range (&Server{}).routes() {
		method, _, _ := strings.Cut(r.pattern, " ")
		routes = append(routes, route{r.pattern, method, r.pass == passNone})
		if method == http.MethodGet { // a pattern of GET matches HEAD too (http.ServeMux)
			routes = append(routes, route{r.pattern, http.MethodHead, r.pass == passNone})
		}
	}
	for _, rt := range routes {
		reaches, ok := states[rt.pattern]
		if !ok {
			t.Errorf("%s: no state of it here", rt.pattern)
			continue
		}
		for _, st := range reaches {
			_, path, _ := strings.Cut(rt.pattern, " ")
			t.Run(rt.method+" "+path+"/"+st.name, func(t *testing.T) {
				// Which conditions are false in this state: its target exists
				// or not, and has a tag or none, as its setup makes it. One
				// that holds here, or a tag it has none of, is no case of it.
				_, tagged := st.setup(newEnv(t, l))
				for _, f := range []struct{ name, field, value string }{
					{`If-Match: "x"`, "If-Match", `"x"`},
					{"If-Match: *", "If-Match", "*"},
					{"If-None-Match: *", "If-None-Match", "*"},
					{"If-None-Match: its tag", "If-None-Match", ""},
				} {
					if f.name == "If-Match: *" && st.exists || f.name == "If-None-Match: *" && !st.exists || f.name == "If-None-Match: its tag" && tagged == "" {
						continue
					}
					t.Run(f.name, func(t *testing.T) {
						var inj *faults
						e := newEnv(t, l, func(c *Config) { inj = injectFaults(c.Store.(*Memory)) })
						q, tag := st.setup(e)
						value := f.value
						if f.name == "If-None-Match: its tag" {
							value = tag
						}
						want := http.StatusPreconditionFailed
						if f.field == "If-None-Match" && (rt.method == http.MethodGet || rt.method == http.MethodHead) {
							want = http.StatusNotModified
						}
						refused := refusedFirst[rt.pattern+" "+st.name]
						if refused != "" {
							want = refused.Status()
						}
						spends := maps.Clone(st.spends)
						if rt.gate {
							spends[string(protocol.QuotaRequests)]++
						}
						mem := e.store.(*Memory)
						before, cursors, marks, wrote := debts(e.server, e.clock.Now()), e.server.drains.cursors(), mem.idx.served(), inj.wrote.Load()
						var status int
						if rt.method == http.MethodHead {
							status = e.head(q.path, q.pass, f.field, value).StatusCode
						} else {
							got := e.doWith(q.method, q.path, q.body, q.pass, f.field, value)
							status = got.status
							switch {
							case refused != "" && got.code() != refused:
								t.Errorf("refused before its preconditions with %s, want %s: %s", got.code(), refused, got.body)
							case want == http.StatusPreconditionFailed && got.code() != protocol.CodePreconditionFailed:
								t.Errorf("a 412 that is not precondition_failed: %s", got.body)
							case want == http.StatusNotModified && len(got.body) != 0:
								t.Errorf("a 304 with %d bytes", len(got.body))
							}
						}
						if status != want {
							t.Fatalf("%d, want %d", status, want)
						}
						after := debts(e.server, e.clock.Now())
						for name := range after {
							if _, ok := before[name]; !ok {
								before[name] = 0
							}
						}
						for name, n := range before {
							if got := after[name] - n; got != spends[name] {
								t.Errorf("%s: %d spent, want %d", name, got, spends[name])
							}
						}
						if got := e.server.drains.cursors(); !maps.Equal(got, cursors) {
							t.Errorf("the cursors handed out went from %v to %v", cursors, got)
						}
						if got := mem.idx.served(); !maps.Equal(got, marks) {
							t.Errorf("the messages' marks went from %v to %v", marks, got)
						}
						if got := inj.wrote.Load(); got != wrote {
							t.Errorf("%d writes of the store", got-wrote)
						}
					})
				}
			})
		}
	}
}

// drained is a mailbox holding n messages, more than a page, its first page,
// and the cursor that page handed it, as the server holds it.
func drained(e *env, n int) (*raw, protocol.MessageList, string) {
	e.t.Helper()
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	for range n {
		e.want(e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(e.t, to)), from.pass(1)), http.StatusCreated, "")
	}
	var page protocol.MessageList
	if err := json.Unmarshal(e.do("GET", to.path("/messages"), nil, to.pass(1)).body, &page); err != nil || page.NextCursor == nil {
		e.t.Fatalf("the first page: %v", err)
	}
	if got := e.server.drains.held(to.id.Address()); got != *page.NextCursor {
		e.t.Fatalf("the mailbox holds the cursor %q, its first page handed it %q", got, *page.NextCursor)
	}
	return to, page, *page.NextCursor
}

// A list's HEAD is a poll whatever its cursor, and moves none (PROTOCOL.md
// §11.11, §11.2; the client repo's #412 item 4): one of a first page whose next
// cursor is not the one the mailbox was handed hands out none, and one that
// names the cursor the mailbox was handed is 200, takes from the poll rate, and
// leaves the mailbox holding that cursor, whose GET then continues the drain.
func TestAListsHeadMovesNoCursor(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill = 100, time.Hour
	e := newEnv(t, l)
	to, first, cursor := drained(e, pageSize+2)
	e.want(e.do("DELETE", to.path("/messages/"+first.Messages[0].ID), nil, to.pass(1)), http.StatusNoContent, "")
	// The first page now runs one message later: a GET's would hand out
	// another cursor.
	if h := e.head(to.path("/messages"), to.pass(1)); h.StatusCode != http.StatusOK {
		t.Fatalf("HEAD of the first page: %d", h.StatusCode)
	}
	if got := e.server.drains.held(to.id.Address()); got != cursor {
		t.Errorf("after a HEAD of the first page, the mailbox holds the cursor %q, not the one it was handed, %q", got, cursor)
	}
	next := to.path("/messages?cursor=" + cursor)
	before := debts(e.server, e.clock.Now())
	if h := e.head(next, to.pass(1)); h.StatusCode != http.StatusOK {
		t.Fatalf("HEAD of the page the mailbox was handed: %d", h.StatusCode)
	}
	after := debts(e.server, e.clock.Now())
	if p, pages := after[string(protocol.QuotaPolls)]-before[string(protocol.QuotaPolls)], after[string(protocol.QuotaPages)]-before[string(protocol.QuotaPages)]; p != 1 || pages != 0 {
		t.Errorf("a list's HEAD spent %d polls and %d pages, want a poll", p, pages)
	}
	if got := e.server.drains.held(to.id.Address()); got != cursor {
		t.Errorf("after a HEAD, the mailbox holds the cursor %q, not the one it was handed, %q", got, cursor)
	}
	e.want(e.do("GET", next, nil, to.pass(1)), http.StatusOK, "")
	if got := debts(e.server, e.clock.Now())[string(protocol.QuotaPages)] - after[string(protocol.QuotaPages)]; got != 1 {
		t.Errorf("the GET after it spent %d pages, want 1: no continuation", got)
	}
}

// A page refused for the page allowance leaves the mailbox holding its cursor
// (PROTOCOL.md §11.11: only a GET's 200 spends it; the client repo's #412
// item 2): once a page is due again, the same page continues the drain,
// spending a page and no poll.
func TestARefusedPageLeavesTheMailboxItsCursor(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = pageSize + 1 // two pages to a full mailbox: an allowance of four at once
	l.PollBurst, l.PollRefill = 100, time.Hour
	e := newEnv(t, l)
	to, _, cursor := drained(e, pageSize+1)
	next := to.path("/messages?cursor=" + cursor)
	for range 4 {
		e.want(e.do("GET", next, nil, to.pass(1)), http.StatusOK, "")
		e.want(e.do("GET", to.path("/messages"), nil, to.pass(1)), http.StatusOK, "") // hands out the cursor again
	}
	e.limited(e.do("GET", next, nil, to.pass(1)), protocol.QuotaPages)
	if got := e.server.drains.held(to.id.Address()); got != cursor {
		t.Fatalf("after a refused page, the mailbox holds the cursor %q, not the one it was handed, %q", got, cursor)
	}
	e.clock.Add(l.PollRefill / 2)
	before := debts(e.server, e.clock.Now())
	e.want(e.do("GET", next, nil, to.pass(1)), http.StatusOK, "")
	after := debts(e.server, e.clock.Now())
	if p, pages := after[string(protocol.QuotaPolls)]-before[string(protocol.QuotaPolls)], after[string(protocol.QuotaPages)]-before[string(protocol.QuotaPages)]; p != 0 || pages != 1 {
		t.Errorf("the page after its refusal spent %d polls and %d pages, want a page", p, pages)
	}
}
