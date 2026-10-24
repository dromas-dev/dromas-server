package server

// The orders of refusal a client acts on (PROTOCOL.md §13, the order of
// refusals): a call about a box answers its state before its pass (R1,
// below), and what could change nothing is answered from what is kept (R2,
// below). The third, a precondition evaluated once the target's state is
// known, a false one a call that does nothing else, is
// TestAFalsePreconditionIsACallThatDoesNothingElse. Every other order of
// checks is this server's own, and its handlers are the sequence.

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// stateAnswer is what a call about a box in a state is answered: its status,
// its code where its body is a problem, and whether the body carries the
// address's record.
type stateAnswer struct {
	status int
	code   protocol.Code
	record bool
}

// A call made with a box's pass, or about a box, answers that box's state
// before it judges the pass, whatever pass it carries (PROTOCOL.md §13, the
// order of refusals): never registered or forgotten 404 no_such_mailbox, a
// revoked address 410 revoked with its record, a box whose current
// certificate its identity revoked 401 certificate_revoked. So a box learns
// its own state whatever pass it carries. Every route of routes(), and HEAD
// on each that answers GET, in each state, with no pass, one that is no
// pass, a pass of the box that does not verify, another box's checked pass
// and the box's own pass, checked while the box was live, from a process
// whose memory held the box before its state changed and from one that
// reads it. The routes are read from the code: one without its answers here
// fails. Where a route's answer to a state is another, the table says which
// and why: a send answers its sender's state, by the codes of a sender; the
// read of what is revoked answers what it holds; and where a state has no
// answer of its own, the call goes on, as a registration of an address with
// no box and a revocation of one do.
func TestEveryCallAboutABoxAnswersItsStateBeforeItsPass(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	// live is a box in use: the recipient of the sends below, and the box
	// whose checked pass is another box's to every other.
	live := e.raw().register(protocol.MaxPrekeyLifetime)
	livePass := live.pass(1)
	e.want(e.do("GET", live.path("/messages"), nil, livePass), http.StatusOK, "")
	// made is a box registered, its pass checked and the box loaded by a
	// poll, then changed into its state.
	made := func(change func(r *raw)) (*raw, string) {
		r := e.raw().register(protocol.MaxPrekeyLifetime)
		p := r.pass(1)
		e.want(e.do("GET", r.path("/messages"), nil, p), http.StatusOK, "")
		change(r)
		return r, p
	}
	never := e.raw()
	never.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	forgotten, forgottenPass := made(func(r *raw) {
		if err := e.store.DeleteBox(t.Context(), r.id.Address()); err != nil { // as the TTL deletes it
			t.Fatal(err)
		}
	})
	revoked, revokedPass := made(func(r *raw) {
		rev, err := protocol.SignRevocation(r.signer, r.id.Address())
		if err != nil {
			t.Fatal(err)
		}
		e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
	})
	listed, listedPass := made(func(r *raw) {
		e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
	})
	states := []struct {
		name string
		r    *raw
		own  string // the box's own pass: under its certificate, checked while it was live
	}{
		{"never registered", never, never.pass(1)},
		{"forgotten", forgotten, forgottenPass},
		{"revoked", revoked, revokedPass},
		{"its current certificate revoked", listed, listedPass},
	}

	var (
		noBox       = stateAnswer{http.StatusNotFound, protocol.CodeNoSuchMailbox, false}
		gone        = stateAnswer{http.StatusGone, protocol.CodeRevoked, true}
		revokedCert = stateAnswer{http.StatusUnauthorized, protocol.CodeCertificateRevoked, false}
		goesOn      = stateAnswer{} // the state has no answer of its own on this route: the call goes on
		owner       = map[string]stateAnswer{"never registered": noBox, "forgotten": noBox, "revoked": gone, "its current certificate revoked": revokedCert}
	)
	// What each route answers each state, by its pattern, and what it is
	// sent: its body, from the state's box, and the box its path names.
	type route struct {
		answers map[string]stateAnswer
		body    func(r *raw) any
		sender  bool // the state's box is the sender, by its pass, and the path names a live box
	}
	routes := map[string]route{
		"GET /v1/{addr}": {answers: map[string]stateAnswer{"never registered": noBox, "forgotten": noBox, "revoked": gone,
			"its current certificate revoked": {http.StatusOK, "", false}}}, // the read serves a box whose certificate is revoked, with what revoked it
		"PUT /v1/{addr}": {answers: map[string]stateAnswer{
			"never registered": goesOn, "forgotten": goesOn, // a registration of an address with no box makes one, and judges its pass
			"revoked": gone, "its current certificate revoked": revokedCert,
		}, body: func(r *raw) any { return r.registration(1) }}, // the box's own registration, sent again
		"PUT /v1/{addr}/prekey": {answers: owner, body: func(r *raw) any { return r.upload(1) }}, // the box's own statement, sent again
		"PUT /v1/{addr}/revocations": {answers: map[string]stateAnswer{
			"never registered": goesOn, "forgotten": goesOn, "its current certificate revoked": goesOn, // kept, box or none (PROTOCOL.md §3a), or raised
			"revoked": gone,
		}, body: func(r *raw) any { return r.certs(2) }},
		"GET /v1/{addr}/revocations": {answers: map[string]stateAnswer{ // what is held of the address's revocations, box or none
			"never registered": {http.StatusNotFound, protocol.CodeNotRevoked, false}, "forgotten": {http.StatusNotFound, protocol.CodeNotRevoked, false},
			"revoked": {http.StatusOK, "", true}, "its current certificate revoked": {http.StatusOK, "", true},
		}},
		"PUT /v1/{addr}/acl":              {answers: owner},
		"GET /v1/{addr}/acl":              {answers: owner},
		"PUT /v1/{addr}/account":          {answers: owner},
		"DELETE /v1/{addr}/account":       {answers: owner},
		"GET /v1/{addr}/messages":         {answers: owner},
		"GET /v1/{addr}/messages/{id}":    {answers: owner},
		"DELETE /v1/{addr}/messages/{id}": {answers: owner},
		"POST /v1/{addr}/messages": {answers: map[string]stateAnswer{ // the sender's state, by a sender's codes (PROTOCOL.md §13)
			"never registered": {http.StatusForbidden, protocol.CodeUnknownSender, false}, "forgotten": {http.StatusForbidden, protocol.CodeUnknownSender, false},
			"revoked": {http.StatusForbidden, protocol.CodeSenderRevoked, false}, "its current certificate revoked": revokedCert,
		}, sender: true},
	}

	// The process whose memory held each box before its state changed, and a
	// process of its own for each call, over the same backend, whose memory
	// holds nothing: every state is read.
	warm := e.caller()
	backend := e.store.(*Memory).backend
	cold := func(ip, method, path string, body any, pass string) reply {
		m := newMemory(e.clock.Now, 16, nil, nil)
		m.backend = backend
		return e.callerOf(apitest.Handler(t, New(Config{Store: m, Limits: l, Now: e.clock.Now}).Handler()))(ip, method, path, body, pass)
	}
	processes := []struct {
		name string
		call func(ip, method, path string, body any, pass string) reply
	}{{"a process that held the box", warm}, {"a process that reads it", cold}}

	stranger := e.raw()
	for _, rt := range e.server.routes() {
		want, ok := routes[rt.pattern]
		if !ok {
			t.Errorf("%s: no answers of it here", rt.pattern)
			continue
		}
		method, pattern, _ := strings.Cut(rt.pattern, " ")
		methods := []string{method}
		if method == http.MethodGet { // a pattern of GET matches HEAD too (http.ServeMux)
			methods = append(methods, http.MethodHead)
		}
		for _, st := range states {
			w, ok := want.answers[st.name]
			if !ok {
				t.Errorf("%s: no answer to a box %s", rt.pattern, st.name)
				continue
			}
			if w == goesOn {
				continue
			}
			a := st.r.id.Address()
			// A pass of the box that does not verify: one naming it, under a
			// certificate another identity made.
			notIts := e.passFor(stranger.certify(1), a, e.name())
			passes := []struct{ name, auth string }{
				{"a pass of the box that does not verify", notIts},
				{"the box's own pass", st.own},
			}
			if !want.sender { // a send knows whose pass it is only by reading it, and another box's is another sender
				passes = append(passes, []struct{ name, auth string }{
					{"no pass", ""},
					{"no pass at all, a token", "Bearer " + strings.Repeat("a", 50)},
					{"another box's checked pass", livePass},
				}...)
			}
			at := a.String()
			if want.sender {
				at = live.id.Address().String()
			}
			path := strings.NewReplacer("{addr}", at, "{id}", strings.Repeat("0", 64)).Replace(pattern)
			var body any
			if want.body != nil {
				body = want.body(st.r)
			}
			for _, m := range methods {
				for _, pr := range processes {
					for i, p := range passes {
						what := fmt.Sprintf("%s %s, a box %s, %s, from %s", m, pattern, st.name, p.name, pr.name)
						got := pr.call(fmt.Sprintf("192.0.2.%d", i+1), m, path, body, p.auth)
						if got.status != w.status || m != http.MethodHead && got.code() != w.code {
							t.Errorf("%s: %d %s, want %d %s", what, got.status, got.code(), w.status, w.code)
							continue
						}
						if m == http.MethodHead || !w.record {
							continue
						}
						var rec struct {
							Record   *protocol.Revocations `json:"record"`
							Identity protocol.Bytes        `json:"identity"`
						}
						_ = json.Unmarshal(got.body, &rec)
						if (rec.Record == nil || string(rec.Record.Identity) != string(st.r.id.Document())) && string(rec.Identity) != string(st.r.id.Document()) {
							t.Errorf("%s: %d with no record of the address: %s", what, got.status, got.body)
						}
					}
				}
			}
		}
	}
}

// What each limit of the server is to a retry (R2), by its name in
// limitsByName: a count of what a call makes new, which never refuses that
// call's retry and which a retry never spends; or why it is neither.
var retryRoles = map[string]string{
	string(protocol.QuotaRegistrations):          "made new by a registration, and by a revocation of an address held nothing of",
	string(protocol.QuotaRegistrationsRange):     "made new by a registration, and by a revocation of an address held nothing of",
	string(protocol.QuotaRenewals):               "made new by a renewal",
	string(protocol.QuotaCertificates):           "made new by a renewal",
	string(protocol.QuotaCertificateRevocations): "made new by a raise of the revocation of certificates",
	string(protocol.QuotaSends):                  "made new by a send",
	string(protocol.CodeMailboxBusy):             "made new by a send",
	string(protocol.QuotaRequests):               "the call's own: its address's flood budget, which may defer it",
	string(protocol.QuotaCalls):                  "the call's own: its box's calls, which may defer it",
	string(protocol.QuotaSendsBeforePass):        "the call's own: its address's sends before their pass, which may defer it",
	string(protocol.QuotaMisses):                 "the bound of a read that may find no box and of a pass that may fail, reserved before either",
	string(protocol.QuotaPolls):                  "a list's",
	string(protocol.QuotaPages):                  "a list's",
	string(protocol.CodeRefetchSpent):            "a fetch's",
	string(protocol.CodeFetchPaced):              "a fetch's",
}

// madeNew reports whether the limit named name counts what a call makes new
// (retryRoles).
func madeNew(name string) bool { return strings.HasPrefix(retryRoles[name], "made new") }

// retried is a call that could change nothing, made again, and whether it
// is answered from what is kept: "" if it is, or what it was answered.
type retried struct {
	name   string
	call   func() reply
	wanted func(first, got reply) string
}

// emptyOK is wanted of a retry answered 200 {}.
func emptyOK(_, got reply) string {
	if got.status != http.StatusOK || strings.TrimSpace(string(got.body)) != "{}" {
		return fmt.Sprintf("%d %s, want 200 {}", got.status, got.body)
	}
	return ""
}

// What could change nothing is answered from what is kept, whatever it
// would make new (PROTOCOL.md §13, the order of refusals): a registration's
// identical retry, with its address's registrations and its /48's spent, is
// 200 {}; a renewal's, with the box's renewals and certificates spent, 200
// {}; a send's retry, with its sender's sends a day, the pair and box caps
// and its recipient's new mail received spent, its first receipt; a
// revocation of an address held revoked, with the registrations a
// revocation of an address held nothing of spends spent, 410 with the
// record; and a revocation of certificates through the serial held, with
// the raises a day spent, 200 {}, and one through a lower serial 409
// conflict. Each count is spent alone, by the call the retry repeats, and
// then all of a kind's together, in a process whose memory holds the box and
// in one that reads it. The control is a new call of the kind, refused by a
// count spent; and the retry spends none of what any call makes new. The
// limits are read from the code (limitsByName): one without its role in
// retryRoles fails.
func TestARetryIsAnsweredFromWhatIsKeptWhateverItWouldMakeNew(t *testing.T) {
	t.Parallel()
	for name := range New(Config{Store: NewMemStore(nil), Limits: relaxed()}).limitsByName() {
		if _, ok := retryRoles[name]; !ok {
			t.Errorf("the limit %s: no role of it in retryRoles", name)
		}
	}
	const ip = "2001:db8:5:5::1" // an IPv6 caller, whose registrations its /48 counts too
	type caller = func(ip, method, path string, body any, pass string) reply
	// A kind's run makes the call its retries repeat, spending each count of
	// spent, and returns its answer, the retries, and the control to make.
	type run = func(e *env, call caller, spent []string) (first reply, retries []retried, control func() reply)
	registrations := map[string]func(*Limits){
		string(protocol.QuotaRegistrations):      func(l *Limits) { l.RegistrationsPerHour = 1 },
		string(protocol.QuotaRegistrationsRange): func(l *Limits) { l.RangeRegistrationsPerHour = 1 },
	}
	kinds := []struct {
		name   string
		counts map[string]func(*Limits) // each count, by the name a refusal gives it, set to one
		run    run
	}{
		{"registration", registrations, func(e *env, call caller, _ []string) (reply, []retried, func() reply) {
			r, other := e.raw(), e.raw()
			r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			other.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1)),
				[]retried{{"its identical retry", func() reply { return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1)) }, emptyOK}},
				func() reply { return call(ip, "PUT", other.path(""), other.registration(1), other.pass(1)) }
		}},
		{"renewal", map[string]func(*Limits){
			string(protocol.QuotaRenewals):     func(l *Limits) { l.RenewalsPerDay = 1 },
			string(protocol.QuotaCertificates): func(l *Limits) { l.CertificatesPerDay = 1 },
		}, func(e *env, call caller, spent []string) (reply, []retried, func() reply) {
			// A renewal under the box's current certificate spends its
			// renewals, and one under a later certificate its certificates:
			// with both spent, one of each, and the retry repeats the later.
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			until := e.clock.Now().Add(protocol.PrekeyLifetime)
			var first reply
			var last, under uint64 // the statement the retry repeats, and its certificate
			if slices.Contains(spent, string(protocol.QuotaRenewals)) {
				last, under = 2, 1
				r.prekeyUnder(r.work[1], last, until, nil)
				first = call(ip, "PUT", r.path("/prekey"), r.upload(last), r.pass(under))
			}
			if slices.Contains(spent, string(protocol.QuotaCertificates)) && first.status < 300 {
				last, under = 3, 3
				r.prekey(last, until, nil)
				first = call(ip, "PUT", r.path("/prekey"), r.upload(last), r.pass(under))
			}
			retries := []retried{{"its identical retry", func() reply { return call(ip, "PUT", r.path("/prekey"), r.upload(last), r.pass(under)) }, emptyOK}}
			if under == 3 { // the control: a later certificate again
				r.prekey(5, until, nil)
				return first, retries, func() reply { return call(ip, "PUT", r.path("/prekey"), r.upload(5), r.pass(5)) }
			}
			r.prekeyUnder(r.work[1], 4, until, nil) // the control: a higher serial under the same certificate
			return first, retries, func() reply { return call(ip, "PUT", r.path("/prekey"), r.upload(4), r.pass(1)) }
		}},
		{"send", map[string]func(*Limits){
			string(protocol.QuotaSends):      func(l *Limits) { l.SendsPerDay = 1 },
			string(protocol.CodePairFull):    func(l *Limits) { l.PairCap = 1 },
			string(protocol.CodeMailboxFull): func(l *Limits) { l.BoxCap = 1 },
			string(protocol.CodeMailboxBusy): func(l *Limits) { l.ReceiveBurst, l.ReceiveRefill = 1, time.Hour },
		}, func(e *env, call caller, _ []string) (reply, []retried, func() reply) {
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			post := sealedTo(1, 1, ciphertextTo(e.t, to))
			return e.do("POST", to.path("/messages"), post, from.pass(1)),
				[]retried{{"the same ciphertext again", func() reply { return e.do("POST", to.path("/messages"), post, from.pass(1)) }, func(first, got reply) string {
					if got.status != http.StatusOK || string(got.body) != string(first.body) {
						return fmt.Sprintf("%d %s, want 200 and the first receipt %s", got.status, got.body, first.body)
					}
					return ""
				}}},
				func() reply {
					return e.do("POST", to.path("/messages"), sealedTo(1, 1, ciphertextTo(e.t, to)), from.pass(1))
				}
		}},
		{"revocation", map[string]func(*Limits){
			string(protocol.QuotaRegistrations):          registrations[string(protocol.QuotaRegistrations)],
			string(protocol.QuotaRegistrationsRange):     registrations[string(protocol.QuotaRegistrationsRange)],
			string(protocol.QuotaCertificateRevocations): func(l *Limits) { l.CertificateRevocationsPerDay = 1 },
		}, func(e *env, call caller, spent []string) (reply, []retried, func() reply) {
			// A revocation of an address held nothing of spends its caller's
			// registrations, and a raise of a box's revocation of
			// certificates its raises a day: with all spent, one of each.
			var first reply
			var retries []retried
			var control func() reply
			if slices.Contains(spent, string(protocol.QuotaCertificateRevocations)) {
				r := e.raw()
				r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
				e.want(call("192.0.2.80", "PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "") // from an address of its own
				if first = call(ip, "PUT", r.path("/revocations"), r.certs(5), ""); first.status != http.StatusOK {
					return first, nil, nil
				}
				retries = append(retries,
					retried{"through the serial held", func() reply { return call(ip, "PUT", r.path("/revocations"), r.certs(5), "") }, emptyOK},
					retried{"through a lower serial", func() reply { return call(ip, "PUT", r.path("/revocations"), r.certs(3), "") }, func(_, got reply) string {
						if got.status != http.StatusConflict || got.code() != protocol.CodeConflict {
							return fmt.Sprintf("%d %s, want 409 conflict", got.status, got.body)
						}
						return ""
					}})
				control = func() reply { return call(ip, "PUT", r.path("/revocations"), r.certs(7), "") }
			}
			if slices.ContainsFunc(spent, func(n string) bool { return n != string(protocol.QuotaCertificateRevocations) }) {
				r, other := e.raw(), e.raw()
				revocation := func(r *raw) protocol.Revocations {
					rev, err := protocol.SignRevocation(r.signer, r.id.Address())
					if err != nil {
						e.t.Fatal(err)
					}
					return protocol.Revocations{Identity: r.id.Document(), Revocation: rev}
				}
				if first = call(ip, "PUT", r.path("/revocations"), revocation(r), ""); first.status != http.StatusCreated {
					return first, nil, nil
				}
				retries = append(retries, retried{"of the address held revoked", func() reply { return call(ip, "PUT", r.path("/revocations"), revocation(r), "") }, func(_, got reply) string {
					var p struct {
						Record *protocol.Revocations `json:"record"`
					}
					if got.status != http.StatusGone || got.code() != protocol.CodeRevoked || json.Unmarshal(got.body, &p) != nil || p.Record == nil || string(p.Record.Identity) != string(r.id.Document()) {
						return fmt.Sprintf("%d %s, want 410 revoked with the address's record", got.status, got.body)
					}
					return ""
				}})
				control = func() reply { return call(ip, "PUT", other.path("/revocations"), revocation(other), "") }
			}
			return first, retries, control
		}},
	}
	worlds := map[string][]func(*Config){
		"a process that holds the box": nil,
		"a process that reads it":      {func(c *Config) { c.Store = unknownStore{c.Store} }},
	}
	for _, k := range kinds {
		names := slices.Sorted(maps.Keys(k.counts))
		runs := [][]string{names}
		for _, n := range names {
			runs = append(runs, []string{n})
		}
		for _, spent := range runs {
			for world, with := range worlds {
				t.Run(fmt.Sprintf("%s, %s spent, %s", k.name, strings.Join(spent, " and "), world), func(t *testing.T) {
					l := relaxed()
					l.PairCap, l.BoxCap = 0, 0
					for _, n := range spent {
						k.counts[n](&l)
					}
					e := newEnv(t, l, with...)
					first, retries, control := k.run(e, e.caller(), spent)
					if first.status >= 300 || len(retries) == 0 {
						t.Fatalf("the call the retries repeat: %d %s", first.status, first.body)
					}
					for _, n := range spent {
						if _, ok := retryRoles[n]; ok && debts(e.server, e.clock.Now())[n] == 0 { // a count of limitsByName: the call spent it
							t.Errorf("%s: the call the retries repeat left it unspent", n)
						}
					}
					for _, rt := range retries {
						before := debts(e.server, e.clock.Now())
						got := rt.call()
						for n, d := range debts(e.server, e.clock.Now()) {
							if madeNew(n) && d != before[n] {
								t.Errorf("%s: spent %d of %s, which counts what a call makes new", rt.name, d-before[n], n)
							}
						}
						if why := rt.wanted(first, got); why != "" {
							t.Errorf("%s: %s", rt.name, why)
						}
					}
					got := control()
					refusedBy := string(got.code())
					if q, _ := got.quota(); q != "" {
						refusedBy = string(q)
					}
					if got.status != http.StatusTooManyRequests || !slices.Contains(spent, refusedBy) {
						t.Errorf("the control, a new %s: %d %s, want 429 by one of %v", k.name, got.status, got.body, spent)
					}
				})
			}
		}
	}
}
