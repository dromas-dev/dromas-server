package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The budgets of LIMITS.md, and the rules they are taken by: every call
// spends from one, a count is taken before the work it guards, and what
// would change nothing is answered before what costs.

// A retry is answered as the first send was, from the message held, though
// the mailbox renewed its prekey since (PROTOCOL.md §11.10 step 6): stored once,
// counted once. A new ciphertext to the retired prekey is still stale.
func TestARetryAfterARenewalGetsItsReceipt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 1, 1
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	first := send(t, a, b, "sent before the renewal")
	e.setMiddle(nil)
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	r := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a))
	var again protocol.Receipt
	if r.status != http.StatusOK || json.Unmarshal(r.body, &again) != nil || again != *first {
		t.Fatalf("a retry after the renewal: %d %s, want 200 and %+v", r.status, r.body, *first)
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 1 {
		t.Fatalf("the mailbox holds %d messages (%v), want the one", n, err)
	}
	other := *sent
	other.ciphertext = append([]byte{}, sent.ciphertext...)
	other.ciphertext[len(other.ciphertext)-1] ^= 1 // another ciphertext, to the same retired prekey
	e.want(e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", other, e.pass(a)), http.StatusConflict, protocol.CodePrekeySuperseded)
}

// A sender's calls bound what its sends cost before they are checked, the
// dedupe's read among them, and a retry spends from them too
// (Limits.CallBurst): past them a replay is refused before anything is read.
func TestASendersCallsBoundTheDedupeRead(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, a, b, "once")
	e.setMiddle(nil)
	l.CallBurst, l.CallRefill = 3, time.Minute
	e2, cs := counted(t, e, l)
	pass := e2.pass(a)
	for range 3 {
		e2.want(e2.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, pass), http.StatusOK, "")
	}
	before := cs.calls.Load()
	r := e2.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, pass)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if r.header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for a replay past the sender's calls", n-before)
	}
}

// A mailbox takes new messages at a rate of its own, from every sender together
// (Limits.ReceiveBurst): past it a send is mailbox_rate_limited and waits in its
// sender's outbox. A retry spends none of it, and an unmetered account lifts
// it to Limits.AccountReceiveRefill.
func TestTheReceiveBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.ReceiveBurst, l.ReceiveRefill = 2, time.Minute
	e := newEnv(t, l)
	b := e.mailbox()
	s1, s2, s3 := e.mailbox(), e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, s1, b, "one")
	e.setMiddle(nil)
	send(t, s2, b, "two")
	_, err := s3.Send(ctx, b.Address(), "three")
	var ae *client.APIError
	if codeOf(err) != protocol.CodeMailboxRateLimited || !errorsAs(err, &ae) || ae.RetryAfter <= 0 || ae.Status != http.StatusTooManyRequests {
		t.Fatalf("a third new message in the burst: %v", err)
	}
	e.want(e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(s1)), http.StatusOK, "") // a retry: nothing new
	e.clock.Add(time.Minute)
	if rs, err := s3.Flush(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("the waiting message after a refill: %v, %v", rs, err)
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 3 {
		t.Fatalf("the mailbox holds %d messages (%v), want 3", n, err)
	}

	// An unmetered account's mailbox takes messages at the lifted refill: the
	// same burst, then one each AccountReceiveRefill.
	_, key := accountEnv(t, e, true, 1)
	echo := e.mailbox()
	adopt(t, echo, key)
	for i, s := range []*client.Mailbox{s1, s2} {
		if _, err := s.Send(ctx, echo.Address(), "to the unmetered mailbox"); err != nil {
			t.Fatalf("send %d to an unmetered mailbox: %v", i+1, err)
		}
	}
	_, err = s3.Send(ctx, echo.Address(), "past its burst")
	if codeOf(err) != protocol.CodeMailboxRateLimited || !errorsAs(err, &ae) || ae.RetryAfter != time.Second {
		t.Fatalf("a third new message to the unmetered mailbox at once: %v, want mailbox_rate_limited after a second", err)
	}
	if top, ok := e.server.Top(string(protocol.CodeMailboxRateLimited), 10); !ok || !slices.ContainsFunc(top, func(d Indebted) bool { return d.Key == echo.Address().String() }) {
		t.Errorf("the operator's top of mailbox_rate_limited, %v, does not list the unmetered mailbox", top)
	}
	e.clock.Add(l.AccountReceiveRefill)
	if rs, err := s3.Flush(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("the waiting message after one lifted refill: %v, %v", rs, err)
	}
}

// liftedPolls are the limits of the tests of the lifted polls: a burst of
// two, refilled once a minute, which an unmetered account lifts to one each
// ten seconds.
func liftedPolls() Limits {
	l := relaxed()
	l.PollBurst, l.PollRefill, l.AccountPollRefill = 2, time.Minute, 10*time.Second
	return l
}

// polls lists b's messages n times at once, each answered 200, then once
// more, which is refused polls after wait.
func (e *env) polls(b *client.Mailbox, n int, wait time.Duration) {
	e.t.Helper()
	path := "/v1/" + b.Address().String() + "/messages"
	for range n {
		e.want(e.do(http.MethodGet, path, nil, e.pass(b)), http.StatusOK, "")
	}
	r := e.do(http.MethodGet, path, nil, e.pass(b))
	e.limited(r, protocol.QuotaPolls)
	if got := r.header.Get("Retry-After"); got != strconv.Itoa(retrySeconds(wait)) {
		e.t.Fatalf("a poll past the burst: Retry-After %q, want %v", got, wait)
	}
}

// An unmetered account lifts its mailboxes' polls to Limits.AccountPollRefill
// (LIMITS.md § Accounts): the same burst, then one each AccountPollRefill,
// and the operator's top of polls lists such a mailbox.
func TestAnUnmeteredAccountLiftsItsMailboxesPolls(t *testing.T) {
	t.Parallel()
	l := liftedPolls()
	e := newEnv(t, l)
	_, key := accountEnv(t, e, true, 1)
	echo := e.mailbox()
	adopt(t, echo, key)
	e.polls(echo, l.PollBurst, l.AccountPollRefill)
	e.clock.Add(l.AccountPollRefill)
	e.polls(echo, 1, l.AccountPollRefill)
	if top, ok := e.server.Top(string(protocol.QuotaPolls), 10); !ok || !slices.ContainsFunc(top, func(d Indebted) bool { return d.Key == echo.Address().String() }) {
		t.Errorf("the operator's top of polls, %v, does not list the unmetered mailbox", top)
	}
}

// A mailbox outside an unmetered account, in no account or in a metered one,
// polls at Limits.PollRefill, whatever AccountPollRefill is.
func TestAMailboxOutsideAnUnmeteredAccountPollsAtPollRefill(t *testing.T) {
	t.Parallel()
	l := liftedPolls()
	e := newEnv(t, l)
	_, key := accountEnv(t, e, false, 1)
	metered := e.mailbox()
	adopt(t, metered, key)
	outside := []*client.Mailbox{e.mailbox(), metered}
	for _, b := range outside {
		e.polls(b, l.PollBurst, l.PollRefill)
	}
	e.clock.Add(l.AccountPollRefill)
	for _, b := range outside {
		e.polls(b, 0, l.PollRefill-l.AccountPollRefill)
	}
	e.clock.Add(l.PollRefill - l.AccountPollRefill)
	for _, b := range outside {
		e.polls(b, 1, l.PollRefill)
	}
}

// The lifted polls are counted in buckets of their own (LIMITS.md
// § Accounts): a mailbox that has spent its polls at Limits.PollRefill and
// then joins an unmetered account has the whole burst at once, and a mailbox
// outside the account that polls with it keeps its own refill.
func TestTheLiftedPollsHaveBucketsOfTheirOwn(t *testing.T) {
	t.Parallel()
	l := liftedPolls()
	e := newEnv(t, l)
	_, key := accountEnv(t, e, true, 1)
	joins, free := e.mailbox(), e.mailbox()
	e.polls(joins, l.PollBurst, l.PollRefill)
	e.polls(free, l.PollBurst, l.PollRefill)
	adopt(t, joins, key)
	e.polls(joins, l.PollBurst, l.AccountPollRefill)
	e.clock.Add(l.AccountPollRefill)
	e.polls(joins, 1, l.AccountPollRefill)
	e.polls(free, 0, l.PollRefill-l.AccountPollRefill)
}

func errorsAs(err error, ae **client.APIError) bool {
	for err != nil {
		if e, ok := err.(*client.APIError); ok {
			*ae = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// A lookup, the read of a mailbox, is its caller's address's to pay for: it
// takes no pass (PROTOCOL.md §11.8; dromas-dev/dromas-client#352). Past
// the gate, where it spends its address's flood budget whatever it carries,
// a pass this process has checked among them, it spends nothing, as the
// page a link opens spends nothing: memory answers both, and only a read
// that finds no mailbox counts, as a miss. Whatever Authorization it carries,
// no pass is parsed or checked, and none of a mailbox's calls is spent.
func TestLookupsArePaidByTheirCaller(t *testing.T) {
	t.Parallel()
	t.Run("whatever it carries", func(t *testing.T) {
		l := relaxed()
		l.CallBurst, l.CallRefill = 1, time.Hour
		e, _, reg := metered(t, l)
		a, b := e.mailbox(), e.mailbox()
		e.clock.Add(time.Second) // past the passes the registrations showed
		pass := e.pass(a)
		e.want(e.do(http.MethodGet, "/v1/"+a.Address().String()+"/acl", nil, pass), http.StatusOK, "") // a's one call, which checks its pass
		before := counts(t, reg, "dromas_server_passes_total")
		read := "/v1/" + b.Address().String()
		for _, auth := range []string{pass, e.pass(b), "dromas-pass nonsense", "Bearer x", ""} {
			for range 3 {
				e.want(e.do(http.MethodGet, read, nil, auth), http.StatusOK, "")
			}
		}
		if d := moved(before, counts(t, reg, "dromas_server_passes_total")); len(d) != 0 {
			t.Errorf("reads of a mailbox looked at passes: %v", d)
		}
		e.limited(e.do(http.MethodGet, "/v1/"+a.Address().String()+"/acl", nil, pass), protocol.QuotaCalls) // the one it spent, and none by the reads
	})
	t.Run("its address's flood budget, with a pass checked", func(t *testing.T) {
		l := relaxed()
		l.RequestBurst, l.RequestRefill = 2, time.Hour
		e := newEnv(t, l)
		call := e.caller()
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
		e.want(call("10.0.0.1", "PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
		pass := r.pass(1)
		e.want(call("10.0.0.2", "GET", r.path("/messages"), nil, pass), http.StatusOK, "") // checked, of a mailbox live in memory
		for range l.RequestBurst {
			e.want(call("10.0.0.3", "GET", r.path(""), nil, pass), http.StatusOK, "")
		}
		e.limited(call("10.0.0.3", "GET", r.path(""), nil, pass), protocol.QuotaRequests)
		e.want(call("10.0.0.3", "GET", r.path("/messages"), nil, pass), http.StatusOK, "") // a call that takes the pass is its mailbox's
	})
	t.Run("with none", func(t *testing.T) {
		l := relaxed()
		e := newEnv(t, l)
		b := e.mailbox()
		l.MissesPerMinute = 2
		e2, cs := counted(t, e, l)
		read := "/v1/" + b.Address().String()
		e2.want(e2.do(http.MethodGet, read, nil, ""), http.StatusOK, "")
		before := cs.calls.Load()
		for range 50 {
			e2.want(e2.do(http.MethodGet, read, nil, ""), http.StatusOK, "")
			if r := e2.do(http.MethodGet, protocol.LinkPath+b.Address().String(), nil, ""); r.status != http.StatusOK {
				t.Fatalf("the link page: %d", r.status)
			}
		}
		if got := cs.calls.Load(); got != before {
			t.Errorf("50 more lookups of a mailbox held in memory made %d storage calls, want none", got-before)
		}
	})
}

// A fetch or an ack of an id the mailbox does not hold is answered from memory,
// and is a call like any other: it spends the mailbox's calls. A held message's
// fetch and ack were paid for by its receive.
func TestUnknownIDsSpendTheMailboxsCalls(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "held")
	l.CallBurst, l.CallRefill = 2, time.Minute
	e2, _ := counted(t, e, l)
	pass := e2.pass(b)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	unknown := "/v1/" + b.Address().String() + "/messages/" + strings.Repeat("ab", 32)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusNotFound, protocol.CodeMessageNotFound)
	e2.want(e2.do(http.MethodGet, unknown, nil, pass), http.StatusNotFound, protocol.CodeMessageNotFound)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusTooManyRequests, protocol.CodeRateLimited)
}

// A prekey statement that could not be taken even if it verified is refused
// from its order, read before any signature is checked (PROTOCOL.md §11.9): a
// serial not above the current one under the current certificate is 409 and
// a certificate the floor covers is invalid_key, though the signature is not the
// statement's. Nothing is counted against the caller for either.
func TestAStatementOutOfOrderIsRefusedBeforeItsSignature(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	r := e.raw()
	n := r.registerCertified(protocol.MaxPrekeyLifetime)
	key, _ := age.GenerateHybridIdentity()
	stale := &protocol.Prekey{Address: r.id.Address(), Rank: n, Serial: n, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	misSigned := protocol.PrekeyRequest{Prekey: stale.Statement(), PrekeySignature: r.sig[n]} // the current statement's signature, over other bytes
	e.want(e.do("PUT", r.path("/prekey"), misSigned, r.pass(n)), http.StatusConflict, protocol.CodeSerialTooLow)
	e.want(e.do("PUT", r.path("/revocation"), r.certs(n), ""), http.StatusOK, "")
	stale.Serial = n + 1
	misSigned.Prekey = stale.Statement()
	got := e.do("PUT", r.path("/prekey"), misSigned, r.pass(n))
	e.want(got, http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	if !strings.Contains(string(got.body), "revoked") {
		t.Fatalf("a statement under a revoked certificate: %s", got.body)
	}
	var nobody protocol.Address
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusNotFound, protocol.CodeMailboxNotFound) // the address's one miss is still there
}

// Registration never changes a mailbox, so a registered mailbox is answered from its
// record whether this process holds it or reads it, and spends nothing of its
// address's registrations (PROTOCOL.md §11.5, a request that would change
// nothing; dromas-dev/dromas-client#410): with the address's one registration
// spent, the mailbox's identical retry is 200, and another statement is 409 with
// no check, signed or not, with a pass or none.
func TestARegisteredMailboxIsAnsweredWhateverItsAddressSpentOfRegistrations(t *testing.T) {
	t.Parallel()
	for name, with := range map[string][]func(*Config){
		"a mailbox this process holds":         nil,
		"a mailbox this process does not hold": {func(c *Config) { c.Store = unknownStore{c.Store} }},
	} {
		t.Run(name, func(t *testing.T) {
			l := relaxed()
			l.RegistrationsPerHour = 1
			e := newEnv(t, l, with...)
			r := e.raw().register(protocol.MaxPrekeyLifetime) // the address's one registration
			r.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			unsigned := r.registration(1)
			unsigned.PrekeySignature = []byte("not a signature")
			retry := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
			another := e.do("PUT", r.path(""), r.registration(2), r.pass(2))
			if retry.status != http.StatusOK || another.status != http.StatusConflict || another.code() != protocol.CodeMailboxAlreadyExists {
				t.Fatalf("retry %d %s, another statement %d %s: want 200, and 409 mailbox_already_exists", retry.status, retry.code(), another.status, another.code())
			}
			e.want(e.do("PUT", r.path(""), unsigned, ""), http.StatusConflict, protocol.CodeMailboxAlreadyExists)
		})
	}
}

// failedReads is a store whose reads of an address fail while fail is set,
// as a store that cannot be reached.
type failedReads struct {
	Store
	fail atomic.Bool
}

func (s *failedReads) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if s.fail.Load() {
		return nil, errors.New("the store cannot be reached")
	}
	return s.Store.Mailbox(ctx, a)
}

// A registration's read of an address its process's memory cannot answer is
// counted once, as what it turns out to be (LIMITS.md rule 4; register;
// dromas-dev/dromas-client#410). The registrations it would spend, of
// the address and of its /48, are reserved before the read and given back
// when it finds a mailbox or a revocation, or fails, and kept when it finds
// nothing; it reserves no miss. Where they are spent, the read is a
// lookup's, under a miss: given back when it finds a mailbox or a revocation,
// and kept when it finds nothing, which is refused for the registrations.
// With the misses spent too, the read is refused for them.
func TestARegistrationsReadIsCountedAsWhatItFinds(t *testing.T) {
	t.Parallel()
	const ip = "2001:db8:7:7::1"
	l := relaxed()
	l.RegistrationsPerHour, l.RangeRegistrationsPerHour, l.MissesPerMinute = 2, 2, 1
	reads := &failedReads{}
	e := newEnv(t, l, func(c *Config) { reads.Store, c.Store = c.Store, unknownStore{reads} })
	call := e.caller()
	fresh := func() *raw {
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
		return r
	}
	register := func(r *raw) reply { return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1)) }
	mailbox, gone := fresh(), fresh()
	e.want(register(mailbox), http.StatusCreated, "") // the first of the two
	e.want(call("192.0.2.70", "PUT", gone.path(""), gone.registration(1), gone.pass(1)), http.StatusCreated, "")
	rev, err := protocol.SignRevocation(gone.signer, gone.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(call("192.0.2.70", "PUT", gone.path("/revocation"), protocol.Revocations{Identity: gone.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
	mailbox.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	// answered is the mailbox's identical retry, another statement, and a
	// registration of the revoked address, each answered from what is kept.
	answered := func() {
		t.Helper()
		e.want(register(mailbox), http.StatusOK, "")
		e.want(call(ip, "PUT", mailbox.path(""), mailbox.registration(2), mailbox.pass(2)), http.StatusConflict, protocol.CodeMailboxAlreadyExists)
		e.want(register(gone), http.StatusGone, protocol.CodeMailboxRevoked)
	}

	// One registration left: what finds a mailbox or a revocation gives it back,
	// and so does a read that fails.
	for range 3 {
		answered()
	}
	failing := fresh()
	reads.fail.Store(true)
	e.want(register(failing), http.StatusServiceUnavailable, protocol.CodeUnavailable)
	reads.fail.Store(false)
	e.want(register(failing), http.StatusCreated, "") // the second of the two

	// None left: the read is a lookup's, under the one miss, which a mailbox or
	// a revocation found gives back.
	for range 3 {
		answered()
	}
	e.limited(register(fresh()), protocol.QuotaRegistrations) // nothing found: the miss kept
	e.limited(register(fresh()), protocol.QuotaMisses)
	e.limited(register(mailbox), protocol.QuotaMisses) // the retry is deferred by the misses, never refused for the registrations
	e.clock.Add(time.Minute)                           // the miss back, no registration
	e.want(register(mailbox), http.StatusOK, "")
}

// readsMeet holds the first read of address a's record, once it has read,
// until a second has read too, so two registrations of a both read it
// before either writes, however their goroutines are scheduled: a second
// read that had only begun could still land after the first's write, and
// find the mailbox. Later reads pass. late is set if no second read ended within
// 5 s.
type readsMeet struct {
	Store
	a    protocol.Address
	n    atomic.Int32
	both chan struct{}
	late atomic.Bool
}

func (s *readsMeet) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	b, err := s.Store.Mailbox(ctx, a)
	if a == s.a {
		switch s.n.Add(1) {
		case 1:
			select {
			case <-s.both:
			case <-time.After(5 * time.Second):
				s.late.Store(true)
			}
		case 2:
			close(s.both)
		}
	}
	return b, err
}

// Two identical registrations of a new address at once, each reading it
// before either writes, make one mailbox: one is 201, and the other meets the
// mailbox at its write and is answered 200 from its record (registered,
// bounded). Each kept its registrations before its signatures (register,
// g.keep), and the one answered 200 gives them back (refund), as Boulder's
// NewAccount refunds the loser: the two spend one of each count, from IPv4
// the address's and from IPv6 the /48's. Control: with no refund, the first
// fresh registration after them is refused.
func TestIdenticalRegistrationsAtOnceSpendOneRegistration(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, ip, fresh string // the race's caller, and the fresh registrations'
		quota           protocol.Quota
		limits          func(*Limits)
	}{
		{"the address's", "192.0.2.7", "192.0.2.7", protocol.QuotaRegistrations, func(l *Limits) { l.RegistrationsPerHour = 2 }},
		{"the /48's", "2001:db8:1:1::1", "2001:db8:1:2::1", protocol.QuotaRegistrationsRange, func(l *Limits) { l.RangeRegistrationsPerHour = 2 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := relaxed()
			c.limits(&l)
			meet := &readsMeet{both: make(chan struct{})}
			e := newEnv(t, l, func(c *Config) { meet.Store, c.Store = c.Store, unknownStore{meet} })
			call := e.caller()
			r := e.raw()
			r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			meet.a = r.id.Address()
			reg, pass := r.registration(1), r.pass(1)
			answers := make(chan reply, 2)
			for range 2 {
				go func() { answers <- call(c.ip, "PUT", r.path(""), reg, pass) }()
			}
			a, b := <-answers, <-answers
			if meet.late.Load() {
				t.Fatal("the second registration never read the address while the first waited")
			}
			if got := fmt.Sprint(a.status, " ", b.status); got != "201 200" && got != "200 201" {
				t.Fatalf("two identical registrations at once: %s %s, %s %s; want 201 and 200", got, a.code(), b.code(), b.body)
			}
			register := func() reply {
				fresh := e.raw()
				fresh.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
				return call(c.fresh, "PUT", fresh.path(""), fresh.registration(1), fresh.pass(1))
			}
			e.want(register(), http.StatusCreated, "")
			e.limited(register(), c.quota)
		})
	}
}

// A revocation of certificates through a serial no higher than the one held
// changes nothing, and is answered so before its signature is checked: the
// same serial 200, a lower one 409, whatever the signature; a higher one's
// signature is checked.
func TestAFloorNoHigherIsAnsweredWithoutACheck(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/revocation"), r.certs(7), ""), http.StatusOK, "")
	same, lower := r.certs(7), r.certs(5)
	same.RevokedCertificatesSignature, lower.RevokedCertificatesSignature = []byte("junk"), []byte("junk")
	e.want(e.do("PUT", r.path("/revocation"), same, ""), http.StatusOK, "")
	e.want(e.do("PUT", r.path("/revocation"), lower, ""), http.StatusConflict, protocol.CodeSerialTooLow)
	higher := r.certs(9)
	higher.RevokedCertificatesSignature = []byte("junk")
	e.want(e.do("PUT", r.path("/revocation"), higher, ""), http.StatusBadRequest, protocol.CodeInvalidRevocation) // checked
}

// The identity's acts are counted per mailbox, each kind on its own, so neither
// holds back the other: its new certificates (Limits.CertificatesPerDay), the
// mailbox's first among them, a renewal by a later signer than the identity,
// and its raises of the revocation of certificates
// (Limits.CertificateRevocationsPerDay). A renewal while the revocation held
// covers the mailbox's current certificate is not counted: it replaces what
// a counted raise revoked. The revocation of the address is counted against
// no mailbox, so nothing keeps an owner from ending a mailbox.
func TestTheIdentitysActsAreCountedApart(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.CertificatesPerDay, l.CertificateRevocationsPerDay, l.CertificatesBurst, l.CertificateRevocationsBurst = 1, 1, 1, 1
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime).certified()
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekey(5, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(5), r.pass(5)), http.StatusOK, "") // the mailbox's first certificate, the day's one
	r.prekey(6, until, nil)
	e.limited(e.do("PUT", r.path("/prekey"), r.upload(6), r.pass(6)), protocol.QuotaCertificates)
	e.want(e.do("PUT", r.path("/revocation"), r.certs(5), ""), http.StatusOK, "") // the day's one raise, which no certificate spent
	e.limited(e.do("PUT", r.path("/revocation"), r.certs(7), ""), protocol.QuotaCertificateRevocations)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(6), r.pass(6)), http.StatusOK, "") // replaces certificate 5, which is revoked
	r.prekey(8, until, nil)
	e.limited(e.do("PUT", r.path("/prekey"), r.upload(8), r.pass(8)), protocol.QuotaCertificates) // 6 is not revoked
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocation"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
}

// A taker who holds a mailbox's working key can spend the mailbox's calls with its
// pass, and so hold back a renewal by that working key. It cannot hold back a
// renewal under a later certificate, the identity's act, which spends its
// certificates and no calls (PROTOCOL.md §11.5, §15.5). The control is a renewal
// by the current signer, which the spent calls refuse.
func TestATakerCannotHoldARenewalUnderALaterCertificateBack(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.CallBurst, l.CallRefill = DefaultLimits().CallBurst, DefaultLimits().CallRefill
	e := newEnv(t, l)
	r := e.raw()
	r.registerCertified(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekey(1000, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(1000), r.pass(1000)), http.StatusOK, "")
	taken := r.pass(1000)
	for e.do("GET", r.path("/acl"), nil, taken).status == http.StatusOK {
	}
	r.prekeyUnder(r.work[1000], 1001, until, nil)
	e.limited(e.do("PUT", r.path("/prekey"), r.upload(1001), taken), protocol.QuotaCalls)
	r.prekey(2000, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2000), r.pass(2000)), http.StatusOK, "")
	e.limited(e.do("GET", r.path("/acl"), nil, r.pass(2000)), protocol.QuotaCalls)
}

// A taker who holds a mailbox's working key cannot hold back the identity's
// raise of the revocation of certificates, which carries no pass and spends a
// count no renewal spends. Once that is taken, the taken pass is
// refused, and the renewal that replaces the revoked certificate is taken at
// once, with the mailbox's calls and the identity's certificates for the day
// spent: it spends none of the mailbox's counts (#84). The calls are still
// spent after it.
func TestATakerCannotHoldTheRemedyBack(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.CallBurst, l.CallRefill = DefaultLimits().CallBurst, DefaultLimits().CallRefill
	l.CertificatesPerDay, l.CertificateRevocationsPerDay, l.CertificatesBurst, l.CertificateRevocationsBurst = 1, 1, 1, 1
	e := newEnv(t, l)
	r := e.raw()
	r.registerCertified(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekey(1000, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(1000), r.pass(1000)), http.StatusOK, "") // the day's one certificate
	taken := r.pass(1000)
	for e.do("GET", r.path("/acl"), nil, taken).status == http.StatusOK {
	}
	r.prekey(2000, until, nil)
	e.limited(e.do("PUT", r.path("/prekey"), r.upload(2000), r.pass(2000)), protocol.QuotaCertificates) // the day's one is spent
	e.want(e.do("PUT", r.path("/revocation"), r.certs(1000), ""), http.StatusOK, "")
	e.want(e.do("GET", r.path("/acl"), nil, taken), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2000), r.pass(2000)), http.StatusOK, "")
	e.limited(e.do("GET", r.path("/acl"), nil, r.pass(2000)), protocol.QuotaCalls)
}

// A new pass, a renewal and a revocation reserve no miss
// (Limits.MissesPerMinute): what their signature checks cost is bounded by
// the address's flood budget, which a call spends at the gate before its
// pass is checked (TestANewPassSpendsItsAddresssFloodBudget). So, from one
// address, lookups that find no mailbox past its misses, then passes that
// fail (another server's, one run out), a renewal its checks refuse and a
// revocation that does not verify, leave an honest new pass, renewal and
// revocation taken, while the next lookup that finds nothing is refused.
func TestANewPassReservesNoMiss(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	r, other := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	list := r.path("/messages")
	for range 2 {
		e.want(e.do(http.MethodGet, e.raw().path(""), nil, ""), http.StatusNotFound, protocol.CodeMailboxNotFound)
	}
	e.limited(e.do(http.MethodGet, e.raw().path(""), nil, ""), protocol.QuotaMisses)
	wrongServer := e.passFor(r.signer, r.id.Address(), "elsewhere.example")
	e.clock.Add(-time.Hour)
	runOut := r.pass(1)
	e.clock.Add(time.Hour)
	r.prekey(2, e.clock.Now().Add(2*protocol.MaxPrekeyLifetime), nil) // past what the server takes
	sig, err := protocol.SignRevocation(other.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	forged := protocol.Revocations{Identity: r.id.Document(), Revocation: sig}
	for range 3 {
		e.want(e.do(http.MethodGet, list, nil, wrongServer), http.StatusUnauthorized, protocol.CodeInvalidPass)
		e.want(e.do(http.MethodGet, list, nil, runOut), http.StatusUnauthorized, protocol.CodePassExpired)
		e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1)), http.StatusBadRequest, "")
		e.want(e.do("PUT", r.path("/revocation"), forged, ""), http.StatusBadRequest, protocol.CodeInvalidRevocation)
	}
	e.clock.Add(time.Second)
	e.want(e.do(http.MethodGet, list, nil, r.pass(1)), http.StatusOK, "")
	r.prekey(3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1)), http.StatusOK, "")
	sig, err = protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocation"), protocol.Revocations{Identity: r.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	e.limited(e.do(http.MethodGet, e.raw().path(""), nil, ""), protocol.QuotaMisses)
}

// mailboxSpent names each of s's buckets that holds less than full for key
// at now: every *buckets the Server holds, read from its fields, so a bucket
// added is held too.
func mailboxSpent(s *Server, key string, now time.Time) []string {
	var spent []string
	v := reflect.ValueOf(s).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Type() != reflect.TypeFor[*buckets]() || f.IsNil() {
			continue
		}
		bs := (*buckets)(f.UnsafePointer())
		bs.mu.Lock()
		full, ok := bs.full[key]
		bs.mu.Unlock()
		if ok && full.After(now) {
			spent = append(spent, v.Type().Field(i).Name)
		}
	}
	return spent
}

// A call about mailbox b that b's pass did not make spends none of b's
// budgets (LIMITS.md, rule 5): on every route of routes() that names a
// mailbox, every GET's HEAD too, with each query a route refuses or takes,
// with no pass, one that is no pass, a forged pass of b's, b's pass for
// another server and another mailbox's checked pass; a send to b that
// fails a check; and a send that passes every check and that the store
// refuses, storing nothing (errNotStored), after b's receive is reserved.
// Every budget is on, and each is read from the server's buckets, whatever
// its size.
func TestFailedCallsSpendNothingOfTheMailbox(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	l.RequestBurst, l.RangeRequestBurst, l.MissesPerMinute, l.RangeMissesPerMinute = 0, 0, 0, 0
	l.RegistrationsPerHour, l.RangeRegistrationsPerHour, l.SendsPerMinutePerIP, l.RangeSendsPerMinute = 0, 0, 0, 0
	l.MaxBodiesBeforePass, l.MaxBodiesBeforePassPerRange = 0, 0
	refusing := &failPut{}
	e := newEnv(t, l, func(c *Config) { refusing.Store = c.Store; c.Store = refusing })
	a, b := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	c := e.raw().register(protocol.MaxPrekeyLifetime)
	// b denies a, which spends b's calls; then every budget of b's is full again.
	e.want(e.do("PUT", b.path("/acl"), protocol.ACLDocument{Allow: []string{protocol.AnyAddress}, Deny: []string{a.id.Address().String()}}, b.pass(1)), http.StatusOK, "")
	e.clock.Add(2 * day)
	key := b.id.Address().String()
	full := func(after string) {
		t.Helper()
		if spent := mailboxSpent(e.server, key, e.clock.Now()); len(spent) > 0 {
			t.Errorf("after %s, b's %v are spent", after, spent)
		}
	}
	full("nothing")
	call := func(method, path string, body []byte, pass, ifMatch string) reply {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Host, req.RemoteAddr = e.name(), "10.4.0.2:40000"
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		w := httptest.NewRecorder()
		e.server.Handler().ServeHTTP(w, req)
		return reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
	}
	aPass := a.pass(1)
	e.want(e.do("GET", a.path("/messages"), nil, aPass), http.StatusOK, "") // a's pass, checked
	_, forged := forgedFromPublic(t, e, b.id.Address())
	elsewhere := e.passFor(b.signer, b.id.Address(), "elsewhere.example")
	n := 0
	for _, r := range e.server.routes() {
		method, pattern, _ := strings.Cut(r.pattern, " ")
		if !strings.Contains(pattern, "{address}") {
			continue
		}
		methods := []string{method}
		if method == http.MethodGet {
			methods = append(methods, http.MethodHead)
		}
		paths := []string{strings.NewReplacer("{address}", key, "{id}", strings.Repeat("0", 64)).Replace(pattern)}
		if strings.Contains(pattern, "{id}") {
			paths = append(paths, strings.NewReplacer("{address}", key, "{id}", "zz").Replace(pattern))
		}
		for _, m := range methods {
			for _, path := range paths {
				for _, query := range []string{"", "?nope=1", "?wait=5", "?cursor=x"} {
					for _, pass := range []string{"", "dromas-pass nonsense", forged, elsewhere, aPass} {
						for _, ifMatch := range []string{"", `"nope"`} {
							call(m, path+query, []byte(`{"x":"y"}`), pass, ifMatch)
							n++
						}
					}
				}
			}
		}
	}
	full(fmt.Sprintf("%d calls about b that b did not make", n))
	good := b.sealed(1, sealFor(t, b, 1))
	post := func(q protocol.SendQuery, body []byte, pass string) reply {
		t.Helper()
		return call(http.MethodPost, b.path("/messages")+"?"+q.Encode(), body, pass, "")
	}
	for _, c := range []struct {
		name string
		send func() reply
	}{
		{"no pass", func() reply { return post(good.SendQuery, good.ciphertext, "") }},
		{"a forged pass", func() reply { return post(good.SendQuery, good.ciphertext, forged) }},
		{"no age file", func() reply { return post(good.SendQuery, []byte("not age"), a.pass(1)) }},
		{"another statement", func() reply {
			return post(protocol.SendQuery{Statement: protocol.StatementHash([]byte("x"))}, good.ciphertext, a.pass(1))
		}},
		{"a sender b's ACL denies", func() reply { return post(good.SendQuery, good.ciphertext, a.pass(1)) }},
		{"a write the store refuses", func() reply {
			refusing.mu.Lock()
			refusing.err = fmt.Errorf("%w: injected", errNotStored)
			refusing.mu.Unlock()
			defer func() {
				refusing.mu.Lock()
				refusing.err = nil
				refusing.mu.Unlock()
			}()
			return post(good.SendQuery, good.ciphertext, c.pass(1))
		}},
	} {
		if r := c.send(); r.status < 400 {
			t.Errorf("a send with %s: %d", c.name, r.status)
		}
		full("a send with " + c.name)
	}
}

// forgedFromPublic is a pass for mailbox a made from what GET /v1/<a> serves
// anyone: the mailbox's prekey signature, which carries its current
// certificate, where the pass's signature goes. It passes every check but
// the working key's signature.
func forgedFromPublic(t *testing.T, e *env, a protocol.Address) (protocol.RegisterRequest, string) {
	t.Helper()
	var br protocol.MailboxResponse
	if err := json.Unmarshal(e.do("GET", "/v1/"+a.String(), nil, "").body, &br); err != nil {
		t.Fatal(err)
	}
	na := e.clock.Now().UTC().Truncate(time.Second).Add(4 * time.Minute)
	pass := protocol.PassScheme + ` address="` + a.String() + `", not_after="` + na.Format(protocol.TimeLayout) +
		`", signature="` + base64.StdEncoding.EncodeToString(br.PrekeySignature) + `"`
	return protocol.RegisterRequest{Identity: br.Identity, Prekey: br.Prekey, PrekeySignature: br.PrekeySignature}, pass
}

// retryFinds is each way a registration's identical retry finds its mailbox:
// in its process's memory; read, with its address's registrations left; and
// read by a lookup, with them spent by the mailbox's own registration
// (register).
var retryFinds = map[string]struct {
	spent bool
	with  []func(*Config)
}{
	"a mailbox this process holds":                                            {},
	"a mailbox this process does not hold":                                    {false, []func(*Config){func(c *Config) { c.Store = unknownStore{c.Store} }}},
	"a mailbox this process does not hold, its address's registrations spent": {true, []func(*Config){func(c *Config) { c.Store = unknownStore{c.Store} }}},
}

// A registration of a registered mailbox is answered from its record, before the
// registrations count, whether this process holds the mailbox or reads it, so its
// pass is checked as any call's is (dromas-dev/dromas-server#40): a forged one
// is invalid_pass, each time, as on any other route. A mailbox read where its
// address's registrations are spent is read by a lookup, and its pass checked
// the same (dromas-dev/dromas-client#450 item 2).
func TestAnIdenticalRetrysPassIsChecked(t *testing.T) {
	t.Parallel()
	for name, c := range retryFinds {
		t.Run(name, func(t *testing.T) {
			l := relaxed()
			if c.spent {
				l.RegistrationsPerHour = 1
			}
			e := newEnv(t, l, c.with...)
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			reg, forged := forgedFromPublic(t, e, r.id.Address())
			for range 3 {
				e.want(e.do("PUT", r.path(""), reg, forged), http.StatusUnauthorized, protocol.CodeInvalidPass)
				e.want(e.do("GET", r.path("/acl"), nil, forged), http.StatusUnauthorized, protocol.CodeInvalidPass)
			}
		})
	}
}

// An identical retry of a registration, once its pass is checked, spends one
// of the mailbox's calls, as a renewal's identical retry does: so passes in turn,
// each checked in full, are bounded by the mailbox's budget
// (dromas-dev/dromas-server#40). An honest retry, with the same pass or a
// new one, is taken. So it is whether this process holds the mailbox or reads
// it, with its address's registrations left or spent
// (dromas-dev/dromas-client#450 item 2).
func TestAnIdenticalRetrySpendsTheMailboxsCalls(t *testing.T) {
	t.Parallel()
	for name, c := range retryFinds {
		t.Run(name, func(t *testing.T) {
			l := relaxed()
			l.CallBurst, l.CallRefill = 2, time.Hour
			if c.spent {
				l.RegistrationsPerHour = 1
			}
			e := newEnv(t, l, c.with...)
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			reg, p1 := r.registration(1), r.pass(1)
			e.clock.Add(time.Second)
			p2 := r.pass(1)
			e.want(e.do("PUT", r.path(""), reg, p1), http.StatusOK, "")
			e.want(e.do("PUT", r.path(""), reg, p2), http.StatusOK, "")
			e.limited(e.do("PUT", r.path(""), reg, p1), protocol.QuotaCalls)
			e.limited(e.do("GET", r.path("/acl"), nil, p2), protocol.QuotaCalls)
		})
	}
}

// A reservation that would be refused only because others of its key are in
// flight waits for one to settle: given back, it is taken; kept, it is
// refused.
func TestAReservationWaitsForOthersInFlight(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	bs := newBuckets("test", 1, time.Hour)
	first, ok, _ := bs.reserve(context.Background(), "k", clock)
	if !ok {
		t.Fatal("the first reservation was refused")
	}
	done := make(chan bool)
	go func() {
		_, ok, _ := bs.reserve(context.Background(), "k", clock)
		done <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	first.release(now)
	if !<-done {
		t.Fatal("a reservation waiting on one given back was refused")
	}
	go func() {
		_, ok, _ := bs.reserve(context.Background(), "k", clock)
		done <- ok
	}()
	if <-done {
		t.Fatal("a reservation with no token and none in flight was taken")
	}
}

// Honest calls from one address at once that each reserve a miss and give
// it back, more of them than the address has misses, are all answered: a
// call past the misses waits for those in flight and is taken once they are
// given back (buckets.reserve, LIMITS.md rule 4). The cases are lookups of
// mailboxes that exist, cold, each read from the table, and the restart:
// mailboxes behind one address that each make their first call, a list with
// a pass, to a process that holds nothing of them, as followers paused for
// the same minute come back to a process just started. Control: with no
// wait for the calls in flight, a call past the misses is refused 429
// misses.
func TestColdCallsAtOnceAreAllAnswered(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		n       int
		read    time.Duration
		restart bool
	}{
		{"11 lookups", 11, 20 * time.Millisecond, false},
		{"50 lookups", 50, 2 * time.Millisecond, false},
		{"11 first calls after a restart", 11, 20 * time.Millisecond, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := relaxed()
			l.MissesPerMinute = DefaultLimits().MissesPerMinute
			if c.n <= l.MissesPerMinute {
				t.Fatalf("%d calls are within the %d misses", c.n, l.MissesPerMinute)
			}
			e := newEnv(t, l)
			var bs []*raw
			for range c.n {
				bs = append(bs, e.raw().register(protocol.MaxPrekeyLifetime))
			}
			fed(t, e.store)
			// A process that holds nothing of them, each read taking c.read.
			srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: &ctxMailbox{Store: e.store, d: c.read}, Limits: l, Now: e.clock.Now}).Handler()))
			t.Cleanup(srv.Close)
			e2 := &env{t: t, clock: e.clock, srv: srv}
			reqs := make([]*http.Request, c.n)
			for i, b := range bs {
				path := b.path("")
				if c.restart {
					path = b.path("/messages")
				}
				req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if c.restart {
					req.Header.Set("Authorization", e2.passFor(b.by[1], b.id.Address(), e2.name()))
				}
				reqs[i] = req
			}
			answers := make([]string, c.n)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i, req := range reqs {
				wg.Go(func() {
					<-start
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						answers[i] = err.Error()
						return
					}
					defer func() { _ = resp.Body.Close() }()
					var p struct{ Code string }
					_ = json.NewDecoder(resp.Body).Decode(&p)
					answers[i] = fmt.Sprint(resp.StatusCode, " ", p.Code)
				})
			}
			close(start)
			wg.Wait()
			for i, a := range answers {
				if a != "200 " {
					t.Errorf("call %d of %d at once: %s, want 200", i+1, c.n, a)
				}
			}
		})
	}
}

// slowPut holds each message write, as a store's two writes do, so sends in
// flight at once meet the counts together.
type slowPut struct {
	Store
	d time.Duration
}

func (s slowPut) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	time.Sleep(s.d)
	return s.Store.PutMessage(ctx, mailbox, h, body)
}

// concurrently posts n sends at once from each of froms to to, through a
// server whose message writes each take a while, and returns how many were
// stored.
func concurrently(t *testing.T, e *env, l Limits, to *raw, froms []*raw, n int) int {
	t.Helper()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: slowPut{e.store, 50 * time.Millisecond}, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	e2 := &env{t: t, clock: e.clock, srv: srv}
	type post struct {
		body []byte
		pass string
	}
	var posts []post
	for _, from := range froms {
		pass := e2.passFor(from.by[1], from.id.Address(), e2.name())
		for range n {
			var ct bytes.Buffer
			w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
			_, _ = io.WriteString(w, `{"v":1}`)
			_ = w.Close()
			posts = append(posts, post{ct.Bytes(), pass})
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	stored := 0
	for _, p := range posts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+to.path("/messages?")+to.sealed(1, nil).Encode(), bytes.NewReader(p.body))
			req.Header.Set("Authorization", p.pass)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				mu.Lock()
				stored++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return stored
}

// A sender's daily count is taken before the write: sends in flight at once
// cannot all pass on one count (dromas-dev/dromas-server#4).
func TestDailySendsAreTakenBeforeTheWrite(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.SendsPerDay, l.MailboxCap, l.SendsBurst = 5, 0, 5
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	if stored := concurrently(t, e, l, to, []*raw{from}, 20); stored != 5 {
		t.Fatalf("%d of 20 concurrent sends stored, with 5 a day", stored)
	}
}

// The mailbox cap counts the sends in flight too, so sends made at once cannot
// all pass on the same count (dromas-dev/dromas-server#4): from one sender,
// and from several.
func TestTheMailboxCapCountsSendsInFlight(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = 3
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	if stored := concurrently(t, e, l, to, []*raw{from}, 20); stored != 3 {
		t.Fatalf("%d of 20 concurrent sends from one sender stored, with a mailbox cap of 3", stored)
	}
	l.MailboxCap = 7
	e = newEnv(t, l)
	to = e.raw().register(protocol.MaxPrekeyLifetime)
	froms := []*raw{e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)}
	if stored := concurrently(t, e, l, to, froms, 5); stored != 7 {
		t.Fatalf("%d of 15 concurrent sends stored, with a mailbox cap of 7", stored)
	}
}

// slowMailbox counts reads of mailbox records, and holds each a while, as a read of
// the table does.
type slowMailbox struct {
	Store
	reads *atomic.Int64
}

func (s slowMailbox) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	s.reads.Add(1)
	time.Sleep(50 * time.Millisecond)
	return s.Store.Mailbox(ctx, a)
}

// Lookups of one cold address at once share one read, and only its caller
// is counted for it (dromas-dev/dromas-server#6): twenty lookups of a mailbox
// that does not exist, from an address with one miss to spend, are each
// answered 404, from one read.
func TestLookupsOfOneAddressShareARead(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	var n atomic.Int64
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: slowMailbox{e.store, &n}, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	var nobody protocol.Address
	nobody[0] = 9
	var wg sync.WaitGroup
	codes := make([]int, 20)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/v1/" + nobody.String())
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusNotFound {
			t.Fatalf("lookup %d: %d, want 404 (all: %v)", i, c, codes)
		}
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("%d reads for twenty lookups of one address at once", got)
	}
}

// ctxMailbox is the test store, but its record cache always misses, so that
// every lookup reads, and each read of a mailbox's record waits d or until its
// context ends, as the PostgreSQL backend's statements do.
type ctxMailbox struct {
	Store
	reads atomic.Int64
	d     time.Duration
}

func (s *ctxMailbox) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	s.reads.Add(1)
	select {
	case <-time.After(s.d):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.Store.Mailbox(ctx, a)
}

func (s *ctxMailbox) Known(protocol.Address) (*Mailbox, bool) { return nil, false }

// A lookup's shared read runs apart from the request that leads it
// (dromas-dev/dromas-server#32): a leader whose caller hangs up during
// the read fails none of the lookups waiting on it, each answered from that
// one read.
func TestALeaderWhoHangsUpFailsNoLookup(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	fed(t, e.store)
	st := &ctxMailbox{Store: e.store, d: time.Second}
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: st, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	u := srv.URL + b.path("")
	led := make(chan struct{})
	go func() { // the leader: a caller that hangs up 50 ms into the read
		defer close(led)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	for st.reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	resp, err := http.Get(u) // waits on the leader's read
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	<-led
	if resp.StatusCode != http.StatusOK || st.reads.Load() != 1 {
		t.Fatalf("a lookup waiting on a read whose caller hung up: %d (Retry-After %q), from %d reads; want 200 from 1", resp.StatusCode, resp.Header.Get("Retry-After"), st.reads.Load())
	}
}

// panicStore is the test store, but a read of mailbox's record, a first fetch's
// count and a revocation panic, as a bug in decoding a record would. Memory
// holds nothing of mailbox, so a lookup and a registration of it read.
type panicStore struct {
	Store
	mailbox protocol.Address
}

func (s panicStore) Known(a protocol.Address) (*Mailbox, bool) {
	if a == s.mailbox {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s panicStore) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.mailbox {
		panic("a panic in the read of a mailbox's record")
	}
	return s.Store.Mailbox(ctx, a)
}

func (s panicStore) Holds(context.Context, protocol.Address, [32]byte) (bool, error) {
	panic("a panic in a fetch's read of memory")
}

func (s panicStore) Revoke(context.Context, protocol.Address, *Revocations, Expect) error {
	panic("a panic in a revocation's write")
}

// A reservation is settled, and a shared read finished, however its call
// ends, a panic included (dromas-dev/dromas-server#36): after a panic in
// a lookup's read, a registration's read, under the registrations it
// reserved (dromas-dev/dromas-client#450 item 1), a fetch of a held
// message, which spends a token once memory shows it held (#86), and a raise of
// a revocation of certificates, no reservation is held and no read is in
// flight, and the next lookup of the address is answered.
func TestAPanicSettlesItsReservations(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute, l.DrainBurst, l.DrainRefill, l.CertificateRevocationsPerDay, l.CertificateRevocationsBurst = 10, 10, time.Minute, 10, 10
	l.RegistrationsPerHour = 10
	e := newEnv(t, l)
	victim, owner := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	s := New(Config{Store: panicStore{e.store, victim.id.Address()}, Limits: l, Now: e.clock.Now})
	srv := httptest.NewUnstartedServer(apitest.Handler(t, s.Handler()))
	var panics lockedBuffer
	srv.Config.ErrorLog = log.New(&panics, "", 0) // net/http's report of each panic
	srv.Start()
	t.Cleanup(srv.Close)
	api := &env{t: t, clock: e.clock, srv: srv}
	held := func(sets ...*buckets) (n int) {
		for _, bs := range sets {
			bs.mu.Lock()
			n += len(bs.held)
			bs.mu.Unlock()
		}
		return n
	}
	call := func(method, path string, body any, pass string) {
		t.Helper()
		var r io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			r = bytes.NewReader(j)
		}
		req, _ := http.NewRequest(method, srv.URL+path, r)
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil { // a panic ends the connection
			_ = resp.Body.Close()
		}
	}

	call(http.MethodGet, victim.path(""), nil, "")
	if n := held(s.misses.ip, s.misses.rng); n != 0 {
		t.Errorf("after a panic in a lookup's read: %d miss reservations held", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+victim.path(""), nil)
	if resp, err := http.DefaultClient.Do(req); errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a later lookup of the same address waited on a read that never finishes: %v", err)
	} else if err == nil {
		_ = resp.Body.Close()
	}

	call(http.MethodPut, victim.path(""), victim.registration(1), api.passFor(victim.by[1], victim.id.Address(), api.name()))
	if n := held(s.regs.ip, s.regs.rng); n != 0 {
		t.Errorf("after a panic in a registration's read: %d registration reservations held", n)
	}

	ct := ciphertextTo(t, owner)
	e.want(e.do(http.MethodPost, owner.path("/messages"), owner.sealed(1, ct), victim.pass(1)), http.StatusCreated, "")
	id := sha256.Sum256(ct)
	call(http.MethodGet, owner.path("/messages/"+hex.EncodeToString(id[:])), nil, api.passFor(owner.by[1], owner.id.Address(), api.name()))
	if n := held(s.drained); n != 0 {
		t.Errorf("after a panic in a fetch: %d drain reservations held", n)
	}

	call(http.MethodPut, owner.path("/revocation"), owner.certs(5), "")
	if n := held(s.raises); n != 0 {
		t.Errorf("after a panic in a raise's write: %d reservations held", n)
	}
	if got := panics.String(); strings.Count(got, "http: panic serving") != 5 {
		t.Errorf("%d of the five calls panicked: %s", strings.Count(got, "http: panic serving"), got)
	}
}

// lockedBuffer is a buffer written by the server's goroutines and read by
// the test's: net/http logs a panic before it closes the connection, an
// order the race detector does not see (dromas-dev/dromas-server#73).
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A mailbox takes messages out at a rate of its own (Limits.DrainBurst): every
// fetch of a held message spends the budget, a fetch of one fetched before
// too, and only its own calls spend it. Past it a fetch is
// fetch_rate_limited and the rest waits on the server; a fetch of a message
// it does not hold gives its token back; an account can lift it.
func TestTheDrainBudget(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	for _, body := range []string{"1", "2", "3"} {
		send(t, a, b, body)
	}
	l.DrainBurst, l.DrainRefill = 2, time.Minute
	e2, _ := counted(t, e, l)
	pass := e2.pass(b)
	ids := listOf(t, e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass)).Messages
	if len(ids) != 3 {
		t.Fatalf("listed %d", len(ids))
	}
	fetch := func(id string) reply {
		return e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages/"+id, nil, pass)
	}
	unknown := strings.Repeat("cd", 32)
	e2.want(fetch(unknown), http.StatusNotFound, protocol.CodeMessageNotFound) // given back: not a new message
	e2.want(fetch(ids[0].ID), http.StatusOK, "")
	e2.want(fetch(ids[0].ID), http.StatusOK, "") // fetched before: spends a token too
	r := fetch(ids[1].ID)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeFetchRateLimited)
	if r.header.Get("Retry-After") == "" || !strings.Contains(string(r.body), "waits on the server") {
		t.Fatalf("the third fetch: %s", r.body)
	}
	e.clock.Add(l.DrainRefill)
	e2.want(fetch(ids[1].ID), http.StatusOK, "")

	// An unmetered account's mailbox drains with no budget.
	_, key := accountEnv(t, e, true, 1)
	echo := e.mailbox()
	adopt(t, echo, key)
	for range 3 {
		send(t, a, echo, "to the unmetered mailbox")
	}
	epass := e2.pass(echo)
	for _, m := range listOf(t, e2.do(http.MethodGet, "/v1/"+echo.Address().String()+"/messages", nil, epass)).Messages {
		e2.want(e2.do(http.MethodGet, "/v1/"+echo.Address().String()+"/messages/"+m.ID, nil, epass), http.StatusOK, "")
	}
}

// A number a day and its bucket are set apart (Limits.SendsBurst), as Let's
// Encrypt sets a limit by its burst, count and period: a sender takes the
// whole bucket at once, past it waits one day divided by the number a day,
// and is refused naming that number.
func TestABucketLargerThanItsNumberADay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 2, 5
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	for i := range l.SendsBurst {
		send(t, a, b, fmt.Sprint(i))
	}
	_, err := a.Send(ctx, b.Address(), "past the bucket")
	var ae *client.APIError
	every := 24 * time.Hour / time.Duration(l.SendsPerDay)
	if !errorsAs(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited || ae.Problem.QuotaID != protocol.QuotaSends ||
		ae.Problem.QuotaValue == nil || *ae.Problem.QuotaValue != uint64(l.SendsPerDay) || ae.RetryAfter <= every-time.Minute || ae.RetryAfter > every {
		t.Fatalf("a send past a bucket of %d: %v, want rate_limited sends naming %d a day, due in %v", l.SendsBurst, err, l.SendsPerDay, every)
	}
	e.clock.Add(every)
	send(t, a, b, "one back")
	if _, err := a.Send(ctx, b.Address(), "and no more"); codeOf(err) != protocol.CodeRateLimited {
		t.Fatalf("a second send after one came back: %v, want rate_limited", err)
	}
}

// With the mailbox's calls spent, a fetch or an ack of an id it does not
// hold and a message's HEAD are refused before anything is read (LIMITS.md
// rule 1): none makes a call of the store, the read of its pass included,
// so the spend comes before the read.
func TestASpentMailboxReadsNothingForAMissOrAHead(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	id := send(t, a, b, "held").ID
	l.CallBurst, l.CallRefill = 1, time.Hour
	e2, cs := counted(t, e, l)
	pass := e2.pass(b)
	messages := "/v1/" + b.Address().String() + "/messages/"
	unknown := messages + strings.Repeat("ab", 32)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusNotFound, protocol.CodeMessageNotFound) // the mailbox's one call
	before := cs.calls.Load()
	e2.want(e2.do(http.MethodGet, unknown, nil, pass), http.StatusTooManyRequests, protocol.CodeRateLimited)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusTooManyRequests, protocol.CodeRateLimited)
	if r := e2.head(messages+id, pass); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a message's HEAD with the mailbox's calls spent: %d; want 429", r.StatusCode)
	}
	if n := cs.calls.Load() - before; n != 0 {
		t.Errorf("with the mailbox's calls spent, a fetch and an ack of an id it does not hold and a message's HEAD made %d storage calls; want none", n)
	}
}
