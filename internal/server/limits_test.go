package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// These tests cover the limits on calls that reach storage, and on maps
// that would otherwise grow without bound.

// A key whose bucket is full again is dropped; one still in use is kept.
func TestBucketsDropKeysFullAgain(t *testing.T) {
	t.Parallel()
	t0 := time.Unix(1_700_000_000, 0)
	bs := newBuckets("test", 2, time.Minute)
	for _, k := range []string{"a", "b", "c"} {
		bs.take(k, t0)
	}
	if ok, _ := bs.ready("a", t0); !ok {
		t.Fatal("one of two taken, and not ready")
	}
	if ok, _ := bs.ready("a", t0); !ok {
		t.Fatal("ready took a token")
	}
	bs.take("a", t0)
	if ok, wait := bs.ready("a", t0); ok || wait != time.Minute {
		t.Fatalf("an empty bucket: ready %v, wait %s", ok, wait)
	}
	if ok, wait := bs.take("a", t0); ok || wait != time.Minute {
		t.Fatalf("an empty bucket: took %v, wait %s", ok, wait)
	}
	bs.take("b", t0.Add(90*time.Second)) // still short of full two minutes in
	bs.take("d", t0.Add(2*time.Minute))
	if _, ok := bs.full["b"]; len(bs.full) != 2 || !ok {
		t.Fatalf("holds %d keys, want b and d: %v", len(bs.full), bs.full)
	}
	if ok, _ := bs.take("a", t0.Add(2*time.Minute)); !ok {
		t.Fatal("a dropped key is not a full bucket")
	}
}

// The allowance for list pages after the first follows the mailbox cap and the
// poll rate: two full mailboxes' worth at once, a full mailbox's worth each poll
// interval.
func TestContinuationAllowance(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	pages := (l.MailboxCap + pageSize - 1) / pageSize
	if bs := l.continuations(); bs.n != 2*pages || bs.every != l.PollRefill/time.Duration(pages) {
		t.Fatalf("%d pages, one each %s", bs.n, bs.every)
	}
	l.MailboxCap = 0
	if bs := l.continuations(); bs.n != 2*uncappedPages {
		t.Fatalf("no mailbox cap: %d pages", bs.n)
	}
	l.PollBurst = 0
	if bs := l.continuations(); bs.n != 0 {
		t.Fatal("no poll limit, and a page limit")
	}
}

// counted is a second server on e's store and keys, with its own limits'
// state, whose storage calls are counted.
func counted(t *testing.T, e *env, l Limits) (*env, *countingStore) {
	t.Helper()
	cs := &countingStore{s: e.store}
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: cs, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	return &env{t: t, clock: e.clock, srv: srv}, cs
}

func listOf(t *testing.T, r reply) protocol.MessageList {
	t.Helper()
	var l protocol.MessageList
	if err := json.Unmarshal(r.body, &l); err != nil {
		t.Fatalf("%d %s: %v", r.status, r.body, err)
	}
	return l
}

// A cursor is no way around the poll rate: with nothing after it, a list is
// a poll, answered from memory; with something after it, it is a
// continuation, which has its own allowance.
func TestCursorIsNoWayAroundThePollRate(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = pageSize // a mailbox of one page: two continuations at once, one back each poll interval
	l.PollBurst, l.PollRefill = 3, 50*time.Second
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	e2, cs := counted(t, e, l)
	tok := e2.pass(b)
	list := func(c Cursor) reply {
		return e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages?cursor="+formatCursor(Header{ReceivedAt: c.ReceivedAt, ID: c.ID}), nil, tok)
	}
	start := Cursor{ReceivedAt: time.UnixMilli(0)}
	end := Cursor{ReceivedAt: e.clock.Now().Add(time.Hour)}

	// An empty mailbox: every list with a cursor is a poll.
	for i := range 3 {
		if r := list(start); r.status != http.StatusOK || listOf(t, r).Count != 0 {
			t.Fatalf("poll %d with a cursor: %d %s", i, r.status, r.body)
		}
	}
	e2.want(list(start), http.StatusTooManyRequests, protocol.CodeRateLimited)
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("%d storage calls for lists of an empty mailbox", n)
	}

	// Messages after the cursor, and a cursor this process never handed out: a
	// poll, answered with the page all the same.
	for _, body := range []string{"1", "2", "3"} {
		send(t, a, b, body)
	}
	e.clock.Add(3 * l.PollRefill)
	for i := range 3 {
		r := list(start)
		if got := listOf(t, r); r.status != http.StatusOK || got.Count != 3 || len(got.Messages) != 3 {
			t.Fatalf("made-up cursor %d: %d %s", i, r.status, r.body)
		}
	}
	r := list(start)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if q, _ := r.quota(); q != protocol.QuotaPolls {
		t.Fatalf("a made-up cursor past the polls: %s", r.body)
	}

	// Nothing after the cursor: a poll too, read from memory.
	e.clock.Add(l.PollRefill)
	before := cs.calls.Load()
	r = list(end)
	if got := listOf(t, r); r.status != http.StatusOK || got.Count != 3 || len(got.Messages) != 0 || got.NextCursor != nil {
		t.Fatalf("a cursor past the last message: %d %s", r.status, r.body)
	}
	e2.want(list(end), http.StatusTooManyRequests, protocol.CodeRateLimited)
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls: a list with nothing to return read storage", n-before)
	}
}

// A page after the first is a continuation only with the cursor this process
// handed the mailbox last (dromas-dev/dromas-server#5): a drain's pages come
// from the page allowance, and the same cursor again is a poll.
func TestAContinuationIsTheCursorHandedOutLast(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = 0
	l.PollBurst, l.PollRefill = 2, 50*time.Second
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	for range pageSize + 1 {
		e.want(e.sendTo(to, 1, from, 1), http.StatusCreated, "")
	}
	pass := to.pass(1)
	page := func(cursor string) reply {
		path := to.path("/messages")
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		return e.do(http.MethodGet, path, nil, pass)
	}
	first := listOf(t, page(""))
	if len(first.Messages) != pageSize || first.NextCursor == nil {
		t.Fatalf("the first page: %d messages, next %v", len(first.Messages), first.NextCursor)
	}
	c := *first.NextCursor
	if second := listOf(t, page(c)); len(second.Messages) != 1 || second.NextCursor != nil {
		t.Fatalf("the continuation: %d messages, next %v", len(second.Messages), second.NextCursor)
	}
	e.want(page(c), http.StatusOK, "") // the same cursor again: the mailbox's second poll
	r := page(c)
	e.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if q, _ := r.quota(); q != protocol.QuotaPolls {
		t.Fatalf("a replayed cursor past the polls: %s", r.body)
	}
}

// A fetch or an ack of an id the mailbox does not hold is answered from memory.
func TestUnknownIDsStayInMemory(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	e2, cs := counted(t, e, relaxed())
	tok := e2.pass(b)
	msg := func(method, id string) reply {
		return e2.do(method, "/v1/"+b.Address().String()+"/messages/"+id, nil, tok)
	}
	unknown := strings.Repeat("ab", 32)
	e2.want(msg(http.MethodGet, unknown), http.StatusNotFound, protocol.CodeNoSuchMessage)
	e2.want(msg(http.MethodDelete, unknown), http.StatusNotFound, protocol.CodeNoSuchMessage)
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("%d storage calls for an id the mailbox does not hold", n)
	}
	id := send(t, a, b, "x").ID
	e2.want(msg(http.MethodGet, id), http.StatusOK, "")
	e2.want(msg(http.MethodDelete, id), http.StatusNoContent, "")
	if n := cs.calls.Load(); n != 2 {
		t.Fatalf("%d storage calls for a fetch and an ack", n)
	}
	e2.want(msg(http.MethodGet, id), http.StatusNotFound, protocol.CodeNoSuchMessage)
	e2.want(msg(http.MethodDelete, id), http.StatusNotFound, protocol.CodeNoSuchMessage)
	if n := cs.calls.Load(); n != 2 {
		t.Fatalf("%d storage calls: an acked id reached storage again", n)
	}
}

// A read of the mailboxes table that finds no mailbox is counted against the address
// that asked, and past its count that address is refused before another such
// read. A mailbox memory holds is no miss: it is answered whatever the count.
func TestMissesPerIP(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	b := e.mailbox()
	l.MissesPerMinute = 2
	e2, cs := counted(t, e, l)
	nobody := func(i byte) protocol.Address {
		var a protocol.Address
		a[0], a[1] = 1, i
		return a
	}
	read := func(a protocol.Address) reply {
		return e2.do(http.MethodGet, "/v1/"+a.String(), nil, "")
	}
	for range 3 {
		e2.want(read(b.Address()), http.StatusOK, "")
	}
	pass := e2.pass(b)
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass); r.status != http.StatusOK { // a pass this process now remembers
		t.Fatalf("the owner's poll: %d %s", r.status, r.body)
	}
	e2.want(read(nobody(1)), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e2.want(e2.do(http.MethodGet, "/v1/"+nobody(2).String()+"/messages", nil, e2.pass(b)), http.StatusNotFound, protocol.CodeNoSuchMailbox) // a call with a pass, naming no mailbox
	before := cs.calls.Load()
	r := read(nobody(3))
	e2.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if !strings.Contains(string(r.body), "named no mailbox") || r.header.Get("Retry-After") != "30" {
		t.Fatalf("a third miss in a minute: Retry-After %q, %s", r.header.Get("Retry-After"), r.body)
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls from an address past its misses", n-before)
	}
	for range 3 {
		e2.want(read(b.Address()), http.StatusOK, "") // a live mailbox, held in memory: not a miss
	}
	// A pass the process remembers is answered from memory, whatever its
	// address has spent; a new one costs signature checks, and an address
	// past its count is refused before them.
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass); r.status != http.StatusOK {
		t.Fatalf("the owner's poll with its pass remembered: %d %s", r.status, r.body)
	}
	// So is that pass in another header a server reads as the same
	// credentials (PROTOCOL.md §8, RFC 9110 §11): it is remembered by the one
	// form a client writes, so another header of it costs no check, and the
	// address past its count is no bar.
	for _, respelled := range []string{
		strings.Replace(pass, "dromas-pass ", "DROMAS-PASS ", 1),
		strings.ReplaceAll(pass, `", `, `" ,  `),
	} {
		if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, respelled); r.status != http.StatusOK {
			t.Fatalf("the owner's poll with its pass remembered, written another way: %d %s", r.status, r.body)
		}
	}
	e.clock.Add(time.Second)
	e2.want(e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e2.pass(b)), http.StatusTooManyRequests, protocol.CodeRateLimited)
	e.clock.Add(-time.Second)
	e.clock.Add(30 * time.Second) // one back
	e2.want(read(nobody(4)), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e2.want(read(nobody(5)), http.StatusTooManyRequests, protocol.CodeRateLimited)
}

// An address at its count of misses still makes a mailbox and uses it: a
// registration reads no record, and the new mailbox's record is in memory from
// then on, so its first poll is no read that could miss.
func TestANewMailboxIsUsedWhateverItsAddressMissed(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	var nobody protocol.Address
	nobody[0] = 2
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	nobody[1] = 1
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	b := e.mailbox()
	if r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e.pass(b)); r.status != http.StatusOK {
		t.Fatalf("the new mailbox's poll: %d %s", r.status, r.body)
	}
}

// A missing mailbox that memory remembers is answered from memory: never refused,
// never counted, and no call to storage. Only the store on AWS remembers one.
func TestARememberedMissIsFree(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	l := relaxed()
	l.MissesPerMinute = 1
	e2, cs := counted(t, e, l)
	nobody := e.raw().id.Address()
	read := func(a protocol.Address) reply {
		return e2.do(http.MethodGet, "/v1/"+a.String(), nil, "")
	}
	e2.want(read(nobody), http.StatusNotFound, protocol.CodeNoSuchMailbox) // the read, and the address's one miss
	before := cs.calls.Load()
	for range 5 {
		e2.want(read(nobody), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for a mailbox remembered as missing", n-before)
	}
	e2.want(read(e.raw().id.Address()), http.StatusTooManyRequests, protocol.CodeRateLimited) // another address needs a read
}

// A message is fetched once and kept. Its first fetch is never limited; a
// fetch of one already fetched takes from the mailbox's allowance for catching up
// after a failure, which polls and first fetches never touch.
func TestAFetchedMessageIsFetchedAgainFromAnAllowance(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	l := relaxed()
	l.PollBurst, l.PollRefill = 2, time.Minute
	e2, cs := counted(t, e, l)
	tok := e2.pass(b)
	msg := func(method, id string) reply {
		return e2.do(method, "/v1/"+b.Address().String()+"/messages/"+id, nil, tok)
	}
	id1, id2 := send(t, a, b, "one").ID, send(t, a, b, "two").ID
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id2), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "") // again: one of the two at once
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "") // the other
	before := cs.calls.Load()
	r := msg(http.MethodGet, id1)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeRefetchSpent)
	if !strings.Contains(string(r.body), "fetched before") || r.header.Get("Retry-After") != "60" {
		t.Fatalf("a fetch past the allowance: Retry-After %q, %s", r.header.Get("Retry-After"), r.body)
	}
	e2.want(msg(http.MethodGet, id2), http.StatusTooManyRequests, protocol.CodeRefetchSpent) // the allowance is the mailbox's
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for fetches past the allowance", n-before)
	}
	for range 2 { // the polls are another allowance, untouched
		if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tok); r.status != http.StatusOK {
			t.Fatalf("a poll: %d %s", r.status, r.body)
		}
	}
	id3 := send(t, a, b, "three").ID
	e2.want(msg(http.MethodGet, id3), http.StatusOK, "") // a first fetch is never limited
	e2.want(msg(http.MethodGet, id3), http.StatusTooManyRequests, protocol.CodeRefetchSpent)
	e.clock.Add(time.Minute) // one back
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id1), http.StatusTooManyRequests, protocol.CodeRefetchSpent)
	e2.want(msg(http.MethodDelete, id1), http.StatusNoContent, "") // an ack is never limited
	e2.want(msg(http.MethodGet, id1), http.StatusNotFound, protocol.CodeNoSuchMessage)
}

// The count of fetches lives in the message's mark and stops at 255.
func TestIndexCountsFetches(t *testing.T) {
	t.Parallel()
	x := newIndex()
	var mailbox protocol.Address
	mailbox[0] = 3
	now := uint64(1000)
	if err := x.ensure(context.Background(), mailbox, func() (mailboxRead, error) {
		return mailboxRead{exists: true, marks: []mark{{tag: 7, id: 7, exp: now + 1}, {tag: 8, id: 8, exp: now + 1}}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if held, again := x.fetched(mailbox, 7, now); !held || again {
		t.Fatalf("a first fetch: held %v, again %v", held, again)
	}
	for range 300 {
		if held, again := x.fetched(mailbox, 7, now); !held || !again {
			t.Fatalf("a later fetch: held %v, again %v", held, again)
		}
	}
	if held, again := x.fetched(mailbox, 8, now); !held || again {
		t.Fatalf("another message's first fetch: held %v, again %v", held, again)
	}
	if held, _ := x.fetched(mailbox, 9, now); held {
		t.Fatal("a message the mailbox does not hold")
	}
	if held, _ := x.fetched(mailbox, 7, now+1); held {
		t.Fatal("an expired message")
	}
}

// The server remembers the pass each mailbox showed last, and nothing else of
// it: the same pass is taken again until it runs out, only as checked under
// the certificate that is still the mailbox's, and an entry goes once its pass
// has run out.
func TestPassesAreRememberedUntilTheyRunOut(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var a1, a2 protocol.Address
	a1[0], a2[0] = 1, 2
	sum, cert := [32]byte{1}, [32]byte{2}
	ps := newPasses()
	if ps.has(a1, sum, cert, now) {
		t.Fatal("a pass never shown is remembered")
	}
	ps.keep(a1, seenPass{sum: sum, signer: cert, until: now.Add(protocol.PassLifetime)}, now)
	if !ps.has(a1, sum, cert, now) || !ps.has(a1, sum, cert, now.Add(protocol.PassLifetime-time.Second)) {
		t.Fatal("a pass that was checked is not remembered")
	}
	for name, got := range map[string]bool{
		"run out":             ps.has(a1, sum, cert, now.Add(protocol.PassLifetime)),
		"another pass":        ps.has(a1, [32]byte{9}, cert, now),
		"another certificate": ps.has(a1, sum, [32]byte{9}, now),
		"another mailbox":     ps.has(a2, sum, cert, now),
	} {
		if got {
			t.Errorf("%s: taken as the pass remembered", name)
		}
	}
	// A mailbox's next pass replaces its last.
	next := [32]byte{3}
	ps.keep(a1, seenPass{sum: next, signer: cert, until: now.Add(2 * protocol.PassLifetime)}, now)
	if ps.has(a1, sum, cert, now) || !ps.has(a1, next, cert, now) || len(ps.seen) != 1 {
		t.Fatalf("after a second pass: %d held", len(ps.seen))
	}
	// Passes that have run out go when the next is kept after a sweep is due.
	later := now.Add(protocol.MaxPassLifetime)
	ps.keep(a2, seenPass{sum: sum, signer: cert, until: later.Add(protocol.PassLifetime)}, later)
	if len(ps.seen) != 1 || !ps.has(a2, sum, cert, later) {
		t.Fatalf("%d held after a sweep, want only the pass still good", len(ps.seen))
	}
}

func TestMissCache(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var a1, a2, a3 protocol.Address
	a1[1], a2[1], a3[1] = 1, 2, 3 // one shard
	c := newMailboxCache(2)
	miss := func(a protocol.Address) { c.missed(a, c.begin(a), now) }
	has := func(a protocol.Address, at time.Time) bool { return c.missingAt(a, at) }
	if has(a1, now) {
		t.Fatal("missing before any read")
	}
	miss(a1)
	if !has(a1, now) || !has(a1, now.Add(missTTL-time.Second)) {
		t.Fatal("a miss is not remembered")
	}
	if has(a1, now.Add(missTTL)) {
		t.Fatal("remembered past its time")
	}
	miss(a1)
	c.write(a1, evicted[*Mailbox])
	if has(a1, now) {
		t.Fatal("still missing after a write")
	}
	// A read that began before a write must not record its miss after it.
	tok := c.begin(a1)
	c.write(a2, evicted[*Mailbox])
	c.missed(a1, tok, now)
	if has(a1, now) {
		t.Fatal("a miss read before a write was recorded after it")
	}
	for _, a := range []protocol.Address{a1, a2, a3} {
		miss(a)
	}
	if n := len(c.missing.until); n > 2 || !has(a3, now) {
		t.Fatalf("holds %d, over its size of 2, or not the newest", n)
	}
	off := newMailboxCache(0)
	off.missed(a1, off.begin(a1), now)
	if off.missingAt(a1, now) {
		t.Fatal("size 0 remembered a miss")
	}
}

// On DynamoDB, a mailbox a read did not find is remembered as missing until it
// is written.
func TestMissingMailboxIsRememberedUntilItIsWritten(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	ctx := context.Background()
	r := e.raw()
	a := r.id.Address()
	if _, err := s.Mailbox(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unregistered mailbox: %v", err)
	}
	if !s.cache.missingAt(a, e.clock.Now()) {
		t.Fatal("the miss was not remembered")
	}
	r.prekey(1, e.clock.Now().Add(24*time.Hour), nil)
	e.want(e.do(http.MethodPut, r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
	if b, err := s.Mailbox(ctx, a); err != nil || b.Addr != a {
		t.Fatalf("the mailbox, once registered: %v", err)
	}
}

// A refusal's detail names no value that no member carries (PROTOCOL.md §11.3):
// the polls' refusal says no rate, which is the server's to set (--poll-after,
// --poll-burst, --poll-refill), and the wait is in Retry-After (#65).
func TestThePollsRefusalNamesNoRateItDoesNotCarry(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill, l.PollAfter = 1, 10*time.Second, 10 // a server that asks for a poll every 10 seconds
	e := newEnv(t, l)
	b := e.mailbox()
	path := "/v1/" + b.Address().String() + "/messages"
	e.want(e.do("GET", path, nil, e.pass(b)), http.StatusOK, "")
	got := e.do("GET", path, nil, e.pass(b))
	e.want(got, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if q, _ := got.quota(); q != protocol.QuotaPolls {
		t.Fatalf("the second poll: %s", got.body)
	}
	if d := got.problem().Detail; strings.Contains(d, "minute") || strings.Contains(d, "second") {
		t.Errorf("the polls' refusal names a rate, which no member carries: %q", d)
	}
}
