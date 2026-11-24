package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// These tests cover the limits on calls that reach storage, and on maps
// that would otherwise grow without bound.

// A bucket set resized while it is taken from, as a reload of the limits
// file does, reads its size under the lock the resize writes it under: the
// race detector (go test -race) sees any read outside it.
func TestABucketResizedWhileItIsTakenFrom(t *testing.T) {
	t.Parallel()
	bs := newBuckets("test", 10, time.Millisecond)
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 2000 {
			bs.resize(10+i%2, time.Millisecond)
		}
	})
	wg.Go(func() {
		for range 2000 {
			bs.take("k", now)
		}
	})
	wg.Wait()
}

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

// A list is the mailbox's oldest page and its count, with no cursor
// (PROTOCOL.md §11.11): past a page, the page is the oldest pageSize
// messages, oldest first, and each list is a poll.
func TestAListIsTheOldestPage(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = 0
	l.PollBurst, l.PollRefill = 2, 50*time.Second
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	var newest string
	for range pageSize + 1 {
		newest = formatTime(e.clock.Now())
		e.want(e.sendTo(to, 1, from, 1), http.StatusCreated, "")
		e.clock.Add(time.Second)
	}
	pass := to.pass(1)
	page := listOf(t, e.do(http.MethodGet, to.path("/messages"), nil, pass))
	if page.Count != pageSize+1 || len(page.Messages) != pageSize {
		t.Fatalf("a list of %d messages: count %d, a page of %d", pageSize+1, page.Count, len(page.Messages))
	}
	for i, m := range page.Messages {
		if m.ReceivedAt >= newest || i > 0 && m.ReceivedAt < page.Messages[i-1].ReceivedAt {
			t.Fatalf("the page is not the oldest, oldest first: %+v", page.Messages)
		}
	}
	e.want(e.do(http.MethodGet, to.path("/messages"), nil, pass), http.StatusOK, "")
	e.limited(e.do(http.MethodGet, to.path("/messages"), nil, pass), protocol.QuotaPolls)
}

// A fetch or an ack of an id the mailbox does not hold is answered from
// memory, once one read shows its pass holds (Store.PassHeld): no row is
// read for it.
func TestAnUnknownIDReadsOnlyItsPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	steady(t, e.store, b.Address())
	e2, cs := counted(t, e, relaxed())
	tok := e2.pass(b)
	msg := func(method, id string) reply {
		return e2.do(method, "/v1/"+b.Address().String()+"/messages/"+id, nil, tok)
	}
	unknown := strings.Repeat("ab", 32)
	e2.want(msg(http.MethodGet, unknown), http.StatusNotFound, protocol.CodeMessageNotFound)
	e2.want(msg(http.MethodDelete, unknown), http.StatusNotFound, protocol.CodeMessageNotFound)
	if n := cs.calls.Load(); n != 2 {
		t.Fatalf("%d storage calls for a fetch and an ack of an id the mailbox does not hold; want 2, a read of the pass each", n)
	}
	id := send(t, a, b, "x").ID
	e2.want(msg(http.MethodGet, id), http.StatusOK, "")
	e2.want(msg(http.MethodDelete, id), http.StatusNoContent, "")
	if n := cs.calls.Load(); n != 4 {
		t.Fatalf("%d storage calls for a fetch and an ack", n-2)
	}
	e2.want(msg(http.MethodGet, id), http.StatusNotFound, protocol.CodeMessageNotFound)
	e2.want(msg(http.MethodDelete, id), http.StatusNotFound, protocol.CodeMessageNotFound)
	if n := cs.calls.Load(); n != 6 {
		t.Fatalf("%d storage calls for a fetch and an ack of an acked id; want 2, a read of the pass each", n-4)
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
	e2.want(read(nobody(1)), http.StatusNotFound, protocol.CodeMailboxNotFound)
	e2.want(e2.do(http.MethodGet, "/v1/"+nobody(2).String()+"/messages", nil, e2.pass(b)), http.StatusNotFound, protocol.CodeMailboxNotFound) // a call with a pass, naming no mailbox
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
	// address has spent, and a new one, of a mailbox memory holds, reserves
	// no miss (TestANewPassReservesNoMiss).
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
	e2.want(e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e2.pass(b)), http.StatusOK, "")
	e.clock.Add(-time.Second)
	e.clock.Add(30 * time.Second) // one back
	e2.want(read(nobody(4)), http.StatusNotFound, protocol.CodeMailboxNotFound)
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
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusNotFound, protocol.CodeMailboxNotFound)
	nobody[1] = 1
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	b := e.mailbox()
	if r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e.pass(b)); r.status != http.StatusOK {
		t.Fatalf("the new mailbox's poll: %d %s", r.status, r.body)
	}
}

// A missing mailbox that memory remembers is answered from memory: never refused,
// never counted, and no call to storage. Only the store on PostgreSQL
// remembers one.
func TestARememberedMissIsFree(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	l := relaxed()
	l.MissesPerMinute = 1
	var e2 *env
	var cs *countingStore
	var nobody protocol.Address
	read := func(a protocol.Address) reply {
		return e2.do(http.MethodGet, "/v1/"+a.String(), nil, "")
	}
	rememberedMiss(t, s, func() protocol.Address {
		e2, cs = counted(t, e, l) // a server of its own each try, with limits of its own
		nobody = e.raw().id.Address()
		e2.want(read(nobody), http.StatusNotFound, protocol.CodeMailboxNotFound) // the read, and its caller's one miss
		return nobody
	})
	before := cs.calls.Load()
	for range 5 {
		e2.want(read(nobody), http.StatusNotFound, protocol.CodeMailboxNotFound)
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for a mailbox remembered as missing", n-before)
	}
	e2.want(read(e.raw().id.Address()), http.StatusTooManyRequests, protocol.CodeRateLimited) // another address needs a read
}

// Every fetch of a held message spends the mailbox's budget of messages
// taken out, a fetch of one fetched before among them; a fetch past it
// reads nothing of storage, the polls are a budget of their own, and an ack
// is never limited.
func TestEveryFetchSpendsTheBudgetOfMessagesTakenOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	l := relaxed()
	l.DrainBurst, l.DrainRefill = 3, time.Minute
	l.PollBurst, l.PollRefill = 2, time.Minute
	e2, cs := counted(t, e, l)
	tok := e2.pass(b)
	msg := func(method, id string) reply {
		return e2.do(method, "/v1/"+b.Address().String()+"/messages/"+id, nil, tok)
	}
	id1, id2 := send(t, a, b, "one").ID, send(t, a, b, "two").ID
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id2), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "") // fetched before: the third token
	before := cs.calls.Load()
	r := msg(http.MethodGet, id2)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeFetchRateLimited)
	if r.header.Get("Retry-After") != "60" {
		t.Fatalf("a fetch past the budget: Retry-After %q, %s", r.header.Get("Retry-After"), r.body)
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for a fetch past the budget", n-before)
	}
	for range 2 { // the polls are another budget, untouched
		if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tok); r.status != http.StatusOK {
			t.Fatalf("a poll: %d %s", r.status, r.body)
		}
	}
	e.clock.Add(l.DrainRefill) // one back
	e2.want(msg(http.MethodGet, id1), http.StatusOK, "")
	e2.want(msg(http.MethodGet, id1), http.StatusTooManyRequests, protocol.CodeFetchRateLimited)
	e2.want(msg(http.MethodDelete, id1), http.StatusNoContent, "") // an ack is never limited
	e2.want(msg(http.MethodGet, id1), http.StatusNotFound, protocol.CodeMessageNotFound)
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
	ps.keep(a1, seenPass{sum: next, signer: cert, until: now.Add(protocol.MaxPassLifetime)}, now) // as far ahead as a pass may run
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

// missTries is how many fresh unregistered addresses a test of a remembered
// miss reads before it fails (rememberedMiss).
const missTries = 5

// rememberedMiss runs try, which reads a fresh unregistered address and
// returns it, until memory s remembers that address's miss. Every
// sharedEnv store follows the run's whole schema on its feed, so another
// test's write, applied to the address's cache shard while its read runs,
// keeps that read's miss out, as recCache.missed is made to
// (TestAMissReadAcrossAWriteToItsShardIsNotRemembered); a race on every try
// fails the test.
func rememberedMiss(t *testing.T, s *Memory, try func() protocol.Address) {
	t.Helper()
	for range missTries {
		if a := try(); s.cache.missingAt(a, s.now()) {
			return
		}
	}
	t.Fatalf("in %d reads, each of a fresh unregistered address, no miss was remembered", missTries)
}

// On PostgreSQL, a mailbox a read did not find is remembered as missing until
// it is written.
func TestMissingMailboxIsRememberedUntilItIsWritten(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	ctx := context.Background()
	var r *raw
	rememberedMiss(t, s, func() protocol.Address {
		r = e.raw()
		if _, err := s.Mailbox(ctx, r.id.Address()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unregistered mailbox: %v", err)
		}
		return r.id.Address()
	})
	a := r.id.Address()
	r.prekey(1, e.clock.Now().Add(24*time.Hour), nil)
	e.want(e.do(http.MethodPut, r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
	if b, err := s.Mailbox(ctx, a); err != nil || b.Addr != a {
		t.Fatalf("the mailbox, once registered: %v", err)
	}
}

// readHeld is a backend whose read of an address waits, once it has begun,
// until the test releases it.
type readHeld struct {
	Backend
	reading, release chan struct{}
}

func (b *readHeld) ReadAddress(ctx context.Context, a protocol.Address) (*Mailbox, *Revocations, error) {
	close(b.reading)
	<-b.release
	return b.Backend.ReadAddress(ctx, a)
}

// A read that finds no mailbox remembers no miss where a write to its
// address's cache shard was counted while it ran (recCache.missed): the
// write may be of the address, its record made after the read, and the miss
// would hide it. Here the racing write is the feed's deletion of another
// address's record in the same shard, applied while the read is held.
// Control: one in another shard keeps nothing out.
func TestAMissReadAcrossAWriteToItsShardIsNotRemembered(t *testing.T) {
	t.Parallel()
	var a protocol.Address
	a[0], a[1] = 7, 1
	for name, c := range map[string]struct {
		shard      byte
		remembered bool
	}{
		"a write to its shard":              {7, false},
		"control: a write to another shard": {8, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := newMemory(nil, 10, nil, nil)
			b := &readHeld{Backend: newMemBackend(m.clock), reading: make(chan struct{}), release: make(chan struct{})}
			m.backend = b
			done := make(chan error, 1)
			go func() {
				_, err := m.Mailbox(context.Background(), a)
				done <- err
			}()
			<-b.reading
			var other protocol.Address
			other[0] = c.shard
			m.apply(Change{Kind: RecordChange, Addr: other, Gone: true})
			close(b.release)
			if err := <-done; !errors.Is(err, ErrNotFound) {
				t.Fatalf("an unregistered mailbox: %v", err)
			}
			if got := m.cache.missingAt(a, m.now()); got != c.remembered {
				t.Fatalf("the miss remembered %v, want %v", got, c.remembered)
			}
		})
	}
}

// A refusal's detail names no value that no member carries (PROTOCOL.md §11.3):
// the polls' refusal says no rate, which is the server's to set (poll_after,
// poll_burst, poll_refill), and the wait is in Retry-After (#65).
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
