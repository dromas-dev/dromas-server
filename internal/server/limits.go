package server

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Limits are the server's numbers. Decided ones are marked; the rest are
// tunables, and a zero turns that limit off.
type Limits struct {
	MaxSize        int           // the cap on a ciphertext, in bytes, and what a send reads of its body; nothing may depend on its value
	MailboxCap     int           // total per mailbox, a storage ceiling [tunable]
	SendsPerDay    int           // per sender, a number a day: that many at once, one back each day divided by it (decided: 20)
	PollBurst      int           // polls a mailbox may make at once (decided: 10); also the fetches of messages already fetched
	PollRefill     time.Duration // one more poll each (decided: 50 s; once a minute is stated); also one more such fetch
	PollAfter      int           // seconds, told to clients (decided: 60)
	MaxWait        time.Duration // the longest a list is held, whatever its wait asks (PROTOCOL.md §11.11) [tunable]
	MaxHeldLists   int           // lists this process holds at once; past it a held list is answered 503 (0: none held) [tunable]
	AccountMaxSize int           // the most an account lifts MaxSize to, so what a send reads first; up to MaxSize, nothing
	RenewalsPerDay int           // prekey renewals per mailbox, a number a day as SendsPerDay (decided: 10), so no mailbox can spend the mailboxes table's write capacity
	RetiredKept    int           // retired prekeys a mailbox record keeps for the new-key rule, newest first (decided: 10), so a record stays small

	RegistrationsPerHour      int // per IPv4 address or IPv6 /64 [tunable]
	RangeRegistrationsPerHour int // per IPv6 /48, beside the /64's (decided: 500, Let's Encrypt's ratio of the two, until measured)
	SendsPerMinutePerIP       int // the pre-auth send rate per IP [tunable]
	MissesPerMinute           int // per IP: reads of the mailboxes table that find no mailbox, and checks that fail (decided: 10 for now)

	// Requests is the flood budget of an IPv4 address or IPv6 /64: every call
	// with no pass and every request no route matches (decided: 100 at once,
	// 50 a second).
	RequestBurst  int
	RequestRefill time.Duration

	// Budgets: a burst at once and one more each refill (LIMITS.md).
	ReceiveBurst                 int           // per mailbox: new messages it takes, from all senders together (decided: 50, on, and never off: ReceiveCeiling)
	ReceiveRefill                time.Duration // (decided: 6 s, ten a minute; never shorter than ReceiveCeiling, which an account lifts it to)
	DrainBurst                   int           // per mailbox: its first fetches of held messages, spent only by its own calls (decided: 50, on); an account lifts it
	DrainRefill                  time.Duration // (decided: 6 s, ten a minute)
	CallBurst                    int           // per mailbox: its calls with its pass that no other budget counts [tunable]; an account lifts it
	CallRefill                   time.Duration // [tunable]
	CertificatesPerDay           int           // per mailbox, a number a day: renewals under a later certificate, but for one that replaces a revoked certificate (decided: 10, as renewals)
	CertificateRevocationsPerDay int           // per mailbox, a number a day: raises of its revocation of certificates (decided: a count of its own, apart from CertificatesPerDay; 10, as that one) [tunable]

	// MaxCertificateLifetime is the longest a certificate the server takes
	// when it first takes one may run, its valid-before less its valid-after
	// (PROTOCOL.md §11.7), in whole seconds: served as
	// max_certificate_lifetime in the server's document (§11.18). A renewal
	// under the mailbox's current certificate is not held to it. It must be
	// above protocol.TTL and protocol.MaxSkew together, or dromas-server
	// serve does not start: a client signs no message under a certificate
	// with the TTL or less left, and dates one the hour back (decided: 45 days
	// and the hour).
	MaxCertificateLifetime time.Duration

	// ACLEntries is the most entries a mailbox's ACL holds, its two lists
	// together [tunable]: a mailbox's record, with its ACL, is held in the mailbox
	// cache, so this bounds what one record costs memory there. Never off,
	// and at most protocol.MaxACLEntries: dromas-server serve does not start
	// otherwise.
	ACLEntries int

	// How long a body may take: BodyTimeout, and one second more for each
	// BodyMinRate bytes its handler reads, as Apache's RequestReadTimeout
	// counts; each write of a response the same, for the bytes of it already
	// written. A body that stops coming is cut off after BodyTimeout. What the
	// server drains of a body after its handler has what the handler's reads
	// left, and the answer's time runs from the end of the drain (paced). It
	// is also the longest a send waits for the one large read.
	BodyTimeout time.Duration // [tunable]
	BodyMinRate int           // bytes a second [tunable]

	// HeadBytes is the most of a request's head, its request line and its
	// headers, that the server reads (http.Server.MaxHeaderBytes): what the
	// longest call needs, a pass of protocol.MaxPassAuthorization bytes
	// with the request line and the other headers a client and a proxy in
	// front of it send, and no more (decided: least need). Its default
	// follows the longest pass (headBytes).
	// A head is read before any count, since the address a call is counted
	// by may be one of its headers (LIMITS.md, rule 1).
	HeadBytes int
	// HeadTimeout is how long a request's head may take to arrive
	// (http.Server.ReadHeaderTimeout), before any handler sees it.
	HeadTimeout time.Duration
}

// DefaultLimits are the decided numbers, and the proposed values of the
// tunables that have one. Tunables with no proposed value are off.
func DefaultLimits() Limits {
	return Limits{
		MaxSize:                      64 << 10,
		MailboxCap:                   1000,
		SendsPerDay:                  20,
		PollBurst:                    10,
		PollRefill:                   50 * time.Second,
		PollAfter:                    60,
		MaxWait:                      5 * time.Minute,
		MaxHeldLists:                 50_000,
		RenewalsPerDay:               10,
		RetiredKept:                  10,
		RegistrationsPerHour:         10,
		RangeRegistrationsPerHour:    500,
		MissesPerMinute:              10,
		RequestBurst:                 100,
		RequestRefill:                20 * time.Millisecond,
		ReceiveBurst:                 50,
		ReceiveRefill:                6 * time.Second,
		DrainBurst:                   50,
		DrainRefill:                  6 * time.Second,
		CallBurst:                    50,
		CallRefill:                   6 * time.Second,
		CertificatesPerDay:           10,
		CertificateRevocationsPerDay: 10,
		MaxCertificateLifetime:       45*24*time.Hour + protocol.MaxSkew,
		ACLEntries:                   500,
		BodyTimeout:                  20 * time.Second,
		BodyMinRate:                  500,
		HeadBytes:                    headBytes(),
		HeadTimeout:                  10 * time.Second,
	}
}

// maxCertificate is MaxCertificateLifetime in the whole seconds the
// server's document serves, which is what a certificate is held to.
func (l Limits) maxCertificate() uint64 {
	return uint64(max(l.MaxCertificateLifetime, 0) / time.Second)
}

// ceiling is the largest ciphertext any sender may send.
func (l Limits) ceiling() int { return max(l.MaxSize, l.AccountMaxSize) }

// ReceiveCeiling is the shortest refill of any mailbox's budget of new messages: no
// mailbox takes new messages faster than one each, ten a second, whatever its account
// lifts, and dromas-server serve does not start with flags that would (decided).
// A mailbox's messages are one item collection of the messages
// table, which its LSI holds to 10 GB on one partition, and every message
// leaves an item there until it expires (ARCHITECTURE.md § Storage).
const ReceiveCeiling = time.Second / 10

// liftedReceives is the refill of new messages an account lifts a mailbox's to.
func (l Limits) liftedReceives() time.Duration { return min(l.ReceiveRefill, ReceiveCeiling) }

// uncappedPages is how many list pages a mailbox is taken to hold when no mailbox
// cap bounds it.
const uncappedPages = 1000

// continuations is the allowance for list pages after the first, per mailbox. A
// page after the first is not a poll (PROTOCOL.md §11.11), so it has its own:
// two full mailboxes' worth of pages at once, and a full mailbox's worth back each
// poll interval. A drain's pages are never refused (its fetches may be paced:
// Limits.DrainBurst), and a cursor is no way around the poll rate. With no
// poll limit there is none.
func (l Limits) continuations() *buckets {
	if l.PollBurst == 0 || l.PollRefill <= 0 {
		return newBuckets(string(protocol.QuotaPages), 0, 0)
	}
	pages := (l.MailboxCap + pageSize - 1) / pageSize
	if l.MailboxCap == 0 {
		pages = uncappedPages
	}
	return newBuckets(string(protocol.QuotaPages), 2*pages, l.PollRefill/time.Duration(pages))
}

// buckets is a set of token buckets by key: n tokens, one back each
// interval. A key's bucket starts full, on its first use and after a
// restart. Each is kept as the time it is full again (the GCRA form of a
// token bucket), in whole durations, so no rounding refuses a token that is
// due. A key whose bucket is full again is the same as no key, and is
// dropped (prune).
type buckets struct {
	// name is the limit's: the quota a rate_limited names, or the code its
	// refusal has of its own.
	name  string
	mu    sync.Mutex
	n     int
	every time.Duration
	full  map[string]time.Time
	sweep time.Time // when prune next runs
	// held counts each key's reservations not yet kept or released, and
	// settled is closed and replaced each time one is (reserve).
	held    map[string]int
	settled chan struct{}
	// m counts each take (Metrics.limit); nil counts nothing.
	m *Metrics
}

// newBuckets is buckets of n, refilled one every interval, for the limit
// named name: the quota a rate_limited names, or the code its refusal has of
// its own.
func newBuckets(name string, n int, every time.Duration) *buckets {
	return &buckets{name: name, n: n, every: every, full: map[string]time.Time{}, held: map[string]int{}, settled: make(chan struct{})}
}

// reserveWait bounds how long a reservation waits for others of its key to
// settle. What they wait on is a table read or a signature check, which
// takes milliseconds.
const reserveWait = time.Second

// reservation is a token taken before work whose outcome says whether it
// counts: kept if it does, given back if not.
type reservation struct {
	bs   *buckets
	key  string
	done bool
}

// reserve takes a token for key before the work it guards. When none is
// left only because reservations of the same key are still in flight, it
// waits for one to settle, up to reserveWait or the end of ctx: so calls
// that would all be given back, made at once, are not refused for each
// other. It returns how long until a token is due when it refuses. A nil
// reservation with ok true is a bucket set that never limits.
func (bs *buckets) reserve(ctx context.Context, key string, now func() time.Time) (r *reservation, ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return nil, true, 0
	}
	var give *time.Timer // made only once there is something to wait for
	for {
		bs.mu.Lock()
		t := now()
		bs.prune(t)
		next, over := bs.next(key, t)
		if over <= 0 {
			bs.full[key] = next
			bs.held[key]++
			bs.mu.Unlock()
			bs.m.limit(bs.name, true)
			return &reservation{bs: bs, key: key}, true, 0
		}
		inFlight, settled := bs.held[key] > 0, bs.settled
		bs.mu.Unlock()
		if !inFlight {
			bs.m.limit(bs.name, false)
			return nil, false, over
		}
		if give == nil {
			give = time.NewTimer(reserveWait)
			defer give.Stop()
		}
		select {
		case <-settled:
		case <-give.C:
			bs.m.limit(bs.name, false)
			return nil, false, over
		case <-ctx.Done():
			bs.m.limit(bs.name, false)
			return nil, false, over
		}
	}
}

// keep settles the reservation as counted: its token stays taken.
func (r *reservation) keep() { r.settle(false, time.Time{}) }

// release settles the reservation as not counted: its token goes back.
// Either does nothing to a reservation already settled. So each is settled
// where its outcome is known, and also released by a defer made where it is
// taken: it is settled on every path, a panic included
// (dromas-dev/dromas-server#36).
func (r *reservation) release(now time.Time) { r.settle(true, now) }

func (r *reservation) settle(back bool, now time.Time) {
	if r == nil || r.done {
		return
	}
	r.done = true
	bs := r.bs
	bs.mu.Lock()
	if bs.held[r.key]--; bs.held[r.key] <= 0 {
		delete(bs.held, r.key)
	}
	if back {
		bs.giveLocked(r.key, now)
	}
	close(bs.settled)
	bs.settled = make(chan struct{})
	bs.mu.Unlock()
}

// perPeriod is buckets of n, refilled n per period: a number a day is one
// back each day divided by it (Let's Encrypt's token bucket, and never a
// window that empties at midnight: dromas-dev/dromas-server#54).
func perPeriod(name string, n int, period time.Duration) *buckets {
	if n == 0 {
		return newBuckets(name, 0, 0)
	}
	return newBuckets(name, n, period/time.Duration(n))
}

// take takes one token for key at now. When none is left it returns how
// long until one is. A bucket set with n == 0, or no interval, never
// limits.
func (bs *buckets) take(key string, now time.Time) (ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return true, 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.prune(now)
	next, over := bs.next(key, now)
	if over > 0 {
		bs.m.limit(bs.name, false)
		return false, over
	}
	bs.full[key] = next
	bs.m.limit(bs.name, true)
	return true, 0
}

// giveLocked puts back a token taken for key, for a call that turned out not
// to count: a reservation released. It never fills a bucket past full. It is
// Let's Encrypt's refund (Boulder's maybeRefund): one interval off the key's
// time, never before now, so a release after the key's refill caught up gives
// back a token a later call took (LIMITS.md § Known weaknesses). The caller
// holds bs.mu.
func (bs *buckets) giveLocked(key string, now time.Time) {
	full, ok := bs.full[key]
	if !ok {
		return
	}
	if full = full.Add(-bs.every); full.After(now) {
		bs.full[key] = full
	} else {
		delete(bs.full, key)
	}
}

// ready reports whether key has a token at now, and takes none: for a limit
// that counts an outcome known only after the work it guards.
func (bs *buckets) ready(key string, now time.Time) (ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return true, 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if _, over := bs.next(key, now); over > 0 {
		return false, over
	}
	return true, 0
}

// next is when key's bucket would be full again were a token taken at now,
// and how far that is past a full bucket: over zero, no token is left. Each
// token taken puts full one interval later; a full bucket is n intervals'
// worth.
func (bs *buckets) next(key string, now time.Time) (next time.Time, over time.Duration) {
	full := bs.full[key]
	if full.Before(now) {
		full = now
	}
	next = full.Add(bs.every)
	return next, next.Sub(now) - time.Duration(bs.n)*bs.every
}

// clear fills key's bucket at now, as if the key had never been seen, and
// reports whether it held anything: a token taken and not yet back.
// Reservations in flight settle as they would have.
func (bs *buckets) clear(key string, now time.Time) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	full, ok := bs.full[key]
	delete(bs.full, key)
	return ok && full.After(now)
}

// prune drops every key whose bucket is full again, once each time an empty
// bucket would have filled: the map holds only keys used within the last two
// such periods, not every key ever seen.
func (bs *buckets) prune(now time.Time) {
	if now.Before(bs.sweep) {
		return
	}
	for k, full := range bs.full {
		if !full.After(now) {
			delete(bs.full, k)
		}
	}
	bs.sweep = now.Add(time.Duration(bs.n) * bs.every)
}

// ipKey keys a per-IP limit on a client address: the IPv4 address, or the
// IPv6 /64, since every IPv6 end site holds at least a /64.
func ipKey(host string) string {
	ip, ok := hostAddr(host)
	if !ok {
		return host
	}
	if ip.Is4() {
		return ip.String()
	}
	p, _ := ip.Prefix(64)
	return p.String()
}

// rangeKey keys a limit on a client's IPv6 /48, "the range a single
// subscriber is typically given" (Let's Encrypt's Boulder), and is "" for an
// IPv4 address or anything that is no address: those have no /48 count.
func rangeKey(host string) string {
	ip, ok := hostAddr(host)
	if !ok || ip.Is4() {
		return ""
	}
	p, _ := ip.Prefix(48)
	return p.String()
}

// hostAddr reads a client's address as the limits key it: an IPv4 address
// written as IPv6 is the IPv4 address, and an IPv6 zone, which names an
// interface of this host and is no part of the address, is dropped
// (dromas-dev/dromas-server#48).
func hostAddr(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

// headBytes is the head the longest call needs: a pass as long as one can be,
// with 2 KiB for its request line and the other headers a client and a proxy
// in front of it send, rounded up to a power of two. A pass is as long as
// the largest signature bound of any identity key type the client defines,
// so a type with a larger bound raises it with the client release that
// defines that type.
func headBytes() int {
	n := 1 << 10
	for n < protocol.MaxPassAuthorization+2<<10 {
		n <<= 1
	}
	return n
}
