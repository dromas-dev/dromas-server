package server

import (
	"context"
	"errors"
	"log"
	"sync/atomic"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Memory is the store: what this process holds in memory, over a Backend
// that holds the durable state (ARCHITECTURE.md § Memory). What a poll needs
// lives here (index), loaded per box on its first use, and bounded caches of
// box and account records serve sends and reads of a box (recCache). Every
// write goes through one function (write), which applies its outcome, and
// every change the backend's feed hands over goes through one (apply). It
// is the one implementation of Store, whatever the backend: NewDynamoStore
// and NewMemStore make it.
type Memory struct {
	backend Backend
	now     func() time.Time
	log     *log.Logger
	// loads counts boxes read into memory, for tests.
	loads atomic.Int64

	idx      *index
	cache    *boxCache // with the boxes a read found missing
	accCache *accountCache
}

// DefaultBoxCache is how many box records memory holds by default, as many
// account records, and as many boxes remembered as missing.
const DefaultBoxCache = 10000

// newMemory is memory with no backend yet, on a clock (time.Now if nil),
// holding boxCache box records, as many account records and as many boxes
// remembered missing. Metrics, if set, count the caches' hits, misses and
// evictions.
func newMemory(now func() time.Time, boxCache int, l *log.Logger, m *Metrics) *Memory {
	s := &Memory{now: now, log: redacting(l), idx: newIndex(), cache: newBoxCache(boxCache), accCache: newAccountCache(boxCache)}
	if s.now == nil {
		s.now = time.Now
	}
	if m != nil {
		s.cache.note = func(e string) { m.cacheEvent("boxes", e) }
		s.cache.missing.note = func(e string) { m.cacheEvent("missing", e) }
		s.accCache.note = func(e string) { m.cacheEvent("accounts", e) }
	}
	return s
}

// clock is memory's now, which its backend reads too: one clock.
func (s *Memory) clock() time.Time { return s.now() }

func (s *Memory) nowMs() uint64 { return ms(s.now()) }

func (s *Memory) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Printf(format, args...)
	}
}

// Start follows the backend's feed: from then on every change it hands
// over is applied (apply). Memory starts empty, and a box is loaded on its
// first use, after the feed is followed: a change made before its load is
// in the load, one made after reaches memory by the feed, or both, and
// applying it twice is harmless (ARCHITECTURE.md § Startup). Nothing is
// kept across restarts.
func (s *Memory) Start(ctx context.Context) error { return s.backend.Start(ctx, s.apply) }

// Ready reports whether the backend's feed is followed.
func (s *Memory) Ready() bool { return s.backend.Ready() }

// target is what memory holds that a write may change: an address's record,
// revocations and marks, or an account's record, or nothing.
type target struct {
	addr    *protocol.Address
	account *string
}

func ofAddress(a protocol.Address) target { return target{addr: &a} }
func ofAccount(id string) target          { return target{account: &id} }

// write makes one write of the backend, do, and applies its outcome to
// memory: every write the store makes goes through here, and nothing else
// reads what a write's error means (Backend).
//
//   - Applied: applied, if any, puts it in memory.
//   - Refused, as the store stated: nothing changes, but a refusal of the
//     write's condition on a box's record or revocations (ErrStale,
//     ErrExists) says the store holds what this process never applied, so
//     the copy memory holds of the address is evicted, counted as a write
//     (recCache.write), and a read begun before it puts nothing.
//   - Unknown, ErrUnknown or any error the backend did not state as a
//     refusal: memory forgets the address, the record cache and the index
//     (forget), or evicts the account, so that the next use reads it; and
//     ErrUnknown is returned, wrapping the cause.
//
// A count reserved for the write is kept when it was applied or may have
// been, and given back for a refusal (mayHaveApplied, LIMITS.md rule 4).
func (s *Memory) write(t target, do func() error, applied func()) error {
	err := do()
	switch {
	case err == nil:
		if applied != nil {
			applied()
		}
		return nil
	case isRefusal(err):
		if t.addr != nil && (errors.Is(err, ErrStale) || errors.Is(err, ErrExists)) {
			s.cache.write(*t.addr, evicted[*Box])
		}
		return err
	}
	switch {
	case t.addr != nil:
		s.forget(*t.addr)
	case t.account != nil:
		s.accCache.write(*t.account, evicted[*Account])
	}
	return unknown(err)
}

// ensure loads box a into memory on its first use by this process. The
// callers that come while it loads share the load, so it reads apart from
// the context of the caller that began it, each of its backend's calls
// bounded there.
func (s *Memory) ensure(ctx context.Context, a protocol.Address) error {
	return s.idx.ensure(ctx, a, func() (boxRead, error) {
		return s.readBox(context.WithoutCancel(ctx), a)
	})
}

// readBox reads what memory holds of a box: its record's standing, its
// identity's revocations and its live messages, strongly consistent, so a
// change made before the read is in it (one made after reaches memory by the
// feed). What it read joins the cache, as of its token (recCache.fill).
func (s *Memory) readBox(ctx context.Context, a protocol.Address) (boxRead, error) {
	s.loads.Add(1)
	var r boxRead
	tok := s.cache.begin(a)
	rec, rv, err := s.backend.ReadAddress(ctx, a)
	if err != nil {
		return r, err
	}
	if b := view(a, rec, rv); b != nil {
		s.cache.fill(b, tok)
	}
	if rv != nil {
		r.revoked, r.through = len(rv.Address) > 0, rv.Through
	}
	if rec == nil {
		return r, nil // no box: no mail either
	}
	if r.st, _, err = rec.standing(); err != nil {
		return r, err
	}
	v := versionOf(rec)
	r.exists, r.rev, r.created = true, v.rev, v.created
	live, err := s.backend.ReadLive(ctx, a)
	if err != nil {
		return r, err
	}
	for _, h := range live {
		r.marks = append(r.marks, s.idx.newMark(h.ID, h.From, ms(h.ReceivedAt)+ttlMs))
	}
	return r, nil
}

// Held implements Store: the standing of a box memory has loaded.
func (s *Memory) Held(a protocol.Address) (Standing, bool) { return s.idx.standing(a) }

// applyBox records a box record this process wrote: b is what is held of
// its address, the record and the revocations read with it. Those were read
// before the write, so in the step that counts the write (recCache.write)
// b merges with what the cache holds of the address, every image since
// applied to it, and where the cache holds nothing, joins it only where the
// read before a registration found the address missing and no write to it
// was counted since. A read begun before the write puts nothing after it.
func (s *Memory) applyBox(b *Box) {
	s.cache.write(b.Addr, func(cur *Box, held, missing bool) (*Box, bool) {
		switch {
		case held:
			return mergeViews(cur, b), true
		case missing:
			return cloneBox(b), true
		}
		return nil, false
	})
	st, _, err := storedRecord(b).standing()
	if err != nil { // a record this process just checked and wrote
		s.logf("boxes: a record written with a bad identity: %v", err)
		return
	}
	s.idx.setStanding(b.Addr, st, versionOf(b))
}

// applyRevocations records an address's revocations as they now are, from
// this process's write or the feed.
func (s *Memory) applyRevocations(a protocol.Address, rv *Revocations) {
	s.cache.write(a, func(cur *Box, held, _ bool) (*Box, bool) {
		if !held {
			return nil, false
		}
		m, err := cur.withRevocations(rv)
		return m, err == nil // one that fails is evicted: the next use reads it
	})
	s.idx.setRevocations(a, len(rv.Address) > 0, rv.Through)
}

// forget drops what memory holds of an address whose record was deleted,
// whose item does not read, or that a write whose outcome is unknown may
// have changed (write), so that its next use reads it again. A deletion
// from the feed may be of a record older than one this process has written
// since: the read after it is what tells.
func (s *Memory) forget(a protocol.Address) {
	s.cache.write(a, evicted[*Box])
	s.idx.forget(a)
}

// retired takes a message this process retired out of memory, leaving a
// tomb until the feed's echo (index.remove).
func (s *Memory) retired(box protocol.Address, id [32]byte, received time.Time) {
	s.idx.remove(box, s.idx.tagOf(id), ms(received)+ttlMs, s.nowMs(), false)
}

// apply applies one change of the backend's feed to memory: one rule for
// each kind of change. An item whose image does not read is applied as one
// gone, whatever its kind (dromas-dev/dromas-client#407 item 1): the
// address forgotten, the account evicted, so that memory answers for none
// of it, and its next use reads it, which fails, so nothing is served or
// taken for it on what memory held before (dromas-dev/dromas-server#87).
func (s *Memory) apply(c Change) {
	if c.Err != nil {
		s.logf("%s: an item that does not read, taken as gone: %v", c.Kind, c.Err)
	}
	gone := c.Gone || c.Err != nil
	switch c.Kind {
	case RecordChange:
		// A record's image refreshes the record cache and the standing,
		// where they hold an older record; one this build cannot read, such
		// as one in a state it never writes or whose ACL does not read, is
		// forgotten, as its removal is.
		var st Standing
		var err error
		if !gone {
			if st, _, err = c.Box.standing(); err != nil {
				s.logf("%s: a record whose standing does not read, taken as gone: %v", c.Kind, err)
				gone = true
			}
		}
		if gone {
			s.forget(c.Addr)
			return
		}
		s.cache.write(c.Addr, s.cache.image(c.Box))
		s.idx.setStanding(c.Addr, st, versionOf(c.Box))
	case RevocationsChange:
		// They add to what memory holds, since nothing in them is ever
		// taken away; they are never deleted.
		if gone {
			s.forget(c.Addr)
			return
		}
		s.applyRevocations(c.Addr, c.Revocations)
	case MessageChange:
		switch {
		case c.Err != nil:
			s.forget(c.Addr)
		case c.Gone:
			// Only the TTL deletes a message item, after it expired, and
			// memory drops a mark at its expiry.
		case c.Live:
			s.idx.insert(c.Addr, s.idx.newMark(c.Header.ID, c.Header.From, ms(c.Header.ReceivedAt)+ttlMs), s.nowMs())
		default: // acked, or its body found gone
			s.idx.remove(c.Addr, s.idx.tagOf(c.Header.ID), ms(c.Header.ReceivedAt)+ttlMs, s.nowMs(), true)
		}
	case AccountChange:
		if gone {
			s.accCache.write(c.AccountID, evicted[*Account])
			return
		}
		s.accCache.write(c.AccountID, s.accCache.image(c.Account))
	}
}

func (k ChangeKind) String() string {
	switch k {
	case RecordChange:
		return "boxes: a record"
	case RevocationsChange:
		return "boxes: an address's revocations"
	case MessageChange:
		return "msgs: a message"
	case AccountChange:
		return "accounts: an account"
	}
	return "a change of no kind"
}

// Box implements Store: the cache, or a read. An address the read finds
// nothing of is remembered as missing for a while (missCache), so naming it
// again costs no read. The read fills the cache, so it is strongly
// consistent, as a box's load is: a write made before it is in it, and one
// made after reaches the cache by the feed, or, where it was counted after
// the read's token, keeps the fill out (recCache.fill, missed).
func (s *Memory) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if b, ok := s.cache.get(a); ok {
		return b, nil
	}
	if s.cache.missingAt(a, s.now()) {
		return nil, ErrNotFound
	}
	tok := s.cache.begin(a)
	rec, rv, err := s.backend.ReadAddress(ctx, a)
	if err != nil {
		return nil, err
	}
	b := view(a, rec, rv)
	if b == nil {
		s.cache.missed(a, tok, s.now())
		return nil, ErrNotFound
	}
	s.cache.fill(b, tok)
	return b, nil
}

// Known implements Store: the record cache, or the memory of a box a read did
// not find.
func (s *Memory) Known(a protocol.Address) (*Box, bool) {
	if b, ok := s.cache.get(a); ok {
		return b, true
	}
	return nil, s.cache.missingAt(a, s.now())
}

// Begin implements Store: a's token in the record cache (recCache.begin).
func (s *Memory) Begin(a protocol.Address) uint64 { return uint64(s.cache.begin(a)) }

// CreateBox implements Store.
func (s *Memory) CreateBox(ctx context.Context, b *Box) error {
	if err := b.writable(); err != nil {
		return err
	}
	b.Rev = 1
	return s.write(ofAddress(b.Addr), func() error { return s.backend.CreateBox(ctx, b) }, func() { s.applyBox(b) })
}

// UpdateBox implements Store.
func (s *Memory) UpdateBox(ctx context.Context, b *Box) error {
	if err := b.writable(); err != nil {
		return err
	}
	return s.write(ofAddress(b.Addr), func() error { return s.backend.UpdateBox(ctx, b) }, func() {
		b.Rev++
		s.applyBox(b)
	})
}

// DeleteBox implements Store.
func (s *Memory) DeleteBox(ctx context.Context, a protocol.Address) error {
	return s.write(ofAddress(a), func() error { return s.backend.DeleteBox(ctx, a) }, func() { s.forget(a) })
}

// Revoke implements Store.
func (s *Memory) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) error {
	var held *Revocations
	return s.write(ofAddress(a), func() (err error) {
		held, err = s.backend.Revoke(ctx, a, rv, want)
		return err
	}, func() { s.applyRevocations(a, held) })
}

// Adopt implements Store.
func (s *Memory) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	return s.write(ofAddress(b.Addr), func() error { return s.backend.Adopt(ctx, b, account, key) }, func() {
		b.Account, b.Rev = account, b.Rev+1
		s.applyBox(b)
	})
}

// Leave implements Store.
func (s *Memory) Leave(ctx context.Context, b *Box) error {
	return s.write(ofAddress(b.Addr), func() error { return s.backend.Leave(ctx, b) }, func() {
		b.Account, b.Rev = "", b.Rev+1
		s.applyBox(b)
	})
}

// CreateAccount implements Store.
func (s *Memory) CreateAccount(ctx context.Context, a *Account) error {
	a.Rev = 1
	return s.write(ofAccount(a.ID), func() error { return s.backend.CreateAccount(ctx, a) }, nil)
}

// PutAdoptKey implements Store. Memory holds no adopt key.
func (s *Memory) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	return s.write(target{}, func() error { return s.backend.PutAdoptKey(ctx, k) }, nil)
}

// AdoptKey implements Store: a strongly consistent read, so a key just made
// is found.
func (s *Memory) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	return s.backend.AdoptKey(ctx, account, hash)
}

// Account implements Store: the cache, or a strongly consistent read, so a
// change made before it is in it (one made after reaches the cache by the
// feed, or, where it was counted after the read's token, keeps the fill
// out: recCache.fill).
func (s *Memory) Account(ctx context.Context, id string) (*Account, error) {
	if a, ok := s.accCache.get(id); ok {
		return a, nil
	}
	tok := s.accCache.begin(id)
	a, err := s.backend.Account(ctx, id)
	if err != nil {
		return nil, err
	}
	s.accCache.fill(a, tok)
	return a, nil
}

// Dedupe implements Store: the message's item, acked or not. A stale miss is
// caught by PutMessage's conditional write.
func (s *Memory) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	return s.backend.Dedupe(ctx, box, id)
}

// PutMessage implements Store: stored, the message's mark joins memory; met
// by another send's item of the same ciphertext, that item's header is
// returned.
func (s *Memory) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	err := s.write(ofAddress(box), func() error { return s.backend.PutMessage(ctx, box, h, body) }, func() {
		s.idx.insert(box, s.idx.newMark(h.ID, h.From, ms(h.ReceivedAt)+ttlMs), s.nowMs())
	})
	var d duplicate
	if errors.As(err, &d) {
		return d.h, nil
	}
	return nil, err
}

// List implements Store: a page read just after a write may miss it while
// memory's count has it; a client lists at every poll, so the next one has
// it.
func (s *Memory) List(ctx context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error) {
	return s.backend.List(ctx, box, after, limit)
}

// Message implements Store. A live message whose body is gone (a
// half-finished ack, or a body the lifecycle rule took early) is retired and
// answered as gone.
func (s *Memory) Message(ctx context.Context, box protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, body, err := s.backend.Message(ctx, box, id, from)
	if errors.Is(err, errNoBody) {
		if err := s.retire(ctx, box, id); err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return h, body, nil
}

// retire takes a live message out of the list, and out of memory: its item
// stays as the dedupe record until it expires. ErrNotFound if it is not live.
func (s *Memory) retire(ctx context.Context, box protocol.Address, id [32]byte) error {
	var received time.Time
	return s.write(ofAddress(box), func() (err error) {
		received, err = s.backend.Retire(ctx, box, id)
		return err
	}, func() { s.retired(box, id, received) })
}

// DeleteMessage implements Store (ack): the body, then the item leaves the
// list. Both steps are safe to repeat, so a crash between them is finished by
// the client's next ack, and a fetch in between finds no body and retires it.
func (s *Memory) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) error {
	var received time.Time
	return s.write(ofAddress(box), func() (err error) {
		received, err = s.backend.DeleteMessage(ctx, box, id)
		return err
	}, func() { s.retired(box, id, received) })
}

// DeleteMessages implements Store (a revocation): every live message in the
// box, as acks.
func (s *Memory) DeleteMessages(ctx context.Context, box protocol.Address) error {
	return s.DeleteFrom(ctx, box, func(protocol.Address) bool { return true })
}

// DeleteFrom implements Store: the live messages in the box whose sender
// matches, each out of memory as it is taken out of the list.
func (s *Memory) DeleteFrom(ctx context.Context, box protocol.Address, from func(protocol.Address) bool) error {
	return s.write(ofAddress(box), func() error {
		return s.backend.DeleteFrom(ctx, box, from, func(id [32]byte, received time.Time) { s.retired(box, id, received) })
	}, nil)
}

// Count implements Store: from memory, after the box's load on its first
// use.
func (s *Memory) Count(ctx context.Context, box protocol.Address) (int, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, err
	}
	return s.idx.count(box, s.nowMs()), nil
}

// PairCount implements Store: from memory, after the box's load on its
// first use.
func (s *Memory) PairCount(ctx context.Context, box, from protocol.Address) (int, time.Time, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, time.Time{}, err
	}
	n, oldest := s.idx.pair(box, prefix8(from[:]), s.nowMs())
	if n == 0 {
		return 0, time.Time{}, nil
	}
	return n, fromMs(oldest), nil
}

// After implements Store: from memory, after the box's load on its first use.
func (s *Memory) After(ctx context.Context, box protocol.Address, c *Cursor) (int, error) {
	if err := s.ensure(ctx, box); err != nil {
		return 0, err
	}
	return s.idx.after(box, ms(c.ReceivedAt)+ttlMs, prefix8(c.ID[:]), s.nowMs()), nil
}

// Holds implements Store: from memory, after the box's load on its first use.
// A message another process stored is held once the feed has brought it.
func (s *Memory) Holds(ctx context.Context, box protocol.Address, id [32]byte) (bool, error) {
	if err := s.ensure(ctx, box); err != nil {
		return false, err
	}
	return s.idx.holds(box, s.idx.tagOf(id), s.nowMs()), nil
}

// Fetched implements Store, from memory as Holds does.
func (s *Memory) Fetched(ctx context.Context, box protocol.Address, id [32]byte) (held, again bool, err error) {
	if err := s.ensure(ctx, box); err != nil {
		return false, false, err
	}
	held, again = s.idx.fetched(box, s.idx.tagOf(id), s.nowMs())
	return held, again, nil
}
