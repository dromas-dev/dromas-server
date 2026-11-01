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
// lives here (index), loaded per mailbox on its first use, and bounded caches of
// mailbox and account records serve sends and reads of a mailbox (recCache). Every
// write goes through one function (write), which applies its outcome, and
// every change the backend's feed hands over goes through one (apply). It
// is the one implementation of Store, whatever the backend: NewDynamoStore
// and NewMemStore make it.
type Memory struct {
	backend Backend
	now     func() time.Time
	log     *log.Logger
	// loads counts mailboxes read into memory, for tests.
	loads atomic.Int64

	idx      *index
	cache    *mailboxCache // with the mailboxes a read found missing
	accCache *accountCache
}

// DefaultMailboxCache is how many mailbox records memory holds by default, as many
// account records, and as many mailboxes remembered as missing.
const DefaultMailboxCache = 10000

// newMemory is memory with no backend yet, on a clock (time.Now if nil),
// holding mailboxCache mailbox records, as many account records and as many mailboxes
// remembered missing. Metrics, if set, count the caches' hits, misses and
// evictions.
func newMemory(now func() time.Time, mailboxCache int, l *log.Logger, m *Metrics) *Memory {
	s := &Memory{now: now, log: redacting(l), idx: newIndex(), cache: newMailboxCache(mailboxCache), accCache: newAccountCache(mailboxCache)}
	if s.now == nil {
		s.now = time.Now
	}
	if m != nil {
		s.cache.note = func(e string) { m.cacheEvent("mailboxes", e) }
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
// over is applied (apply). Memory starts empty, and a mailbox is loaded on its
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
//     write's condition on a mailbox's record or revocations (ErrStale,
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
			s.cache.write(*t.addr, evicted[*Mailbox])
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

// ensure loads mailbox a into memory on its first use by this process. The
// callers that come while it loads share the load, so it reads apart from
// the context of the caller that began it, each of its backend's calls
// bounded there.
func (s *Memory) ensure(ctx context.Context, a protocol.Address) error {
	return s.idx.ensure(ctx, a, func() (mailboxRead, error) {
		return s.readMailbox(context.WithoutCancel(ctx), a)
	})
}

// readMailbox reads what memory holds of a mailbox: its record's standing, its
// identity's revocations and its live messages, strongly consistent, so a
// change made before the read is in it (one made after reaches memory by the
// feed). What it read joins the cache, as of its token (recCache.fill).
func (s *Memory) readMailbox(ctx context.Context, a protocol.Address) (mailboxRead, error) {
	s.loads.Add(1)
	var r mailboxRead
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
		return r, nil // no mailbox: no messages either
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
		r.marks = append(r.marks, s.idx.newMark(h.ID, ms(h.ReceivedAt)+ttlMs))
	}
	return r, nil
}

// Held implements Store: the standing of a mailbox memory has loaded.
func (s *Memory) Held(a protocol.Address) (Standing, bool) { return s.idx.standing(a) }

// Changed returns a channel closed at mailbox a's next change in memory
// (Store.Changed).
func (s *Memory) Changed(a protocol.Address) <-chan struct{} { return s.idx.changed(a) }

// NextExpiry implements Store, from the index.
func (s *Memory) NextExpiry(a protocol.Address) time.Time {
	if exp := s.idx.nextExpiry(a); exp != 0 {
		return time.UnixMilli(int64(exp)) //nolint:gosec // a unix ms of a live message
	}
	return time.Time{}
}

// applyMailbox records a mailbox record this process wrote: b is what is held of
// its address, the record and the revocations read with it. Those were read
// before the write, so in the step that counts the write (recCache.write)
// b merges with what the cache holds of the address, every image since
// applied to it, and where the cache holds nothing, joins it only where the
// read before a registration found the address missing and no write to it
// was counted since. A read begun before the write puts nothing after it.
func (s *Memory) applyMailbox(b *Mailbox) {
	s.cache.write(b.Addr, func(cur *Mailbox, held, missing bool) (*Mailbox, bool) {
		switch {
		case held:
			return mergeViews(cur, b), true
		case missing:
			return cloneMailbox(b), true
		}
		return nil, false
	})
	st, _, err := storedRecord(b).standing()
	if err != nil { // a record this process just checked and wrote
		s.logf("mailboxes: a record written with a bad identity: %v", err)
		return
	}
	s.idx.setStanding(b.Addr, st, versionOf(b))
}

// applyRevocations records an address's revocations as they now are, from
// this process's write or the feed.
func (s *Memory) applyRevocations(a protocol.Address, rv *Revocations) {
	s.cache.write(a, func(cur *Mailbox, held, _ bool) (*Mailbox, bool) {
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
	s.cache.write(a, evicted[*Mailbox])
	s.idx.forget(a)
}

// retired takes a message this process deleted out of memory, leaving a
// tomb until the feed's echo (index.remove, index.deleted).
func (s *Memory) retired(mailbox protocol.Address, id [32]byte, received time.Time) {
	s.idx.remove(mailbox, s.idx.tagOf(id), ms(received)+ttlMs, s.nowMs(), false)
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
			if st, _, err = c.Mailbox.standing(); err != nil {
				s.logf("%s: a record whose standing does not read, taken as gone: %v", c.Kind, err)
				gone = true
			}
		}
		if gone {
			s.forget(c.Addr)
			return
		}
		// A view held of the address with no record, read since its record
		// was deleted, has no version to hold an image to: the image may be
		// of the record deleted, its event behind this process's delete on
		// the stream. The view is dropped, and the next use reads the address
		// (dromas-dev/dromas-server#169).
		img := s.cache.image(c.Mailbox)
		s.cache.write(c.Addr, func(cur *Mailbox, held, missing bool) (*Mailbox, bool) {
			if held && !cur.hasRecord() {
				return nil, false
			}
			return img(cur, held, missing)
		})
		s.idx.imageStanding(c.Addr, st, versionOf(c.Mailbox))
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
			// Acked, its body found gone, its mailbox's address revoked, or
			// expired and taken by the TTL, whose mark memory dropped at its
			// expiry.
			s.idx.deleted(c.Addr, s.idx.tagOf(c.Header.ID), s.nowMs())
		case c.Live:
			s.idx.insert(c.Addr, s.idx.newMark(c.Header.ID, ms(c.Header.ReceivedAt)+ttlMs), s.nowMs())
		default: // out of the list and kept, as an ack of a build before dromas-dev/dromas-client#507 left it
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
		return "mailboxes: a record"
	case RevocationsChange:
		return "mailboxes: an address's revocations"
	case MessageChange:
		return "msgs: a message"
	case AccountChange:
		return "accounts: an account"
	}
	return "a change of no kind"
}

// Mailbox implements Store: the cache, or a read. An address the read finds
// nothing of is remembered as missing for a while (missCache), so naming it
// again costs no read. The read fills the cache, so it is strongly
// consistent, as a mailbox's load is: a write made before it is in it, and one
// made after reaches the cache by the feed, or, where it was counted after
// the read's token, keeps the fill out (recCache.fill, missed).
func (s *Memory) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
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

// Known implements Store: the record cache, or the memory of a mailbox a read did
// not find.
func (s *Memory) Known(a protocol.Address) (*Mailbox, bool) {
	if b, ok := s.cache.get(a); ok {
		return b, true
	}
	return nil, s.cache.missingAt(a, s.now())
}

// Begin implements Store: a's token in the record cache (recCache.begin).
func (s *Memory) Begin(a protocol.Address) uint64 { return uint64(s.cache.begin(a)) }

// CreateMailbox implements Store.
func (s *Memory) CreateMailbox(ctx context.Context, b *Mailbox) error {
	if err := b.writable(); err != nil {
		return err
	}
	b.Rev = 1
	return s.write(ofAddress(b.Addr), func() error { return s.backend.CreateMailbox(ctx, b) }, func() { s.applyMailbox(b) })
}

// UpdateMailbox implements Store.
func (s *Memory) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	if err := b.writable(); err != nil {
		return err
	}
	return s.write(ofAddress(b.Addr), func() error { return s.backend.UpdateMailbox(ctx, b) }, func() {
		b.Rev++
		s.applyMailbox(b)
	})
}

// DeleteMailbox implements Store.
func (s *Memory) DeleteMailbox(ctx context.Context, a protocol.Address) error {
	return s.write(ofAddress(a), func() error { return s.backend.DeleteMailbox(ctx, a) }, func() { s.forget(a) })
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
func (s *Memory) Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error {
	return s.write(ofAddress(b.Addr), func() error { return s.backend.Adopt(ctx, b, account, key) }, func() {
		b.Account, b.Rev = account, b.Rev+1
		s.applyMailbox(b)
	})
}

// Leave implements Store.
func (s *Memory) Leave(ctx context.Context, b *Mailbox) error {
	return s.write(ofAddress(b.Addr), func() error { return s.backend.Leave(ctx, b) }, func() {
		b.Account, b.Rev = "", b.Rev+1
		s.applyMailbox(b)
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

// Dedupe implements Store: the live message's item. A stale miss is caught by
// PutMessage's conditional write.
func (s *Memory) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	return s.backend.Dedupe(ctx, mailbox, id)
}

// PutMessage implements Store: stored, the message's mark joins memory; met
// by another send's live item of the same ciphertext, that item's header is
// returned.
func (s *Memory) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	err := s.write(ofAddress(mailbox), func() error { return s.backend.PutMessage(ctx, mailbox, h, body) }, func() {
		s.idx.insert(mailbox, s.idx.newMark(h.ID, ms(h.ReceivedAt)+ttlMs), s.nowMs())
	})
	var d duplicate
	if errors.As(err, &d) {
		return d.h, nil
	}
	return nil, err
}

// List implements Store: a page read eventually consistent just after a
// write may miss it while memory's count has it, and a client lists at every
// poll, so the next one has it; a held list's, which no later change may
// wake, is read strongly consistent (Server.list).
func (s *Memory) List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	return s.backend.List(ctx, mailbox, after, limit, consistent)
}

// Message implements Store. A live message whose body is gone (a
// half-finished ack, or a body the lifecycle rule took early) is retired and
// answered as gone.
func (s *Memory) Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, body, err := s.backend.Message(ctx, mailbox, id, from)
	if errors.Is(err, errNoBody) {
		if err := s.retire(ctx, mailbox, id); err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return h, body, nil
}

// retire deletes a live message's item, so it leaves the list, and takes it
// out of memory. ErrNotFound if it is not live.
func (s *Memory) retire(ctx context.Context, mailbox protocol.Address, id [32]byte) error {
	var received time.Time
	return s.write(ofAddress(mailbox), func() (err error) {
		received, err = s.backend.Retire(ctx, mailbox, id)
		return err
	}, func() { s.retired(mailbox, id, received) })
}

// DeleteMessage implements Store (ack): the body, then the item. Both steps
// are safe to repeat, so a crash between them is finished by the client's
// next ack, and a fetch in between finds no body and retires it.
func (s *Memory) DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) error {
	var received time.Time
	return s.write(ofAddress(mailbox), func() (err error) {
		received, err = s.backend.DeleteMessage(ctx, mailbox, id)
		return err
	}, func() { s.retired(mailbox, id, received) })
}

// DeleteMessages implements Store (a revocation): every live message in the
// mailbox, as acks, each out of memory as its item is deleted.
func (s *Memory) DeleteMessages(ctx context.Context, mailbox protocol.Address) error {
	return s.write(ofAddress(mailbox), func() error {
		return s.backend.DeleteAll(ctx, mailbox, func(id [32]byte, received time.Time) { s.retired(mailbox, id, received) })
	}, nil)
}

// Count implements Store: from memory, after the mailbox's load on its first
// use.
func (s *Memory) Count(ctx context.Context, mailbox protocol.Address) (int, error) {
	if err := s.ensure(ctx, mailbox); err != nil {
		return 0, err
	}
	return s.idx.count(mailbox, s.nowMs()), nil
}

// After implements Store: from memory, after the mailbox's load on its first use.
func (s *Memory) After(ctx context.Context, mailbox protocol.Address, c *Cursor) (int, error) {
	if err := s.ensure(ctx, mailbox); err != nil {
		return 0, err
	}
	return s.idx.after(mailbox, ms(c.ReceivedAt)+ttlMs, prefix8(c.ID[:]), s.nowMs()), nil
}

// Holds implements Store: from memory, after the mailbox's load on its first use.
// A message another process stored is held once the feed has brought it.
func (s *Memory) Holds(ctx context.Context, mailbox protocol.Address, id [32]byte) (bool, error) {
	if err := s.ensure(ctx, mailbox); err != nil {
		return false, err
	}
	return s.idx.holds(mailbox, s.idx.tagOf(id), s.nowMs()), nil
}

// Fetched implements Store, from memory as Holds does.
func (s *Memory) Fetched(ctx context.Context, mailbox protocol.Address, id [32]byte) (held, again bool, err error) {
	if err := s.ensure(ctx, mailbox); err != nil {
		return false, false, err
	}
	held, again = s.idx.fetched(mailbox, s.idx.tagOf(id), s.nowMs())
	return held, again, nil
}
