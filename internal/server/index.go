package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/dromas-dev/dromas-client/protocol"
)

// index is what a process holds in memory so that a poll never leaves it
// (ARCHITECTURE.md § Memory): for each mailbox this
// process has used, its standing and one mark per live message.
//
// A mailbox is loaded on its first use (ensure), from the tables, and kept
// current after that by this process's own writes and by the streams. A
// change to a mailbox memory does not hold is dropped, since its first use reads
// it; a change that arrives while the mailbox loads waits, and is applied after
// the load, in order. Applying a change twice, or late, is harmless:
// messages are a set keyed by (id, expiry), a count is the size of the set,
// and a standing only moves to a newer record (version). A deletion, which
// names no expiry, is the exception (deleted).
type index struct {
	shards [256]indexShard // by the address's first byte
	// key tags each mark (markTag): random, made with the index.
	key [32]byte
}

type indexShard struct {
	mu        sync.Mutex
	mailboxes map[protocol.Address]*mailboxMem
	// wake holds, for each mailbox a list is held on, the channel closed at
	// the mailbox's next change (changed).
	wake map[protocol.Address]chan struct{}
}

// mark is one live message (ARCHITECTURE.md § Memory).
//
// A message is known by its tag, which nobody outside the server can choose
// or compute: the id is the SHA-256 of a ciphertext its sender chose, so 8
// bytes of it are the sender's to steer: an id that only shares a held
// message's prefix would pass for it (dromas-dev/dromas-server#10).
// The plain prefix stays for one thing: ordering two messages of one
// millisecond as the list orders them.
type mark struct {
	tag uint64 // markTag of the message id: what the mark is known by
	id  uint64 // first 8 bytes of the message id, for the list's order within a millisecond only
	exp uint64 // expiry in unix ms: received_at + TTL
	n   uint8  // fetches of it this process has served, to 255: a second one is a repeat
}

// mailboxMem is one mailbox in memory.
type mailboxMem struct {
	loading *mailboxLoad // set while the mailbox's first load is in flight
	exists  bool         // the mailbox has a record
	st      Standing     // its record's, with Listed unset: standing judges it
	// The record's version: when its mailbox registered, in unix ms, and its
	// rev.
	created, rev uint64
	// What its identity revoked, from its revocations item: the address,
	// and certificates through a serial (0: none). Neither is taken away.
	revoked bool
	through uint64
	// stale is set when the record was deleted while the mailbox loaded: the
	// load may have read it before, so the mailbox is dropped after it.
	stale bool
	marks []mark
	// tombs are messages this process removed whose removal the stream has
	// not echoed yet: the stream's late insert must not bring them back. The
	// echo clears one; so does its expiry, in case the echo came first.
	tombs []mark
}

// mailboxLoad is a mailbox's first load: the changes that arrive meanwhile, and its
// outcome for the callers waiting on it.
type mailboxLoad struct {
	queued []func(*mailboxMem)
	done   chan struct{}
	err    error
}

// mailboxRead is what a load reads of a mailbox: whether it has a record, its
// standing at its version (created, rev), what its identity revoked, and
// its live messages.
type mailboxRead struct {
	exists  bool
	st      Standing
	created uint64
	rev     uint64
	revoked bool
	through uint64
	marks   []mark
}

// newIndex returns an empty index under a random key: the tags are this
// process's alone, and nothing made of one leaves it.
func newIndex() *index {
	x := &index{}
	_, _ = rand.Read(x.key[:])
	for i := range x.shards {
		x.shards[i].mailboxes = map[protocol.Address]*mailboxMem{}
		x.shards[i].wake = map[protocol.Address]chan struct{}{}
	}
	return x
}

func (x *index) shard(a protocol.Address) *indexShard { return &x.shards[a[0]] }

func prefix8(b []byte) uint64 { return binary.BigEndian.Uint64(b[:8]) }

// markTag is how memory knows a message: the first 8 bytes of
// HMAC-SHA-256, under key, of its whole id.
func markTag(key *[32]byte, id [32]byte) uint64 {
	m := hmac.New(sha256.New, key[:])
	m.Write(id[:])
	return prefix8(m.Sum(nil))
}

// tagOf is markTag under this index's key.
func (x *index) tagOf(id [32]byte) uint64 { return markTag(&x.key, id) }

func (x *index) newMark(id [32]byte, exp uint64) mark {
	return mark{tag: x.tagOf(id), id: prefix8(id[:]), exp: exp}
}

// ensure loads mailbox a unless memory holds it. read runs once however many
// callers ask at the same time; if it fails, the mailbox stays unloaded and the
// next caller reads again.
func (x *index) ensure(ctx context.Context, a protocol.Address, read func() (mailboxRead, error)) error {
	sh := x.shard(a)
	sh.mu.Lock()
	if m := sh.mailboxes[a]; m != nil {
		l := m.loading
		sh.mu.Unlock()
		if l == nil {
			return nil
		}
		select {
		case <-l.done:
			return l.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l := &mailboxLoad{done: make(chan struct{})}
	m := &mailboxMem{loading: l}
	sh.mailboxes[a] = m
	sh.mu.Unlock()

	r, err := read()
	sh.mu.Lock()
	if err != nil {
		delete(sh.mailboxes, a) // and its queued changes: the next read sees them
	} else {
		m.exists, m.st, m.created, m.rev, m.marks = r.exists, r.st, r.created, r.rev, r.marks
		m.revoked, m.through = r.revoked, r.through
		for _, op := range l.queued {
			op(m)
		}
		m.loading = nil
		if m.stale {
			delete(sh.mailboxes, a) // its callers go on with what they waited for; the next use reads it again
		}
	}
	l.err = err
	sh.mu.Unlock()
	close(l.done)
	return err
}

// apply runs op on mailbox a: now if memory holds it, after its load if it is
// loading, and not at all if memory does not hold it. Every change to a mailbox
// passes here, a write of this process's and one from the streams, so here
// every list held on it is woken (changed).
func (x *index) apply(a protocol.Address, op func(*mailboxMem)) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	defer sh.woke(a)
	switch m := sh.mailboxes[a]; {
	case m == nil:
	case m.loading != nil:
		m.loading.queued = append(m.loading.queued, op)
	default:
		op(m)
	}
}

// changed returns a channel closed at mailbox a's next change in memory: a
// list held on it waits on it, taken before it reads the mailbox, so no change
// is missed between the two (PROTOCOL.md §11.11).
func (x *index) changed(a protocol.Address) <-chan struct{} {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.wake[a]
	if c == nil {
		c = make(chan struct{})
		sh.wake[a] = c
	}
	return c
}

// woke wakes every list held on mailbox a. The shard's lock is held.
func (sh *indexShard) woke(a protocol.Address) {
	if c := sh.wake[a]; c != nil {
		close(c)
		delete(sh.wake, a)
	}
}

// held returns mailbox a if memory holds it, loaded.
func (sh *indexShard) held(a protocol.Address) *mailboxMem {
	if m := sh.mailboxes[a]; m != nil && m.loading == nil {
		return m
	}
	return nil
}

// prune drops marks and tombs that have expired at now (unix ms): a message
// is live while now < its expiry.
func (m *mailboxMem) prune(now uint64) {
	m.marks = slices.DeleteFunc(m.marks, func(k mark) bool { return k.exp <= now })
	m.tombs = slices.DeleteFunc(m.tombs, func(k mark) bool { return k.exp <= now })
}

func same(a, b mark) bool { return a.tag == b.tag && a.exp == b.exp }

// insert adds a live message, from this process's write or the stream. A
// message with a tomb stays removed.
func (x *index) insert(mailbox protocol.Address, k mark, now uint64) {
	x.apply(mailbox, func(m *mailboxMem) {
		if k.exp <= now {
			return
		}
		m.prune(now)
		if slices.ContainsFunc(m.tombs, func(t mark) bool { return same(t, k) }) ||
			slices.ContainsFunc(m.marks, func(t mark) bool { return same(t, k) }) {
			return
		}
		m.marks = append(m.marks, k)
	})
}

// remove removes a message. A removal by this process leaves a tomb until
// the stream echoes it (echo true) or the message would have expired.
func (x *index) remove(mailbox protocol.Address, tag, exp, now uint64, echo bool) {
	x.apply(mailbox, func(m *mailboxMem) {
		m.prune(now)
		k := mark{tag: tag, exp: exp}
		m.marks = slices.DeleteFunc(m.marks, func(t mark) bool { return same(t, k) })
		switch {
		case echo:
			m.tombs = slices.DeleteFunc(m.tombs, func(t mark) bool { return same(t, k) })
		case exp > now && !slices.ContainsFunc(m.tombs, func(t mark) bool { return same(t, k) }):
			m.tombs = append(m.tombs, k)
		}
	})
}

// deleted removes a message whose item the stream says was deleted, which
// names its id and not its expiry: of the marks and tombs of its tag, the one
// of the earliest expiry. A mailbox holds one item of an id at a time, and the
// stream brings an item's changes in order, so that is the message whose item
// went; a tomb is this process's own removal of it, echoed. It reads wrong
// where this process holds a later message of the same bytes when the
// deletion arrives, one it stored or one its load of the mailbox read, after an
// ack or the expiry of the first (dromas-dev/dromas-client#548 items 9,
// 10): a mark it takes leaves the mailbox counted one short, and a list held on
// it answered an empty page, until the stream's insert of that message
// brings the mark back; a tomb it takes, of the later message this process
// acked, lets that insert count a message that is gone, until its own
// deletion arrives.
func (x *index) deleted(mailbox protocol.Address, tag, now uint64) {
	x.apply(mailbox, func(m *mailboxMem) {
		m.prune(now)
		first := func(ks []mark) int {
			i := -1
			for j, k := range ks {
				if k.tag == tag && (i < 0 || k.exp < ks[i].exp) {
					i = j
				}
			}
			return i
		}
		i, t := first(m.marks), first(m.tombs)
		switch {
		case t >= 0 && (i < 0 || m.tombs[t].exp <= m.marks[i].exp):
			m.tombs = slices.Delete(m.tombs, t, t+1)
		case i >= 0:
			m.marks = slices.Delete(m.marks, i, i+1)
		}
	})
}

// count returns the number of live messages in a mailbox.
func (x *index) count(mailbox protocol.Address, now uint64) int {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(mailbox)
	if m == nil {
		return 0
	}
	m.prune(now)
	return len(m.marks)
}

// nextExpiry returns the earliest expiry (unix ms) of a mailbox's marks, or 0
// for a mailbox with none or not loaded. It prunes nothing: a mark that expired
// since the mailbox was last read is a change its reader has not seen, so its
// expiry, now past, is returned.
func (x *index) nextExpiry(mailbox protocol.Address) uint64 {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(mailbox)
	if m == nil {
		return 0
	}
	var first uint64
	for _, k := range m.marks {
		if first == 0 || k.exp < first {
			first = k.exp
		}
	}
	return first
}

// after returns how many live messages a mailbox holds past a list position: the
// list is oldest first, by receipt time (so by expiry) and then id.
func (x *index) after(mailbox protocol.Address, exp, id, now uint64) (n int) {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(mailbox)
	if m == nil {
		return 0
	}
	m.prune(now)
	for _, k := range m.marks {
		if k.exp > exp || (k.exp == exp && k.id > id) {
			n++
		}
	}
	return n
}

// holds reports whether a mailbox holds a live message of this tag.
func (x *index) holds(mailbox protocol.Address, tag, now uint64) bool {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(mailbox)
	if m == nil {
		return false
	}
	m.prune(now)
	return slices.ContainsFunc(m.marks, func(k mark) bool { return k.tag == tag })
}

// fetched is holds for a fetch: it also reports whether this process has
// served the message before, and counts this serving.
func (x *index) fetched(mailbox protocol.Address, tag, now uint64) (held, again bool) {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(mailbox)
	if m == nil {
		return false, false
	}
	m.prune(now)
	for i := range m.marks {
		if k := &m.marks[i]; k.tag == tag {
			again = k.n > 0
			if k.n < 255 {
				k.n++
			}
			return true, again
		}
	}
	return false, false
}

// setStanding records a mailbox's standing, of a record at version v, unless
// memory holds a newer record's.
func (x *index) setStanding(a protocol.Address, st Standing, v version) {
	x.apply(a, func(m *mailboxMem) {
		if (version{m.created, m.rev}).after(v) {
			return
		}
		m.exists, m.st, m.created, m.rev = true, st, v.created, v.rev
	})
}

// setRevocations records what an address's identity revoked, adding to
// what memory holds: nothing it revoked is taken away.
func (x *index) setRevocations(a protocol.Address, revoked bool, through uint64) {
	x.apply(a, func(m *mailboxMem) {
		m.revoked = m.revoked || revoked
		m.through = max(m.through, through)
	})
}

// forget drops mailbox a from memory, whose record was deleted: its next use
// reads it again. One loading is dropped once its load is done.
func (x *index) forget(a protocol.Address) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	defer sh.woke(a)
	switch m := sh.mailboxes[a]; {
	case m == nil:
	case m.loading != nil:
		m.stale = true
	default:
		delete(sh.mailboxes, a)
	}
}

// standing returns a loaded mailbox's standing, and whether it has one: a
// revoked address has, whether or not a record is left, and an address with
// no record has none.
func (x *index) standing(a protocol.Address) (Standing, bool) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(a)
	switch {
	case m == nil:
		return Standing{}, false
	case m.revoked:
		st := m.st
		st.State, st.Listed = Revoked, false
		return st, true
	case !m.exists:
		return Standing{}, false
	}
	st := m.st
	st.Listed = m.through > 0 && st.Rank > 0 && st.Rank <= m.through // certificates only: never the identity
	return st, true
}
