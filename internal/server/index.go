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
// (ARCHITECTURE.md § Memory): for each box this
// process has used, its standing and one mark per live message.
//
// A box is loaded on its first use (ensure), from the tables, and kept
// current after that by this process's own writes and by the streams. A
// change to a box memory does not hold is dropped, since its first use reads
// it; a change that arrives while the box loads waits, and is applied after
// the load, in order. Applying a change twice, or late, is harmless:
// messages are a set keyed by (id, expiry), a count is the size of the set,
// and a standing only moves to a newer record (version).
type index struct {
	shards [256]indexShard // by the address's first byte
	// key tags each mark (markTag): random, made with the index.
	key [32]byte
}

type indexShard struct {
	mu    sync.Mutex
	boxes map[protocol.Address]*boxMem
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
	tag  uint64 // markTag of the message id: what the mark is known by
	id   uint64 // first 8 bytes of the message id, for the list's order within a millisecond only
	from uint64 // first 8 bytes of the sender's address, for the per-pair cap
	exp  uint64 // expiry in unix ms: received_at + TTL
	n    uint8  // fetches of it this process has served, to 255: a second one is a repeat
}

// boxMem is one box in memory.
type boxMem struct {
	loading *boxLoad // set while the box's first load is in flight
	exists  bool     // the box has a record
	st      Standing // its record's, with Listed unset: standing judges it
	// The record's version: when its box registered, in unix ms, and its
	// rev.
	created, rev uint64
	// What its identity revoked, from its revocations item: the address,
	// and certificates through a serial (0: none). Neither is taken away.
	revoked bool
	through uint64
	// stale is set when the record was deleted while the box loaded: the
	// load may have read it before, so the box is dropped after it.
	stale bool
	marks []mark
	// tombs are messages this process removed whose removal the stream has
	// not echoed yet: the stream's late insert must not bring them back. The
	// echo clears one; so does its expiry, in case the echo came first.
	tombs []mark
}

// boxLoad is a box's first load: the changes that arrive meanwhile, and its
// outcome for the callers waiting on it.
type boxLoad struct {
	queued []func(*boxMem)
	done   chan struct{}
	err    error
}

// boxRead is what a load reads of a box: whether it has a record, its
// standing at its version (created, rev), what its identity revoked, and
// its live messages.
type boxRead struct {
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
		x.shards[i].boxes = map[protocol.Address]*boxMem{}
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

func (x *index) newMark(id [32]byte, from protocol.Address, exp uint64) mark {
	return mark{tag: x.tagOf(id), id: prefix8(id[:]), from: prefix8(from[:]), exp: exp}
}

// ensure loads box a unless memory holds it. read runs once however many
// callers ask at the same time; if it fails, the box stays unloaded and the
// next caller reads again.
func (x *index) ensure(ctx context.Context, a protocol.Address, read func() (boxRead, error)) error {
	sh := x.shard(a)
	sh.mu.Lock()
	if m := sh.boxes[a]; m != nil {
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
	l := &boxLoad{done: make(chan struct{})}
	m := &boxMem{loading: l}
	sh.boxes[a] = m
	sh.mu.Unlock()

	r, err := read()
	sh.mu.Lock()
	if err != nil {
		delete(sh.boxes, a) // and its queued changes: the next read sees them
	} else {
		m.exists, m.st, m.created, m.rev, m.marks = r.exists, r.st, r.created, r.rev, r.marks
		m.revoked, m.through = r.revoked, r.through
		for _, op := range l.queued {
			op(m)
		}
		m.loading = nil
		if m.stale {
			delete(sh.boxes, a) // its callers go on with what they waited for; the next use reads it again
		}
	}
	l.err = err
	sh.mu.Unlock()
	close(l.done)
	return err
}

// apply runs op on box a: now if memory holds it, after its load if it is
// loading, and not at all if memory does not hold it.
func (x *index) apply(a protocol.Address, op func(*boxMem)) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	switch m := sh.boxes[a]; {
	case m == nil:
	case m.loading != nil:
		m.loading.queued = append(m.loading.queued, op)
	default:
		op(m)
	}
}

// held returns box a if memory holds it, loaded.
func (sh *indexShard) held(a protocol.Address) *boxMem {
	if m := sh.boxes[a]; m != nil && m.loading == nil {
		return m
	}
	return nil
}

// prune drops marks and tombs that have expired at now (unix ms): a message
// is live while now < its expiry.
func (m *boxMem) prune(now uint64) {
	m.marks = slices.DeleteFunc(m.marks, func(k mark) bool { return k.exp <= now })
	m.tombs = slices.DeleteFunc(m.tombs, func(k mark) bool { return k.exp <= now })
}

func same(a, b mark) bool { return a.tag == b.tag && a.exp == b.exp }

// insert adds a live message, from this process's write or the stream. A
// message with a tomb stays removed.
func (x *index) insert(box protocol.Address, k mark, now uint64) {
	x.apply(box, func(m *boxMem) {
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
func (x *index) remove(box protocol.Address, tag, exp, now uint64, echo bool) {
	x.apply(box, func(m *boxMem) {
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

// count returns the number of live messages in a box.
func (x *index) count(box protocol.Address, now uint64) int {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return 0
	}
	m.prune(now)
	return len(m.marks)
}

// pair returns how many live messages from one sender a box holds, and the
// earliest expiry among them.
func (x *index) pair(box protocol.Address, from uint64, now uint64) (n int, oldest uint64) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return 0, 0
	}
	m.prune(now)
	for _, k := range m.marks {
		if k.from == from {
			n++
			if oldest == 0 || k.exp < oldest {
				oldest = k.exp
			}
		}
	}
	return n, oldest
}

// after returns how many live messages a box holds past a list position: the
// list is oldest first, by receipt time (so by expiry) and then id.
func (x *index) after(box protocol.Address, exp, id, now uint64) (n int) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
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

// holds reports whether a box holds a live message of this tag.
func (x *index) holds(box protocol.Address, tag, now uint64) bool {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return false
	}
	m.prune(now)
	return slices.ContainsFunc(m.marks, func(k mark) bool { return k.tag == tag })
}

// fetched is holds for a fetch: it also reports whether this process has
// served the message before, and counts this serving.
func (x *index) fetched(box protocol.Address, tag, now uint64) (held, again bool) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
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

// setStanding records a box's standing, of a record at version v, unless
// memory holds a newer record's.
func (x *index) setStanding(a protocol.Address, st Standing, v version) {
	x.apply(a, func(m *boxMem) {
		if (version{m.created, m.rev}).after(v) {
			return
		}
		m.exists, m.st, m.created, m.rev = true, st, v.created, v.rev
	})
}

// setRevocations records what an address's identity revoked, adding to
// what memory holds: nothing it revoked is taken away.
func (x *index) setRevocations(a protocol.Address, revoked bool, through uint64) {
	x.apply(a, func(m *boxMem) {
		m.revoked = m.revoked || revoked
		m.through = max(m.through, through)
	})
}

// forget drops box a from memory, whose record was deleted: its next use
// reads it again. One loading is dropped once its load is done.
func (x *index) forget(a protocol.Address) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	switch m := sh.boxes[a]; {
	case m == nil:
	case m.loading != nil:
		m.stale = true
	default:
		delete(sh.boxes, a)
	}
}

// standing returns a loaded box's standing, and whether it has one: a
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
	st.Listed = m.through > 0 && st.CertSerial <= m.through
	return st, true
}
