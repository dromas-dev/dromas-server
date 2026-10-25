package server

import (
	"container/list"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// recCache is a bounded LRU of records, each at a version, and a record
// never moves back to an older one. Two are kept: what is held of each
// address, a box's record with its identity's revocations (ARCHITECTURE.md
// § Memory, for sends and reads of a box), with the addresses a read found
// missing; and account records (for a sender's limits).
//
// What it holds never goes back to before a write this process has applied
// (dromas-dev/dromas-server#12, #41, #95, #96). It counts the writes to
// each shard of its keys, and a write is counted and applied in one step
// under its lock (write), from this process or the stream, once the write
// has committed. A read takes its shard's count, a token, before it reads
// (begin); its copy is put in one step under the lock (fill), where the
// cache holds the key, every write since applied to it, or else only while
// no write to the shard was counted since the token. A copy refused is
// never put, so no reader is given it.
type recCache[K comparable, V any] struct {
	mu  takings
	max int // 0: no cache
	ll  *list.List
	m   map[K]*list.Element // value: V

	// writes is the count of the writes seen to the keys of each shard
	// (shard). It counts with no cache too: a read that lookups share is
	// held to it (Server.lookup).
	writes []uint64
	shard  func(K) int
	// missing, if set, remembers the keys a read found missing (missed). A
	// write to one ends it, in the step that counts the write.
	missing *missCache[K]

	key   func(V) K
	ver   func(V) version
	clone func(V) V
	// merge, if set, is what two copies of an entry hold together, old the
	// cached one: fill and image keep it in place of the newer copy alone.
	merge func(old, cur V) V
	// note, if set, is told of each hit, miss and eviction (Metrics).
	note func(event string)
	// between, in tests, runs in fill and in missed between the check and
	// the put, under the lock: it is handed the taking of the lock the check
	// was made under (takings), so that it can tell the lock was held from
	// the check to the put (dromas-dev/dromas-client#407 item 3).
	between func(checked uint64)
}

// takings is the cache's lock, which counts each taking of it, so that a
// step can be shown to have held it throughout: a check and its put are one
// step only where no other taking came between them.
type takings struct {
	sync.Mutex
	n uint64
}

// Lock takes the lock, and counts it.
func (t *takings) Lock() {
	t.Mutex.Lock()
	t.n++
}

// stepped runs between, if set: a step's check is done, under the taking
// checked, and its put comes next.
func (c *recCache[K, V]) stepped(checked uint64) {
	if c.between != nil {
		c.between(checked)
	}
}

// token is a shard's write count as a read of one of its keys begins
// (recCache.begin): every write counted before it is in what that read
// finds, since a write is counted once it has committed.
type token uint64

type boxCache = recCache[protocol.Address, *Box]

// newBoxCache holds size addresses, and remembers as many missing. Its
// writes are counted by the address's first byte.
func newBoxCache(size int) *boxCache {
	c := newRecCache(size, 256, func(a protocol.Address) int { return int(a[0]) },
		func(b *Box) protocol.Address { return b.Addr }, versionOf, cloneBox)
	c.merge = mergeViews // revocations are never taken away, so neither copy's are lost
	c.missing = newMissCache[protocol.Address](size)
	return c
}

type accountCache = recCache[string, *Account]

// newAccountCache holds size accounts. Accounts change seldom, so one count
// serves them all.
func newAccountCache(size int) *accountCache {
	return newRecCache(size, 1, func(string) int { return 0 },
		func(a *Account) string { return a.ID }, func(a *Account) version { return version{rev: a.Rev} }, cloneAccount)
}

func newRecCache[K comparable, V any](size, shards int, shard func(K) int, key func(V) K, ver func(V) version, clone func(V) V) *recCache[K, V] {
	return &recCache[K, V]{max: size, ll: list.New(), m: map[K]*list.Element{}, writes: make([]uint64, shards), shard: shard,
		key: key, ver: ver, clone: clone}
}

func (c *recCache[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		c.noted("miss")
		var zero V
		return zero, false
	}
	c.noted("hit")
	c.ll.MoveToFront(e)
	return c.clone(e.Value.(V)), true
}

func (c *recCache[K, V]) noted(event string) {
	if c.note != nil {
		c.note(event)
	}
}

// begin returns k's token, for a read of k about to begin.
func (c *recCache[K, V]) begin(k K) token {
	c.mu.Lock()
	defer c.mu.Unlock()
	return token(c.writes[c.shard(k)])
}

// fill caches v, a copy read at tok, unless the cache holds a newer record
// of it, or merges it with the copy held. For a key the cache does not hold,
// it puts v only while no write to the key's shard was counted since tok:
// the write's image found the key not held and changed nothing, so v may be
// older than it. The check and the put are one step under the lock.
func (c *recCache[K, V]) fill(v V, tok token) {
	if c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	checked := c.mu.n
	k := c.key(v)
	if _, held := c.m[k]; !held && token(c.writes[c.shard(k)]) != tok {
		return
	}
	c.stepped(checked)
	c.putLocked(v)
}

// putLocked is fill's put, under c.mu.
func (c *recCache[K, V]) putLocked(v V) {
	k := c.key(v)
	if e, ok := c.m[k]; ok {
		switch {
		case c.merge != nil:
			e.Value = c.merge(e.Value.(V), v)
		case !c.ver(e.Value.(V)).after(c.ver(v)):
			e.Value = c.clone(v)
		}
		c.ll.MoveToFront(e)
		return
	}
	c.insertLocked(k, c.clone(v))
}

// insertLocked adds an entry for k, which the cache does not hold, under
// c.mu, and evicts the least used over max.
func (c *recCache[K, V]) insertLocked(k K, v V) {
	c.m[k] = c.ll.PushFront(v)
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, c.key(old.Value.(V)))
		c.noted("eviction")
	}
}

// write records a write to k, made by this process or seen on the stream
// once it committed, and applies it, in one step under the lock: it counts
// the write in k's shard, so that a read begun before it puts nothing for a
// key not held (fill, missed), ends k's memory of a miss, and holds for k
// what f makes of the entry held, cur (if held), or nothing where f says
// not to keep it. missing tells f that k was remembered missing until then.
// f is the only change to the entry: it returns a value of its own, and
// leaves cur as it is.
func (c *recCache[K, V]) write(k K, f func(cur V, held, missing bool) (V, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes[c.shard(k)]++
	missing := c.missing != nil && c.missing.end(k)
	e, held := c.m[k]
	var cur V
	if held {
		cur = e.Value.(V)
	}
	v, keep := f(cur, held, missing)
	switch {
	case held && keep:
		e.Value = v
	case held:
		c.ll.Remove(e)
		delete(c.m, k)
	case keep && c.max > 0:
		c.insertLocked(k, v)
	}
}

// image is the write of the feed's image of a record, v: an entry held of
// an older record becomes v, merged where the cache merges; a key not held
// stays so, since the next read of it reads the image.
func (c *recCache[K, V]) image(v V) func(V, bool, bool) (V, bool) {
	return func(cur V, held, _ bool) (V, bool) {
		if !held || !c.ver(v).after(c.ver(cur)) {
			return cur, held
		}
		if c.merge != nil {
			return c.merge(cur, v), true
		}
		return c.clone(v), true
	}
}

// evicted is the write that leaves nothing held of its key: a record
// deleted, or one another wrote.
func evicted[V any](V, bool, bool) (V, bool) {
	var none V
	return none, false
}

// evict drops what is held of k, and counts nothing: a copy is put after it
// only as fill puts one.
func (c *recCache[K, V]) evict(k K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.Remove(e)
		delete(c.m, k)
	}
}

// missingAt reports whether k is remembered missing at now.
func (c *recCache[K, V]) missingAt(k K, now time.Time) bool {
	if c.missing == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.missing.has(k, now)
}

// missed records that a read of k begun at tok found nothing, unless a write
// to k's shard was counted since: the check and the record are one step
// under the lock, as fill's are.
func (c *recCache[K, V]) missed(k K, tok token, now time.Time) {
	if c.missing == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	checked := c.mu.n
	if token(c.writes[c.shard(k)]) != tok {
		return
	}
	c.stepped(checked)
	c.missing.add(k, now)
}

// missTTL is how long a box the table did not hold is remembered as missing.
// A write to the box, by this process or seen on the stream, ends it sooner.
const missTTL = 30 * time.Second

// missCache remembers the keys a read found missing, briefly, so that naming
// the same missing box again costs no read. At most max are held; over that,
// the expired go, and if none has, all of them. It is its recCache's, used
// under that cache's lock.
type missCache[K comparable] struct {
	max   int // 0: none
	until map[K]time.Time
	// note, if set, is told of each hit, miss and eviction (Metrics).
	note func(event string)
}

func newMissCache[K comparable](size int) *missCache[K] {
	return &missCache[K]{max: size, until: map[K]time.Time{}}
}

func (c *missCache[K]) noted(event string) {
	if c.note != nil {
		c.note(event)
	}
}

// has reports whether k is remembered as missing at now.
func (c *missCache[K]) has(k K, now time.Time) bool {
	if t, ok := c.until[k]; ok {
		if now.Before(t) {
			c.noted("hit")
			return true
		}
		delete(c.until, k)
	}
	c.noted("miss")
	return false
}

// add remembers k as missing from now.
func (c *missCache[K]) add(k K, now time.Time) {
	if c.max == 0 {
		return
	}
	if len(c.until) >= c.max {
		for o, t := range c.until {
			if !now.Before(t) {
				delete(c.until, o)
			}
		}
		if len(c.until) >= c.max {
			for range c.until {
				c.noted("eviction")
			}
			clear(c.until)
		}
	}
	c.until[k] = now.Add(missTTL)
}

// end forgets k, which a write has given a record or revocations, and
// reports whether it was remembered, expired or not: whether a read had
// found it missing and no write to it was seen since.
func (c *missCache[K]) end(k K) bool {
	_, ok := c.until[k]
	delete(c.until, k)
	return ok
}
