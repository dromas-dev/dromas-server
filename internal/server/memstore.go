package server

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// NewMemStore returns the dev server's store: Memory over a backend of maps
// in this process (memBackend), on the given clock, nothing persisted.
// Memory follows its feed from the start.
func NewMemStore(now func() time.Time) *Memory {
	s := newMemory(now, DefaultBoxCache, nil, nil)
	b := newMemBackend(s.clock)
	s.backend = b
	_ = b.Start(context.Background(), s.apply) // it never fails
	return s
}

// memBackend keeps what a store keeps in maps, as the DynamoDB backend
// keeps it in tables: each write has the outcome its DynamoDB write would
// have, and each change it makes goes to its feed. Expired messages vanish
// at their ExpiresAt, as reads of the tables judge expiry. A box's record stays past its Expires, as one in DynamoDB does
// until the TTL deletes it, which may be days after: a test stands in for
// the TTL with DeleteBox, which is the delete the TTL makes.
//
// Its feed hands each change a write made to apply at the start of the
// backend's next write, in the order the writes were made, on that write's
// goroutine (deliver). So the change comes after its writer has applied the
// write's outcome to memory, as DynamoDB's stream brings a write back a
// second or two after it, and no test waits on a goroutine for it. Reads
// hand nothing over, so a read's token sees no write the read did not make
// room for.
type memBackend struct {
	now func() time.Time

	mu          sync.Mutex
	boxes       map[protocol.Address]*Box         // each box's record, with none of its revocations
	revocations map[protocol.Address]*Revocations // each address's revocations item
	messages    map[protocol.Address]map[[32]byte]*memMessage
	accounts    map[string]*Account
	keys        map[adoptKeyRef]*AdoptKey
	pending     []Change // made since the last delivery, in order: under mu

	feed  sync.Mutex // one delivery at a time, so changes go in order
	apply func(Change)
}

type adoptKeyRef struct {
	account string
	hash    [32]byte
}

// memMessage is a live message: its header and its body.
type memMessage struct {
	h    Header
	body []byte
}

func newMemBackend(now func() time.Time) *memBackend {
	return &memBackend{
		now:         now,
		boxes:       map[protocol.Address]*Box{},
		revocations: map[protocol.Address]*Revocations{},
		messages:    map[protocol.Address]map[[32]byte]*memMessage{},
		accounts:    map[string]*Account{},
		keys:        map[adoptKeyRef]*AdoptKey{},
	}
}

// Start implements Backend: every change made from now on goes to apply.
func (s *memBackend) Start(_ context.Context, apply func(Change)) error {
	s.feed.Lock()
	defer s.feed.Unlock()
	s.apply = apply
	return nil
}

// Ready implements Backend: the feed is in this process.
func (s *memBackend) Ready() bool { return true }

// changed records changes a write made, under mu, for the next delivery.
func (s *memBackend) changed(c ...Change) { s.pending = append(s.pending, c...) }

// deliver hands the changes made so far to the feed, in the order they were
// made: each write calls it before it takes mu.
func (s *memBackend) deliver() {
	s.feed.Lock()
	defer s.feed.Unlock()
	s.mu.Lock()
	cs := s.pending
	s.pending = nil
	s.mu.Unlock()
	if s.apply == nil {
		return
	}
	for _, c := range cs {
		s.apply(c)
	}
}

// recordChange is the feed's change of a's record as it now is.
func recordChange(rec *Box) Change {
	return Change{Kind: RecordChange, Addr: rec.Addr, Box: cloneBox(rec)}
}

// ReadAddress implements Backend.
func (s *memBackend) ReadAddress(_ context.Context, a protocol.Address) (*Box, *Revocations, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rec *Box
	if b := s.boxes[a]; b != nil {
		rec = cloneBox(b)
	}
	var rv *Revocations
	if r, ok := s.revocations[a]; ok {
		c := *r
		rv = &c
	}
	return rec, rv, nil
}

// live is box's live messages at now, the expired dropped.
func (s *memBackend) live(box protocol.Address) map[[32]byte]*memMessage {
	now := s.now()
	m := s.messages[box]
	for id, msg := range m {
		if !now.Before(msg.h.ExpiresAt) {
			delete(m, id)
		}
	}
	return m
}

// ReadLive implements Backend.
func (s *memBackend) ReadLive(_ context.Context, box protocol.Address) ([]Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hs []Header
	for _, m := range s.live(box) {
		hs = append(hs, m.h)
	}
	return hs, nil
}

// CreateBox implements Backend.
func (s *memBackend) CreateBox(_ context.Context, b *Box) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.boxes[b.Addr] != nil {
		return ErrExists
	}
	if _, err := identityWire(b.Identity); err != nil {
		return refused(fmt.Errorf("the identity: %w", err))
	}
	rec := storedRecord(b)
	s.boxes[b.Addr] = rec
	s.changed(recordChange(rec))
	return nil
}

// UpdateBox implements Backend.
func (s *memBackend) UpdateBox(_ context.Context, b *Box) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.boxes[b.Addr]
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	rec := storedRecord(b)
	rec.Rev++
	s.boxes[b.Addr] = rec
	s.changed(recordChange(rec))
	return nil
}

// DeleteBox implements Backend.
func (s *memBackend) DeleteBox(_ context.Context, a protocol.Address) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boxes[a]; ok {
		delete(s.boxes, a)
		s.changed(Change{Kind: RecordChange, Addr: a, Gone: true})
	}
	return nil
}

// Revoke implements Backend.
func (s *memBackend) Revoke(_ context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, error) {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.revocations[a]
	if want == ExpectHeld && !ok || want == ExpectNone && ok {
		return nil, ErrStale
	}
	if !ok {
		cur = &Revocations{}
	}
	if rv.Through > 0 && cur.Through >= rv.Through {
		return nil, ErrStale
	}
	c := *cur
	c.merge(rv)
	s.revocations[a] = &c
	held, echo := c, c
	s.changed(Change{Kind: RevocationsChange, Addr: a, Revocations: &echo})
	return &held, nil
}

// Dedupe implements Backend.
func (s *memBackend) Dedupe(_ context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.live(box)[id]
	if !ok {
		return nil, ErrNotFound
	}
	h := m.h
	return &h, nil
}

// PutMessage implements Backend: a live message of the id refuses it, as
// the condition of DynamoDB's write does.
func (s *memBackend) PutMessage(_ context.Context, box protocol.Address, h *Header, body []byte) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.live(box)[h.ID]; ok {
		orig := m.h
		return duplicate{&orig}
	}
	if s.messages[box] == nil {
		s.messages[box] = map[[32]byte]*memMessage{}
	}
	s.messages[box][h.ID] = &memMessage{h: *h, body: bytes.Clone(body)}
	echo := *h
	s.changed(Change{Kind: MessageChange, Addr: box, Header: &echo, Live: true})
	return nil
}

func less(a, b Header) int {
	if c := a.ReceivedAt.Compare(b.ReceivedAt); c != 0 {
		return c
	}
	return bytes.Compare(a.ID[:], b.ID[:])
}

// List implements Backend: every read of the maps is consistent.
func (s *memBackend) List(_ context.Context, box protocol.Address, after *Cursor, limit int, _ bool) ([]Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Header
	for _, m := range s.live(box) {
		if after != nil && less(m.h, Header{ReceivedAt: after.ReceivedAt, ID: after.ID}) <= 0 {
			continue
		}
		all = append(all, m.h)
	}
	slices.SortFunc(all, less)
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// Message implements Backend: the body, or its bytes from byte from on, a
// slice of what the map keeps.
func (s *memBackend) Message(_ context.Context, box protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.live(box)[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	h, body := m.h, m.body
	if from > 0 && from < int64(len(body)) {
		body = body[from:]
	}
	return &h, bytes.Clone(body), nil
}

// retireLocked deletes a live message, its body with it, and records the
// change: a deletion, which names the id alone, as DynamoDB's stream does.
// The caller holds mu.
func (s *memBackend) retireLocked(box protocol.Address, id [32]byte) (time.Time, error) {
	m, ok := s.live(box)[id]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	delete(s.messages[box], id)
	if len(s.messages[box]) == 0 {
		delete(s.messages, box)
	}
	s.changed(Change{Kind: MessageChange, Addr: box, Header: &Header{ID: id}, Gone: true})
	return m.h.ReceivedAt, nil
}

// Retire implements Backend.
func (s *memBackend) Retire(_ context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retireLocked(box, id)
}

// DeleteMessage implements Backend: the body and the item go together.
func (s *memBackend) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	return s.Retire(ctx, box, id)
}

// DeleteAll implements Backend.
func (s *memBackend) DeleteAll(_ context.Context, box protocol.Address, retired func([32]byte, time.Time)) error {
	s.deliver()
	type taken struct {
		id       [32]byte
		received time.Time
	}
	var out []taken
	s.mu.Lock()
	for id := range s.live(box) {
		if received, err := s.retireLocked(box, id); err == nil {
			out = append(out, taken{id, received})
		}
	}
	s.mu.Unlock()
	for _, t := range out {
		retired(t.id, t.received)
	}
	return nil
}

// Account implements Backend.
func (s *memBackend) Account(_ context.Context, id string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAccount(a), nil
}

// CreateAccount implements Backend.
func (s *memBackend) CreateAccount(_ context.Context, a *Account) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[a.ID]; ok {
		return ErrExists
	}
	s.accounts[a.ID] = cloneAccount(a)
	s.changed(Change{Kind: AccountChange, AccountID: a.ID, Account: cloneAccount(a)})
	return nil
}

// PutAdoptKey implements Backend. An adopt key is no change memory follows.
func (s *memBackend) PutAdoptKey(_ context.Context, k *AdoptKey) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := adoptKeyRef{k.Account, k.Hash}
	if _, ok := s.keys[ref]; ok {
		return ErrExists
	}
	c := *k
	s.keys[ref] = &c
	return nil
}

// AdoptKey implements Backend.
func (s *memBackend) AdoptKey(_ context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[adoptKeyRef{account, hash}]
	if !ok {
		return nil, ErrNotFound
	}
	c := *k
	return &c, nil
}

// Adopt implements Backend: the record and the key's use in one step, as
// DynamoDB's transaction.
func (s *memBackend) Adopt(_ context.Context, b *Box, account string, key [32]byte) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.boxes[b.Addr]
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	k, ok := s.keys[adoptKeyRef{account, key}]
	if !ok || !k.good(s.now()) {
		return ErrKeyRefused
	}
	k.Uses--
	rec := cloneBox(cur)
	rec.Account, rec.Rev = account, cur.Rev+1
	s.boxes[b.Addr] = rec
	s.changed(recordChange(rec))
	return nil
}

// Leave implements Backend.
func (s *memBackend) Leave(_ context.Context, b *Box) error {
	s.deliver()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.boxes[b.Addr]
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	rec := cloneBox(cur)
	rec.Account, rec.Rev = "", cur.Rev+1
	s.boxes[b.Addr] = rec
	s.changed(recordChange(rec))
	return nil
}
