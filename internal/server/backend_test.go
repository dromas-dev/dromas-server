package server

// The store's backends, and the boundary between them and memory: every
// write's outcome, every change the feed hands over, and the rows as the
// PostgreSQL backend's feed decodes them.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// heldRecord is a registered mailbox's record, from the suite's store.
func heldRecord(t *testing.T) (*env, *raw, *Mailbox) {
	t.Helper()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	b, err := e.store.Mailbox(t.Context(), r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	return e, r, b
}

// holdsMailbox reports whether the index holds mailbox a loaded, with a record or
// none.
func (x *index) holdsMailbox(a protocol.Address) bool {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.held(a) != nil
}

// heldWorld is a store over the in-memory backend, with the injector
// between them, that holds: mailbox a, registered, its record cached and the
// mailbox loaded, with two live messages, in no account; an
// account, acct, its record cached, with an adopt key; and an address n
// with no mailbox, read, remembered missing, and loaded. Every change the setup
// made has reached memory, so the write a test makes next is the only one
// counted after it.
type heldWorld struct {
	s        *Memory
	f        *faults
	rec      *Mailbox // a's record, as read
	a, n     protocol.Address
	msgs     [2]*Header
	acct     string
	key      [32]byte // the adopt key's hash
	now      time.Time
	inAcct   bool // a is in acct
	backend  *memBackend
	standing Standing // a's in the index, before the write
}

func newHeldWorld(t *testing.T, inAccount bool) *heldWorld {
	t.Helper()
	_, _, rec := heldRecord(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	w := &heldWorld{s: NewMemStore(func() time.Time { return now }), a: rec.Addr, n: protocol.Address{0xee, 1},
		acct: "acct", key: [32]byte{0xad}, now: now, inAcct: inAccount}
	w.backend = w.s.backend.(*memBackend)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.s.CreateMailbox(ctx, cloneMailbox(rec)))
	must(w.s.CreateAccount(ctx, &Account{ID: w.acct}))
	must(w.s.PutAdoptKey(ctx, &AdoptKey{Account: w.acct, Hash: w.key, Uses: 5, Expires: now.Add(time.Hour)}))
	for i := range w.msgs {
		w.msgs[i] = &Header{ID: [32]byte{0x1d, byte(i)}, Size: 3, ReceivedAt: now.Add(-time.Duration(i+1) * time.Minute)}
		w.msgs[i].ExpiresAt = w.msgs[i].ReceivedAt.Add(protocol.Retention)
		_, err := w.s.PutMessage(ctx, w.a, w.msgs[i], []byte("abc"))
		must(err)
	}
	if inAccount {
		b, err := w.s.Mailbox(ctx, w.a)
		must(err)
		must(w.s.Adopt(ctx, b, w.acct, w.key))
	}
	w.backend.deliver()
	var err error
	w.rec, err = w.s.Mailbox(ctx, w.a)
	must(err)
	if _, err := w.s.Count(ctx, w.a); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Account(ctx, w.acct); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Mailbox(ctx, w.n); !errors.Is(err, ErrNotFound) {
		t.Fatalf("control: an address with no mailbox: %v", err)
	}
	if _, err := w.s.Count(ctx, w.n); err != nil {
		t.Fatal(err)
	}
	w.f = injectFaults(w.s)
	var ok bool
	if w.standing, ok = w.s.Held(w.a); !ok || !w.s.idx.holdsMailbox(w.n) {
		t.Fatal("control: the mailbox is not loaded, or the address with no mailbox")
	}
	if b, ok := w.s.Known(w.a); !ok || b == nil || (b.Account == w.acct) != inAccount {
		t.Fatalf("control: the record is not cached as set up: %v", b)
	}
	if b, ok := w.s.Known(w.n); !ok || b != nil {
		t.Fatal("control: the address with no mailbox is not remembered missing")
	}
	if _, ok := w.s.accCache.get(w.acct); !ok {
		t.Fatal("control: the account is not cached")
	}
	return w
}

// marks is how many live messages the index holds of mailbox a, with no load.
func (w *heldWorld) marks() int { return w.s.idx.count(w.a, ms(w.now)) }

// A write's target: what memory holds that it may change.
const (
	onMailbox = "the mailbox"
	onNew     = "an address with no mailbox"
	onAccount = "a new account"
	onNothing = "nothing memory holds"
)

// backendWrite is a write of the Backend, as the store makes it.
type backendWrite struct {
	on string // its target
	// inAccount sets the world up with the mailbox in its account.
	inAccount bool
	// run makes the write through the store; dup is a send answered with
	// another's header.
	run func(ctx context.Context, w *heldWorld) (dup *Header, err error)
	// refusals are the refusals it states.
	refusals []error
	// applied reports what memory holds once it was applied, or what is
	// wrong.
	applied func(w *heldWorld) string
}

// backendWrites is every write of the Backend: TestEveryWriteOfTheBackend
// ReachesMemoryByItsOutcome holds it to the interface's methods.
func backendWrites() map[string]backendWrite {
	cached := func(w *heldWorld) *Mailbox { b, _ := w.s.Known(w.a); return b }
	return map[string]backendWrite{
		"CreateMailbox": {on: onNew, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			b := cloneMailbox(w.rec)
			b.Addr, b.Account = w.n, ""
			return nil, w.s.CreateMailbox(ctx, b)
		}, refusals: []error{ErrExists}, applied: func(w *heldWorld) string {
			if b, ok := w.s.Known(w.n); !ok || b == nil || b.Rev != 1 {
				return "the new record is not cached"
			}
			if _, ok := w.s.Held(w.n); !ok {
				return "the index holds no standing of the new mailbox"
			}
			return ""
		}},
		"UpdateMailbox": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			b := cloneMailbox(w.rec)
			b.Rank += 10
			return nil, w.s.UpdateMailbox(ctx, b)
		}, refusals: []error{ErrStale}, applied: func(w *heldWorld) string {
			if b := cached(w); b == nil || b.Rev != w.rec.Rev+1 || b.Rank != w.rec.Rank+10 {
				return "the cache does not hold the record written"
			}
			if st, _ := w.s.Held(w.a); st.Rank != w.rec.Rank+10 {
				return "the index does not hold the standing written"
			}
			return ""
		}},
		"DeleteMailbox": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.DeleteMailbox(ctx, w.a)
		}, refusals: []error{errStated}, applied: func(w *heldWorld) string {
			if _, ok := w.s.Known(w.a); ok || w.s.idx.holdsMailbox(w.a) {
				return "memory holds the mailbox whose record was deleted"
			}
			return ""
		}},
		"Revoke": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.Revoke(ctx, w.a, &Revocations{Identity: w.rec.Identity, Address: []byte("the identity's revocation")}, ExpectAnything)
		}, refusals: []error{ErrStale}, applied: func(w *heldWorld) string {
			if b := cached(w); b == nil || b.State != Revoked {
				return "the cache does not hold the revocation"
			}
			if st, _ := w.s.Held(w.a); st.State != Revoked {
				return "the index does not hold the revocation"
			}
			return ""
		}},
		"Adopt": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.Adopt(ctx, cloneMailbox(w.rec), w.acct, w.key)
		}, refusals: []error{ErrStale, ErrKeyRefused}, applied: func(w *heldWorld) string {
			if b := cached(w); b == nil || b.Account != w.acct {
				return "the cache does not hold the mailbox in its account"
			}
			if st, _ := w.s.Held(w.a); !st.InAccount {
				return "the index does not hold the mailbox in an account"
			}
			return ""
		}},
		"Leave": {on: onMailbox, inAccount: true, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.Leave(ctx, cloneMailbox(w.rec))
		}, refusals: []error{ErrStale}, applied: func(w *heldWorld) string {
			if b := cached(w); b == nil || b.Account != "" {
				return "the cache holds the mailbox in its account"
			}
			if st, _ := w.s.Held(w.a); st.InAccount {
				return "the index holds the mailbox in an account"
			}
			return ""
		}},
		"CreateAccount": {on: onAccount, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.CreateAccount(ctx, &Account{ID: "acct2"})
		}, refusals: []error{ErrExists}, applied: func(*heldWorld) string { return "" }},
		"PutAdoptKey": {on: onNothing, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.PutAdoptKey(ctx, &AdoptKey{Account: w.acct, Hash: [32]byte{9}, Uses: 1, Expires: w.now.Add(time.Hour)})
		}, refusals: []error{ErrExists}, applied: func(*heldWorld) string { return "" }},
		"PutMessage": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			h := &Header{ID: [32]byte{0x1d, 9}, Size: 3, ReceivedAt: w.now, ExpiresAt: w.now.Add(protocol.Retention)}
			return w.s.PutMessage(ctx, w.a, h, []byte("abc"))
		}, refusals: []error{errNotStored, duplicate{}}, applied: func(w *heldWorld) string {
			if n := w.marks(); n != 3 {
				return fmt.Sprintf("the index counts %d messages, want 3", n)
			}
			return ""
		}},
		"Retire": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.retire(ctx, w.a, w.msgs[0].ID, time.Time{})
		}, refusals: []error{ErrNotFound}, applied: func(w *heldWorld) string {
			if n := w.marks(); n != 1 {
				return fmt.Sprintf("the index counts %d messages, want 1", n)
			}
			return ""
		}},
		"DeleteMessage": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.DeleteMessage(ctx, w.a, w.msgs[0].ID)
		}, refusals: []error{ErrNotFound}, applied: func(w *heldWorld) string {
			if n := w.marks(); n != 1 {
				return fmt.Sprintf("the index counts %d messages, want 1", n)
			}
			return ""
		}},
		"DeleteAll": {on: onMailbox, run: func(ctx context.Context, w *heldWorld) (*Header, error) {
			return nil, w.s.DeleteMessages(ctx, w.a)
		}, refusals: []error{errStated}, applied: func(w *heldWorld) string {
			if n := w.marks(); n != 0 {
				return fmt.Sprintf("the index counts %d messages, want none", n)
			}
			return ""
		}},
	}
}

// backendReads are the Backend's reads, and its feed's methods: every other
// method is a write, and in backendWrites.
var backendReads = []string{"ReadAddress", "ReadLive", "List", "Message", "Header", "PassHeld", "Account", "AdoptKey", "Start", "Ready"}

// Every write of the Backend, whatever the backend, has one of three
// outcomes, and the store's one choke point (Memory.write) makes each what
// it is in memory, in the count reserved for the write and in its answer:
// applied, memory holds the write and the count is kept; refused as the
// store stated, memory is as it was, but for a refusal of a condition on
// the mailbox's record (ErrStale, ErrExists), which evicts the copy held,
// counted as a write so that a read begun before it puts nothing, and the
// count is given back; unknown, before or after the backend applied it,
// memory forgets what it held of the write's target, the record cache and
// the index, or the account, a read begun before puts nothing, the answer is
// ErrUnknown and the count is kept (dromas-dev/dromas-client#411 item
// 3). The writes are held to the interface's methods: one added there and
// not here fails.
func TestEveryWriteOfTheBackendReachesMemoryByItsOutcome(t *testing.T) {
	t.Parallel()
	writes := backendWrites()
	bt := reflect.TypeFor[Backend]()
	for i := range bt.NumMethod() {
		name := bt.Method(i).Name
		if _, ok := writes[name]; !ok && !slices.Contains(backendReads, name) {
			t.Errorf("the Backend's %s is neither a read nor a write this test makes", name)
		}
	}
	for name := range writes {
		if _, ok := bt.MethodByName(name); !ok {
			t.Errorf("the test makes a write the Backend has none of: %s", name)
		}
	}
	ctx := context.Background()
	for _, name := range slices.Sorted(maps.Keys(writes)) {
		c := writes[name]
		type outcome struct {
			fault   fault
			refusal error
		}
		outcomes := []outcome{{fault: asIs}, {fault: unknownBefore}, {fault: unknownAfter}}
		for _, r := range c.refusals {
			outcomes = append(outcomes, outcome{refusedBefore, r})
		}
		for _, o := range outcomes {
			label := o.fault.String()
			if o.refusal != nil {
				label += ": " + strings.TrimPrefix(o.refusal.Error(), "refused: ")
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				w := newHeldWorld(t, c.inAccount)
				refusal := o.refusal
				if _, ok := refusal.(duplicate); ok {
					refusal = duplicate{w.msgs[1]}
				}
				w.f.set(name, o.fault)
				w.f.refuse[name] = refusal
				addr := w.a
				if c.on == onNew {
					addr = w.n
				}
				tok, atok := w.s.cache.begin(addr), w.s.accCache.begin("acct2")
				dup, err := c.run(ctx, w)

				applied, unknown := o.fault == asIs, o.fault == unknownBefore || o.fault == unknownAfter
				kept := mayHaveApplied(err) || err == nil && dup == nil
				t.Logf("err %v, a duplicate's header %v; the count kept %v", err, dup != nil, kept)
				switch {
				case applied && (err != nil || dup != nil):
					t.Fatalf("applied, the write answers %v, %v", dup, err)
				case unknown && (!errors.Is(err, ErrUnknown) || isRefusal(err) || errors.Is(err, ErrStale) || errors.Is(err, ErrExists) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrKeyRefused)):
					t.Fatalf("unknown, the write answers %v, not ErrUnknown alone", err)
				case refusal != nil:
					if d, ok := refusal.(duplicate); ok {
						if err != nil || dup == nil || dup.ID != d.h.ID {
							t.Fatalf("refused as a duplicate, the send answers %v, %v; want the other's header", dup, err)
						}
					} else if !errors.Is(err, refusal) || errors.Is(err, ErrUnknown) {
						t.Fatalf("refused, the write answers %v; want %v", err, refusal)
					}
				}
				if kept != !(refusal != nil) {
					t.Errorf("the count reserved for the write is kept %v; want %v", kept, refusal == nil)
				}

				// What memory holds of the write's target.
				stale := (c.on == onMailbox || c.on == onNew) && (errors.Is(refusal, ErrStale) || errors.Is(refusal, ErrExists))
				keptOut := func() bool { // a read begun before the write puts nothing
					switch c.on {
					case onAccount:
						w.s.accCache.fill(&Account{ID: "acct2", Rev: 1}, atok)
						_, held := w.s.accCache.get("acct2")
						return !held
					case onNothing:
						return true
					}
					b := cloneMailbox(w.rec)
					b.Addr = addr
					w.s.cache.missed(addr, tok, w.now)
					w.s.cache.fill(b, tok)
					_, held := w.s.Known(addr)
					return !held
				}
				switch c.on {
				case onMailbox, onNew:
					loaded := w.s.idx.holdsMailbox(addr)
					b, cachedOK := w.s.Known(addr)
					switch {
					case unknown:
						if loaded || cachedOK {
							t.Errorf("unknown: memory still holds the address: the index %v, the record cache %v", loaded, cachedOK)
						}
					case stale:
						// The store holds what memory never applied, the
						// record or the call's standing: memory forgets the
						// address, so its next use reads it.
						if loaded || cachedOK {
							t.Errorf("refused for its condition: memory still holds the address: the index %v, the record cache %v", loaded, cachedOK)
						}
					case refusal != nil:
						if !loaded {
							t.Errorf("refused: the index dropped the mailbox")
						}
						if st, _ := w.s.Held(w.a); c.on == onMailbox && st != w.standing {
							t.Errorf("refused: the index holds the mailbox's standing %+v, not %+v as before", st, w.standing)
						}
						if !stale && c.on == onMailbox && (!cachedOK || b == nil || b.Rev != w.rec.Rev) {
							t.Errorf("refused: the record cache does not hold the record as before")
						}
					default:
						if msg := c.applied(w); msg != "" {
							t.Errorf("applied: %s", msg)
						}
					}
				case onNothing:
					if !w.s.idx.holdsMailbox(w.a) {
						t.Error("a write memory holds nothing of dropped the mailbox")
					}
					if _, ok := w.s.Known(w.a); !ok {
						t.Error("a write memory holds nothing of dropped the record")
					}
					if _, ok := w.s.accCache.get(w.acct); !ok {
						t.Error("a write memory holds nothing of dropped the account")
					}
				}
				// What an applied write puts is TestEveryOrderOfAFillAndAWrite's.
				if want := unknown || stale; !applied && c.on != onNothing && keptOut() != want {
					t.Errorf("a read begun before the write puts nothing after it: %v; want %v", !want, want)
				}
			})
		}
	}
}

// Every change memory applies to a mailbox wakes the long polls on it
// (PROTOCOL.md §11.11): every write of the Backend that targets a mailbox,
// applied or of an outcome unknown, as backendWrites makes each (held to
// the interface's methods by TestEveryWriteOfTheBackendReachesMemoryByIts
// Outcome); and every kind of change the backend's feed hands memory, its
// row as it now is, gone, and one that does not read. Each kind is here:
// one added and not here fails.
func TestEveryChangeMemoryAppliesToAMailboxWakesItsLongPolls(t *testing.T) {
	t.Parallel()
	woken := func(c <-chan struct{}) bool {
		select {
		case <-c:
			return true
		default:
			return false
		}
	}
	ctx := context.Background()
	writes := backendWrites()
	for _, name := range slices.Sorted(maps.Keys(writes)) {
		c := writes[name]
		if c.on != onMailbox && c.on != onNew {
			continue // an account's, or nothing memory holds: no mailbox's
		}
		for _, f := range []fault{asIs, unknownBefore, unknownAfter} {
			t.Run(name+"/"+f.String(), func(t *testing.T) {
				w := newHeldWorld(t, c.inAccount)
				addr := w.a
				if c.on == onNew {
					addr = w.n
				}
				held := w.s.Changed(addr)
				w.f.set(name, f)
				_, _ = c.run(ctx, w)
				if !woken(held) {
					t.Error("a long poll on the mailbox is not woken")
				}
			})
		}
	}
	bad := errors.New("an image that does not read")
	feed := map[ChangeKind]func(w *heldWorld) map[string]Change{
		RecordChange: func(w *heldWorld) map[string]Change {
			b := cloneMailbox(w.rec)
			b.Rev++
			return map[string]Change{
				"a newer record": {Kind: RecordChange, Addr: w.a, Mailbox: b},
				"gone":           {Kind: RecordChange, Addr: w.a, Gone: true},
				"unread":         {Kind: RecordChange, Addr: w.a, Err: bad},
			}
		},
		RevocationsChange: func(w *heldWorld) map[string]Change {
			rv := &Revocations{Identity: w.rec.Identity, Address: []byte("the identity's revocation")}
			return map[string]Change{
				"the address revoked": {Kind: RevocationsChange, Addr: w.a, Revocations: rv},
				"gone":                {Kind: RevocationsChange, Addr: w.a, Gone: true},
				"unread":              {Kind: RevocationsChange, Addr: w.a, Err: bad},
			}
		},
		MessageChange: func(w *heldWorld) map[string]Change {
			fresh := &Header{ID: [32]byte{0x1d, 9}, Size: 3, ReceivedAt: w.now, ExpiresAt: w.now.Add(protocol.Retention)}
			return map[string]Change{
				"live":                  {Kind: MessageChange, Addr: w.a, Header: fresh, Live: true},
				"gone":                  {Kind: MessageChange, Addr: w.a, Header: &Header{ID: w.msgs[0].ID}, Gone: true},
				"out of the list, kept": {Kind: MessageChange, Addr: w.a, Header: w.msgs[0]},
				"unread":                {Kind: MessageChange, Addr: w.a, Err: bad},
			}
		},
		AccountChange: func(*heldWorld) map[string]Change { return nil }, // an account's: no mailbox's
	}
	for k := ChangeKind(1); int(k) <= numChangeKinds; k++ {
		changes, ok := feed[k]
		if !ok {
			t.Errorf("no change of kind %s here", k)
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(changes(newHeldWorld(t, false)))) {
			t.Run(k.String()+"/"+name, func(t *testing.T) {
				w := newHeldWorld(t, false)
				held := w.s.Changed(w.a)
				w.s.apply(changes(w)[name])
				if !woken(held) {
					t.Error("a long poll on the mailbox is not woken")
				}
			})
		}
	}
}

// A row of the backend's that does not read is applied as one gone,
// whatever its kind: the address forgotten, the record cache and the index
// both, or the account evicted, each counted so that a read begun before it
// puts nothing (dromas-dev/dromas-client#407 item 1). Each kind's item
// comes as the PostgreSQL backend's feed decodes its row. Every kind of
// change is here: one added and not here fails.
func TestAnItemThatDoesNotReadIsGoneWhateverItsKind(t *testing.T) {
	t.Parallel()
	// Each kind's table, and a row of it of world w that does not read.
	cases := map[ChangeKind]func(w *heldWorld) (string, row){
		RecordChange: func(w *heldWorld) (string, row) {
			r := recordRow(w.rec)
			r["identity"] = []byte("not an identity document")
			return "mailboxes", r
		},
		RevocationsChange: func(w *heldWorld) (string, row) {
			return "revocations", row{"addr": w.a[:], "identity": "not the bytes of an identity document", "revocation": []byte("the identity's revocation")}
		},
		MessageChange: func(w *heldWorld) (string, row) {
			return "messages", row{"box": w.a[:], "id": make([]byte, 32), "size": int32(3), "received_at": "not a time"}
		},
		AccountChange: func(w *heldWorld) (string, row) {
			return "accounts", row{"id": w.acct, "rev": "two", "unmetered": true}
		},
	}
	for k := ChangeKind(1); int(k) <= numChangeKinds; k++ {
		t.Run(k.String(), func(t *testing.T) {
			c, ok := cases[k]
			if !ok {
				t.Fatalf("no row of kind %d that does not read", k)
			}
			w := newHeldWorld(t, false)
			table, r := c(w)
			ch, err := changeOf(table, r, false)
			if err != nil || ch.Kind != k || ch.Err == nil {
				t.Fatalf("control: the row decodes as %v of kind %d, error %v; want its kind, and an image that does not read", err, ch.Kind, ch.Err)
			}
			tok, atok := w.s.cache.begin(w.a), w.s.accCache.begin(w.acct)
			w.s.apply(ch)
			if k == AccountChange {
				if _, ok := w.s.accCache.get(w.acct); ok {
					t.Error("the account is still cached")
				}
				w.s.accCache.fill(&Account{ID: w.acct, Rev: 1}, atok)
				if _, ok := w.s.accCache.get(w.acct); ok {
					t.Error("a read of the account begun before the row puts its copy after it")
				}
				return
			}
			if w.s.idx.holdsMailbox(w.a) {
				t.Error("the index still holds the mailbox")
			}
			if _, ok := w.s.Known(w.a); ok {
				t.Error("the record cache still answers for the address")
			}
			w.s.cache.fill(w.rec, tok)
			if _, ok := w.s.Known(w.a); ok {
				t.Error("a read of the address begun before the row puts its copy after it")
			}
		})
	}
}

// The in-memory backend hands each change to memory after the write that
// made it has applied its own outcome, as the PostgreSQL feed brings a write
// back after it, and in the order the writes were made: at the start of the
// backend's next write. So a registration of an address a
// read found missing is cached by its own write, which its echo, applied
// first, would keep out by ending the miss; and two writes' changes go in
// the order they were made.
func TestTheInMemoryFeedComesAfterItsWritersApply(t *testing.T) {
	t.Parallel()
	_, _, rec := heldRecord(t)
	ctx := t.Context()
	s := NewMemStore(time.Now)
	b := s.backend.(*memBackend)
	var handed []uint64 // the revs of the records' changes handed to memory, in order
	b.apply = func(c Change) {
		if c.Mailbox != nil {
			handed = append(handed, c.Mailbox.Rev)
		}
		s.apply(c)
	}
	if _, err := s.Mailbox(ctx, rec.Addr); !errors.Is(err, ErrNotFound) {
		t.Fatalf("control: an address with no mailbox: %v", err)
	}
	if err := s.CreateMailbox(ctx, cloneMailbox(rec)); err != nil {
		t.Fatal(err)
	}
	if len(handed) != 0 {
		t.Errorf("a write's change was handed to memory before the write returned: %v", handed)
	}
	if got, ok := s.Known(rec.Addr); !ok || got == nil || got.Rev != 1 {
		t.Errorf("a registration of an address read missing is not cached by its own write: %v", got)
	}
	for rev := uint64(1); rev <= 2; rev++ {
		next := cloneMailbox(rec)
		next.Rev = rev
		if err := s.UpdateMailbox(ctx, next); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutAdoptKey(ctx, &AdoptKey{Account: "acct", Hash: [32]byte{1}, Uses: 1, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(handed, []uint64{1, 2, 3}) {
		t.Errorf("the records' changes were handed to memory as revs %v; want 1, 2, 3, each at the next write", handed)
	}
}
