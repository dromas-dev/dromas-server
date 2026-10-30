package server

// The store's backends, and the boundary between them and memory: the
// injector of faults at it, which every test of what memory makes of a
// write's outcome or of a read's answer uses, and the stream's records as
// the DynamoDB backend hands them to memory.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

// dynamo is the DynamoDB backend s is over.
func (s *Memory) dynamo() *dynamoBackend { return s.backend.(*dynamoBackend) }

// onDynamo is the store as memory over the DynamoDB backend, if it is.
func onDynamo(st Store) (*Memory, bool) {
	s, ok := st.(*Memory)
	if !ok {
		return nil, false
	}
	_, ok = s.backend.(*dynamoBackend)
	return s, ok
}

// applyMailboxRecord applies a record of the --mailboxes-table stream as the
// DynamoDB backend's feed hands it to memory.
func (s *Memory) applyMailboxRecord(r stypes.Record) { s.applyStream(mailboxStreamChange(r)) }

// applyMsgRecord is applyMailboxRecord for the --messages-table stream.
func (s *Memory) applyMsgRecord(r stypes.Record) { s.applyStream(msgStreamChange(r)) }

// applyAccountRecord is applyMailboxRecord for the --accounts-table stream.
func (s *Memory) applyAccountRecord(r stypes.Record) { s.applyStream(accountStreamChange(r)) }

func (s *Memory) applyStream(c Change, err error) {
	if err == nil && c.Kind != 0 {
		s.apply(c)
	}
}

// applyMailboxImage applies an item of the --mailboxes-table table as it now is, as
// the stream's image of it.
func (s *Memory) applyMailboxImage(it item) {
	s.applyMailboxRecord(stypes.Record{EventName: stypes.OperationTypeModify, Dynamodb: &stypes.StreamRecord{NewImage: toStream(it)}})
}

// toStream is an item as a stream's image carries it.
func toStream(it item) map[string]stypes.AttributeValue {
	out := map[string]stypes.AttributeValue{}
	for k, v := range it {
		if c := toStreamAV(v); c != nil {
			out[k] = c
		}
	}
	return out
}

// toStreamAV is fromStream's convertAV, the other way.
func toStreamAV(v types.AttributeValue) stypes.AttributeValue {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return &stypes.AttributeValueMemberB{Value: v.Value}
	case *types.AttributeValueMemberS:
		return &stypes.AttributeValueMemberS{Value: v.Value}
	case *types.AttributeValueMemberN:
		return &stypes.AttributeValueMemberN{Value: v.Value}
	case *types.AttributeValueMemberBOOL:
		return &stypes.AttributeValueMemberBOOL{Value: v.Value}
	case *types.AttributeValueMemberL:
		l := make([]stypes.AttributeValue, 0, len(v.Value))
		for _, e := range v.Value {
			if c := toStreamAV(e); c != nil {
				l = append(l, c)
			}
		}
		return &stypes.AttributeValueMemberL{Value: l}
	case *types.AttributeValueMemberM:
		return &stypes.AttributeValueMemberM{Value: toStream(v.Value)}
	}
	return nil
}

// fault is what the injector makes of a write: its outcome, as Backend
// names them.
type fault int

const (
	asIs          fault = iota
	refusedBefore       // refused, with the write's own refusal, nothing applied
	unknownBefore       // an error the backend states nothing of, nothing applied
	unknownAfter        // applied, then an error the backend states nothing of
)

func (f fault) String() string {
	return [...]string{"as is", "refused", "unknown before applying", "unknown after applying"}[f]
}

// errInjected is the injector's error of no kind.
var errInjected = errors.New("injected: an error the backend states nothing of")

// errStated is a refusal AWS stated, for a write with no condition of its
// own: a throttle, or an answer of 4xx to the call.
var errStated = refused(errors.New("AWS throttled the call"))

// faults wraps a backend, and makes any write's outcome what a test asks of
// it, and runs a hook at a read's answer: after the backend answered, before
// memory has the answer. It stands where every fault of a backend reaches
// memory (dromas-dev/dromas-client#407 item 4).
type faults struct {
	Backend
	mu     sync.Mutex
	writes map[string]fault // by the Backend method's name
	refuse map[string]error // the refusal a write states, if not its own
	// read, if set, runs at each read's answer, with the method's name.
	read func(method string)
	// wrote counts the writes that reached the injector, whatever their
	// outcome: every write the store makes of its backend.
	wrote atomic.Int64
}

// injectFaults puts an injector between s and its backend.
func injectFaults(s *Memory) *faults {
	f := &faults{Backend: s.backend, writes: map[string]fault{}, refuse: map[string]error{}}
	s.backend = f
	return f
}

// set makes method's outcome f, until set again.
func (f *faults) set(method string, x fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes[method] = x
}

// ownRefusal is the refusal each write states of itself.
var ownRefusal = map[string]error{
	"CreateMailbox": ErrExists,
	"UpdateMailbox": ErrStale,
	"DeleteMailbox": errStated,
	"Revoke":        ErrStale,
	"Adopt":         ErrStale,
	"Leave":         ErrStale,
	"CreateAccount": ErrExists,
	"PutAdoptKey":   ErrExists,
	"PutMessage":    errNotStored,
	"Retire":        ErrNotFound,
	"DeleteMessage": ErrNotFound,
	"DeleteAll":     errStated,
}

// write runs do as method's fault says.
func (f *faults) write(method string, do func() error) error {
	f.wrote.Add(1)
	f.mu.Lock()
	x, ref := f.writes[method], f.refuse[method]
	f.mu.Unlock()
	if ref == nil {
		ref = ownRefusal[method]
	}
	switch x {
	case refusedBefore:
		return ref
	case unknownBefore:
		return errInjected
	case unknownAfter:
		if err := do(); err != nil {
			return err
		}
		return errInjected
	}
	return do()
}

// answered runs the read hook at method's answer.
func (f *faults) answered(method string) {
	f.mu.Lock()
	h := f.read
	f.mu.Unlock()
	if h != nil {
		h(method)
	}
}

func (f *faults) ReadAddress(ctx context.Context, a protocol.Address) (*Mailbox, *Revocations, error) {
	b, rv, err := f.Backend.ReadAddress(ctx, a)
	f.answered("ReadAddress")
	return b, rv, err
}

func (f *faults) ReadLive(ctx context.Context, mailbox protocol.Address) ([]Header, error) {
	hs, err := f.Backend.ReadLive(ctx, mailbox)
	f.answered("ReadLive")
	return hs, err
}

func (f *faults) List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	hs, err := f.Backend.List(ctx, mailbox, after, limit, consistent)
	f.answered("List")
	return hs, err
}

func (f *faults) Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, body, err := f.Backend.Message(ctx, mailbox, id, from)
	f.answered("Message")
	return h, body, err
}

func (f *faults) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	h, err := f.Backend.Dedupe(ctx, mailbox, id)
	f.answered("Dedupe")
	return h, err
}

func (f *faults) Account(ctx context.Context, id string) (*Account, error) {
	a, err := f.Backend.Account(ctx, id)
	f.answered("Account")
	return a, err
}

func (f *faults) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	k, err := f.Backend.AdoptKey(ctx, account, hash)
	f.answered("AdoptKey")
	return k, err
}

func (f *faults) CreateMailbox(ctx context.Context, b *Mailbox) error {
	return f.write("CreateMailbox", func() error { return f.Backend.CreateMailbox(ctx, b) })
}

func (f *faults) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	return f.write("UpdateMailbox", func() error { return f.Backend.UpdateMailbox(ctx, b) })
}

func (f *faults) DeleteMailbox(ctx context.Context, a protocol.Address) error {
	return f.write("DeleteMailbox", func() error { return f.Backend.DeleteMailbox(ctx, a) })
}

func (f *faults) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, error) {
	var held *Revocations
	err := f.write("Revoke", func() (err error) {
		held, err = f.Backend.Revoke(ctx, a, rv, want)
		return err
	})
	return held, err
}

func (f *faults) Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error {
	return f.write("Adopt", func() error { return f.Backend.Adopt(ctx, b, account, key) })
}

func (f *faults) Leave(ctx context.Context, b *Mailbox) error {
	return f.write("Leave", func() error { return f.Backend.Leave(ctx, b) })
}

func (f *faults) CreateAccount(ctx context.Context, a *Account) error {
	return f.write("CreateAccount", func() error { return f.Backend.CreateAccount(ctx, a) })
}

func (f *faults) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	return f.write("PutAdoptKey", func() error { return f.Backend.PutAdoptKey(ctx, k) })
}

func (f *faults) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) error {
	return f.write("PutMessage", func() error { return f.Backend.PutMessage(ctx, mailbox, h, body) })
}

func (f *faults) Retire(ctx context.Context, mailbox protocol.Address, id [32]byte) (time.Time, error) {
	var at time.Time
	err := f.write("Retire", func() (err error) {
		at, err = f.Backend.Retire(ctx, mailbox, id)
		return err
	})
	return at, err
}

func (f *faults) DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) (time.Time, error) {
	var at time.Time
	err := f.write("DeleteMessage", func() (err error) {
		at, err = f.Backend.DeleteMessage(ctx, mailbox, id)
		return err
	})
	return at, err
}

func (f *faults) DeleteAll(ctx context.Context, mailbox protocol.Address, retired func([32]byte, time.Time)) error {
	return f.write("DeleteAll", func() error { return f.Backend.DeleteAll(ctx, mailbox, retired) })
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
			b.CertSerial += 10
			return nil, w.s.UpdateMailbox(ctx, b)
		}, refusals: []error{ErrStale}, applied: func(w *heldWorld) string {
			if b := cached(w); b == nil || b.Rev != w.rec.Rev+1 || b.CertSerial != w.rec.CertSerial+10 {
				return "the cache does not hold the record written"
			}
			if st, _ := w.s.Held(w.a); st.CertSerial != w.rec.CertSerial+10 {
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
			return nil, w.s.retire(ctx, w.a, w.msgs[0].ID)
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
var backendReads = []string{"ReadAddress", "ReadLive", "List", "Message", "Dedupe", "Account", "AdoptKey", "Start", "Ready"}

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
					case refusal != nil:
						if !loaded {
							t.Errorf("refused: the index dropped the mailbox")
						}
						if st, _ := w.s.Held(w.a); c.on == onMailbox && st != w.standing {
							t.Errorf("refused: the index holds the mailbox's standing %+v, not %+v as before", st, w.standing)
						}
						if stale && cachedOK {
							t.Errorf("refused for its condition: the record cache still holds the copy from before it")
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

// Every change memory applies to a mailbox wakes the lists held on it
// (PROTOCOL.md §11.11): every write of the Backend that targets a mailbox,
// applied or of an outcome unknown, as backendWrites makes each (held to
// the interface's methods by TestEveryWriteOfTheBackendReachesMemoryByIts
// Outcome); and every kind of change the backend's feed hands memory, its
// item as it now is, gone, and one that does not read. Each kind is here:
// one added and not here fails.
func TestEveryChangeMemoryAppliesToAMailboxWakesItsHeldLists(t *testing.T) {
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
					t.Error("a list held on the mailbox is not woken")
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
					t.Error("a list held on the mailbox is not woken")
				}
			})
		}
	}
}

// An item of the backend's that does not read is applied as one gone,
// whatever its kind: the address forgotten, the record cache and the index
// both, or the account evicted, each counted so that a read begun before it
// puts nothing (dromas-dev/dromas-client#407 item 1). Each kind's item
// comes as the DynamoDB backend decodes its stream's record. Every kind of
// change is here: one added and not here fails.
func TestAnItemThatDoesNotReadIsGoneWhateverItsKind(t *testing.T) {
	t.Parallel()
	b := func(v []byte) stypes.AttributeValue { return &stypes.AttributeValueMemberB{Value: v} }
	s := func(v string) stypes.AttributeValue { return &stypes.AttributeValueMemberS{Value: v} }
	modify := func(img map[string]stypes.AttributeValue) stypes.Record {
		return stypes.Record{EventName: stypes.OperationTypeModify, Dynamodb: &stypes.StreamRecord{NewImage: img}}
	}
	// Each kind's record of an item of world w that does not read, and the
	// decoder of its stream.
	cases := map[ChangeKind]func(w *heldWorld) (func(stypes.Record) (Change, error), stypes.Record){
		RecordChange: func(w *heldWorld) (func(stypes.Record) (Change, error), stypes.Record) {
			img := toStream(mailboxItem(w.rec))
			img["state"] = s("deleted") // a state this build never writes
			return mailboxStreamChange, modify(img)
		},
		RevocationsChange: func(w *heldWorld) (func(stypes.Record) (Change, error), stypes.Record) {
			return mailboxStreamChange, modify(map[string]stypes.AttributeValue{"addr": b(w.a[:]), "sk": b([]byte{skRevocations}),
				"identity": s("not the bytes of an identity document"), "revocation": b([]byte("the identity's revocation"))})
		},
		MessageChange: func(w *heldWorld) (func(stypes.Record) (Change, error), stypes.Record) {
			return msgStreamChange, modify(map[string]stypes.AttributeValue{"box": b(w.a[:]), "id": b(make([]byte, 32)),
				"size": &stypes.AttributeValueMemberN{Value: "3"}, "received_at": s("not a number")})
		},
		AccountChange: func(w *heldWorld) (func(stypes.Record) (Change, error), stypes.Record) {
			return accountStreamChange, modify(map[string]stypes.AttributeValue{"account": b([]byte(w.acct)), "sk": b([]byte{skAccount}),
				"rev": s("two"), "unmetered": &stypes.AttributeValueMemberBOOL{Value: true}})
		},
	}
	for k := ChangeKind(1); int(k) <= numChangeKinds; k++ {
		t.Run(k.String(), func(t *testing.T) {
			c, ok := cases[k]
			if !ok {
				t.Fatalf("no item of kind %d that does not read", k)
			}
			w := newHeldWorld(t, false)
			decode, r := c(w)
			ch, err := decode(r)
			if err != nil || ch.Kind != k || ch.Err == nil {
				t.Fatalf("control: the record decodes as %v of kind %d, error %v; want its kind, and an image that does not read", err, ch.Kind, ch.Err)
			}
			tok, atok := w.s.cache.begin(w.a), w.s.accCache.begin(w.acct)
			w.s.apply(ch)
			if k == AccountChange {
				if _, ok := w.s.accCache.get(w.acct); ok {
					t.Error("the account is still cached")
				}
				w.s.accCache.fill(&Account{ID: w.acct, Rev: 1}, atok)
				if _, ok := w.s.accCache.get(w.acct); ok {
					t.Error("a read of the account begun before the item puts its copy after it")
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
				t.Error("a read of the address begun before the item puts its copy after it")
			}
		})
	}
}

// The in-memory backend hands each change to memory after the write that
// made it has applied its own outcome, as DynamoDB's stream brings a write
// back a second or two after it, and in the order the writes were made: at
// the start of the backend's next write. So a registration of an address a
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
