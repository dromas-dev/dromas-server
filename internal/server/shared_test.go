package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

// Helpers the tests of several files share.

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

// held is the revocation record a read of a mailbox (GET /v1/<address>) shows,
// read as a client reads it: the 200's revocation of certificates, or the
// 410's record. Nil when it shows none.
func held(t *testing.T, r reply) *protocol.Revocations {
	t.Helper()
	switch r.status {
	case 200:
		var b protocol.MailboxResponse
		if err := protocol.Unmarshal(r.body, &b); err != nil {
			t.Fatalf("the read of a mailbox: %v: %s", err, r.body)
		}
		return b.Record()
	case 410:
		var p protocol.Problem
		if err := protocol.Unmarshal(r.body, &p); err != nil {
			t.Fatalf("the read of a revoked mailbox: %v: %s", err, r.body)
		}
		return p.Record
	}
	t.Fatalf("the read of a mailbox: %d %s", r.status, r.body)
	return nil
}

// record is a mailbox's own revocation, as its owner makes it.
func record(t *testing.T, b *client.Mailbox) *protocol.Revocations {
	t.Helper()
	rec, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// aclOf is an ACL document: the lists as given.
func aclOf(allow, deny []string) protocol.ACLDocument {
	return protocol.ACLDocument{Allow: allow, Deny: deny}
}

// aclReply reads an ACL document out of an answer.
func aclReply(t *testing.T, r reply) protocol.ACLDocument {
	t.Helper()
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(r.body, &d); err != nil {
		t.Fatalf("not an ACL document: %v: %s", err, r.body)
	}
	return d
}

// sealTo is a send to mailbox to, as the server sees one: an age file to its
// current prekey under both its serials. What is inside is the recipient's
// to judge, so a test needs nothing more.
func (e *env) sealTo(to *client.Mailbox) sealed {
	e.t.Helper()
	b, err := e.store.Mailbox(context.Background(), to.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	rcpt, err := b.Prekey.Recipient()
	if err != nil {
		e.t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rcpt)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return sealedTo(e.statement(to.Address()), ct.Bytes())
}

// certs is the revocation of r's certificates through a serial, signed by its
// identity, in the record that carries it; r signs every statement after it
// under a certificate (raw.certified).
func (r *raw) certs(through uint64) protocol.Revocations {
	r.e.t.Helper()
	r.underCertificates = true
	l, err := protocol.NewRevokedCertificates(r.id.Address(), through)
	if err != nil {
		r.e.t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(r.signer, l)
	if err != nil {
		r.e.t.Fatal(err)
	}
	return protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: l.Statement(), RevokedCertificatesSignature: sig}
}

// sealFor is an age file sealed to raw mailbox to's prekey of the given serial.
func sealFor(t *testing.T, to *raw, serial uint64) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return ct.Bytes()
}

// sendTo posts an age file sealed to to's statement of the given serial,
// naming it, with a pass by the signer of from's statement fromSerial.
func (e *env) sendTo(to *raw, serial uint64, from *raw, fromSerial uint64) reply {
	e.t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return e.do("POST", to.path("/messages"), to.sealed(serial, ct.Bytes()), from.pass(fromSerial))
}

// accountEnv is an env with an account, unmetered or not, and an adopt key
// into it with the given uses.
func accountEnv(t *testing.T, e *env, unmetered bool, uses int) (*Account, string) {
	t.Helper()
	ctx := context.Background()
	id, err := NewAccountID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAccount(id, unmetered)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateAccount(ctx, &Account{ID: id}); !errors.Is(err, ErrExists) {
		t.Fatalf("the account again: %v", err)
	}
	return a, e.adoptKey(t, id, uses, time.Hour)
}

func adopt(t *testing.T, b *client.Mailbox, key string) string {
	t.Helper()
	acc, err := b.Adopt(context.Background(), key)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	return acc
}

// counted is a second server on e's store and keys, with its own limits'
// state, whose storage calls are counted.
func counted(t *testing.T, e *env, l Limits) (*env, *countingStore) {
	t.Helper()
	fed(t, e.store)
	cs := &countingStore{s: e.store}
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: cs, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	return &env{t: t, clock: e.clock, srv: srv}, cs
}

func listOf(t *testing.T, r reply) protocol.MessageList {
	t.Helper()
	var l protocol.MessageList
	if err := json.Unmarshal(r.body, &l); err != nil {
		t.Fatalf("%d %s: %v", r.status, r.body, err)
	}
	return l
}

// metered is a test server whose metrics are m, on a registry of their own.
func metered(t *testing.T, l Limits) (*env, *Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	return newEnv(t, l, func(c *Config) { c.Metrics = m }), m, reg
}

// fault is what the injector makes of a write: its outcome, as Backend
// names them.
type fault int

func (f fault) String() string {
	return [...]string{"as is", "refused", "unknown before applying", "unknown after applying"}[f]
}

// errInjected is the injector's error of no kind.
var errInjected = errors.New("injected: an error the backend states nothing of")

// errStated is a refusal the store stated, for a write with no condition of
// its own: a statement the database rolled back.
var errStated = refused(errors.New("the database refused the statement"))

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

func (f *faults) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, uint64, error) {
	var held *Revocations
	var rev uint64
	err := f.write("Revoke", func() (err error) {
		held, rev, err = f.Backend.Revoke(ctx, a, rv, want)
		return err
	})
	return held, rev, err
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

func (f *faults) Retire(ctx context.Context, mailbox protocol.Address, id [32]byte, received time.Time) (time.Time, error) {
	var at time.Time
	err := f.write("Retire", func() (err error) {
		at, err = f.Backend.Retire(ctx, mailbox, id, received)
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

func (e *env) adoptKey(t *testing.T, account string, uses int, ttl time.Duration) string {
	t.Helper()
	key, hash, err := NewAdoptKey(account)
	if err != nil {
		t.Fatal(err)
	}
	k := &AdoptKey{Account: account, Hash: hash, Uses: uses, Expires: e.clock.Now().Add(ttl)}
	if err := e.store.PutAdoptKey(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutAdoptKey(context.Background(), k); !errors.Is(err, ErrExists) {
		t.Fatalf("the key again: %v", err)
	}
	return key
}

const (
	asIs          fault = iota
	refusedBefore       // refused, with the write's own refusal, nothing applied
	unknownBefore       // an error the backend states nothing of, nothing applied
	unknownAfter        // applied, then an error the backend states nothing of
)

func idOf(t *testing.T, r *protocol.Receipt) [32]byte {
	t.Helper()
	var id [32]byte
	copy(id[:], mustHex(t, r.ID))
	return id
}

// countingStore counts every call of a Store that reaches storage. It does
// not embed the Store, so each method is written here, and a new one is
// counted or not by a choice made where it is added: those Memory
// answers from memory (the index and the record cache, after a mailbox's one
// load on its first use) are not counted.
type countingStore struct {
	s     Store
	calls atomic.Int64
}

func (c *countingStore) count() { c.calls.Add(1) }

func (c *countingStore) Held(a protocol.Address) (Standing, bool) { return c.s.Held(a) }

func (c *countingStore) Changed(a protocol.Address) <-chan struct{} { return c.s.Changed(a) }

func (c *countingStore) NextExpiry(a protocol.Address) time.Time { return c.s.NextExpiry(a) }

func (c *countingStore) Known(a protocol.Address) (*Mailbox, bool) { return c.s.Known(a) }

func (c *countingStore) Begin(a protocol.Address) uint64 { return c.s.Begin(a) }

func (c *countingStore) Count(ctx context.Context, mailbox protocol.Address) (int, error) {
	return c.s.Count(ctx, mailbox)
}

func (c *countingStore) After(ctx context.Context, mailbox protocol.Address, cur *Cursor) (int, error) {
	return c.s.After(ctx, mailbox, cur)
}

func (c *countingStore) Holds(ctx context.Context, mailbox protocol.Address, id [32]byte) (bool, error) {
	return c.s.Holds(ctx, mailbox, id)
}

func (c *countingStore) Fetched(ctx context.Context, mailbox protocol.Address, id [32]byte) (bool, bool, error) {
	return c.s.Fetched(ctx, mailbox, id)
}

func (c *countingStore) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	c.count()
	return c.s.Mailbox(ctx, a)
}

func (c *countingStore) CreateMailbox(ctx context.Context, b *Mailbox) error {
	c.count()
	return c.s.CreateMailbox(ctx, b)
}

func (c *countingStore) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	c.count()
	return c.s.UpdateMailbox(ctx, b)
}

func (c *countingStore) DeleteMailbox(ctx context.Context, a protocol.Address) error {
	c.count()
	return c.s.DeleteMailbox(ctx, a)
}

func (c *countingStore) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) error {
	c.count()
	return c.s.Revoke(ctx, a, rv, want)
}

func (c *countingStore) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	c.count()
	return c.s.Dedupe(ctx, mailbox, id)
}

func (c *countingStore) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	c.count()
	return c.s.PutMessage(ctx, mailbox, h, body)
}

func (c *countingStore) List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	c.count()
	return c.s.List(ctx, mailbox, after, limit, consistent)
}

func (c *countingStore) Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	c.count()
	return c.s.Message(ctx, mailbox, id, from)
}

func (c *countingStore) DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) error {
	c.count()
	return c.s.DeleteMessage(ctx, mailbox, id)
}

func (c *countingStore) DeleteMessages(ctx context.Context, mailbox protocol.Address) error {
	c.count()
	return c.s.DeleteMessages(ctx, mailbox)
}

func (c *countingStore) Account(ctx context.Context, id string) (*Account, error) {
	c.count()
	return c.s.Account(ctx, id)
}

func (c *countingStore) CreateAccount(ctx context.Context, a *Account) error {
	c.count()
	return c.s.CreateAccount(ctx, a)
}

func (c *countingStore) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	c.count()
	return c.s.PutAdoptKey(ctx, k)
}

func (c *countingStore) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	c.count()
	return c.s.AdoptKey(ctx, account, hash)
}

func (c *countingStore) Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error {
	c.count()
	return c.s.Adopt(ctx, b, account, key)
}

func (c *countingStore) Leave(ctx context.Context, b *Mailbox) error {
	c.count()
	return c.s.Leave(ctx, b)
}
