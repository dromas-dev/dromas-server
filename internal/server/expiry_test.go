package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// stands reads a mailbox's record and the certificate its current statement is
// signed under, nil for the identity.
func (e *env) stands(a protocol.Address) (*Mailbox, *protocol.Certificate) {
	e.t.Helper()
	b, err := e.store.Mailbox(context.Background(), a)
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		e.t.Fatal(err)
	}
	_, signer, err := protocol.VerifyPrekeyRecord(id, b.Statement, b.Signature)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, signer.Certificate()
}

// A mailbox's record may go once nothing of the mailbox is valid any more
// (PROTOCOL.md §13): a registration and every renewal set its expiry to the
// later of its certificate's end and its prekey's last message.
func TestARecordExpiresWhenNothingOfTheMailboxIsValid(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	b, cert := e.stands(r.id.Address())
	if want := b.Prekey.NotAfter.Add(protocol.TTL); !b.Expires.Equal(want) || !want.After(cert.NotAfter()) {
		t.Fatalf("a registration's record expires %v, want its prekey's last message, %v, which is after its certificate's end %v", b.Expires, want, cert.NotAfter())
	}
	// A prekey that ends early leaves the certificate's end the later.
	r.prekey(2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 200, "")
	b, cert = e.stands(r.id.Address())
	if !b.Expires.Equal(cert.NotAfter()) || !cert.NotAfter().After(b.Prekey.NotAfter.Add(protocol.TTL)) {
		t.Fatalf("a renewal's record expires %v, want its certificate's end, %v", b.Expires, cert.NotAfter())
	}
	// A renewal for the full lifetime moves it back to its prekey's last message.
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "")
	if b, _ = e.stands(r.id.Address()); !b.Expires.Equal(b.Prekey.NotAfter.Add(protocol.TTL)) {
		t.Fatalf("a renewal for the full lifetime leaves the record expiring %v, want %v", b.Expires, b.Prekey.NotAfter.Add(protocol.TTL))
	}
}

// Once the TTL has deleted a mailbox's record, the mailbox is forgotten: its
// renewal is answered as for no mailbox, and it registers anew, its ACL and its
// account gone with the old one. What its identity revoked stays. A test
// makes the delete the TTL makes.
func TestAForgottenMailboxRegistersAnew(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/acl"), aclOf([]string{"*"}, nil), r.pass(1)), 200, "")
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), 200, "")
	r.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 200, "")
	if err := e.store.DeleteMailbox(ctx, r.id.Address()); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", r.path(""), nil, ""), 404, protocol.CodeNoSuchMailbox)
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 404, protocol.CodeNoSuchMailbox)
	r.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 401, protocol.CodeCertificateRevoked) // still held to what its identity revoked
	e.want(e.do("PUT", r.path(""), r.registration(3), r.pass(3)), 201, "")
	if got := e.do("GET", r.path("/acl"), nil, r.pass(3)); got.status != 200 || string(got.body) != `{"allow":["*"],"deny":[]}`+"\n" {
		t.Fatalf("a mailbox registered anew has an ACL: %d %s", got.status, got.body)
	}
	if b := held(t, e.do("GET", r.path(""), nil, "")); b == nil || len(b.RevokedCertificates) == 0 {
		t.Fatal("a mailbox registered anew is read without its identity's revocation of certificates")
	}
}

// In DynamoDB a mailbox's record carries its expiry as the TTL attribute, in
// seconds, and nothing its identity revoked, which is the item beside it
// (sk 0x01); a revocation of the address deletes the record and keeps the
// item. AWS only.
func TestTheRecordAndTheRevocationsAreTwoItems(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e, s := dynamoEnv(t)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), 200, "")
	get := func(key map[string]types.AttributeValue) item {
		t.Helper()
		out, err := s.dynamo().db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.dynamo().mailboxes, Key: key, ConsistentRead: aws.Bool(true)})
		if err != nil {
			t.Fatal(err)
		}
		return out.Item
	}
	recKey, revsKey := mailboxKey(r.id.Address()), revocationsKey(r.id.Address())
	rec, revs := get(recKey), get(revsKey)
	b, _ := e.stands(r.id.Address())
	if exp, err := rec.uint("expires_at"); err != nil || exp != uint64(b.Expires.Unix()) {
		t.Fatalf("the record's TTL attribute is %d (%v), want %d", exp, err, b.Expires.Unix())
	}
	for _, name := range []string{"revocation", "revoked_certs", "revoked_certs_sig", "through"} {
		if _, ok := rec[name]; ok {
			t.Errorf("the record carries %s", name)
		}
	}
	if through, err := revs.uint("through"); err != nil || through != 1 {
		t.Fatalf("the revocations item: through %d, %v", through, err)
	}
	if _, ok := revs["expires_at"]; ok {
		t.Error("the revocations item has an expiry")
	}
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), 201, "")
	if get(recKey) != nil {
		t.Error("the revocation of the address left the mailbox's record")
	}
	if revs = get(revsKey); revs == nil {
		t.Fatal("the revocation of the address left no revocations item")
	}
	if _, ok := revs["revocation"]; !ok {
		t.Error("the revocations item does not keep the revocation of the address")
	}
}

// A second process that holds a mailbox learns from the stream what another
// wrote: a revocation of the mailbox's certificates, and the revocation of its
// address, each answered from its memory once it arrives. AWS only.
func TestASecondProcessLearnsWhatIsRevoked(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	other := startDynamo(t, e.clock.Now)
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	// within waits up to ten seconds for the second process to answer as
	// want: the stream is read every 200 ms.
	within := func(what string, call func() reply, status int, code protocol.Code) {
		t.Helper()
		var r reply
		for range 100 {
			if r = call(); r.status == status && r.code() == code {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: the second process answers %d %s, want %d %s", what, r.status, r.code(), status, code)
	}

	certs := e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(r *raw) func() reply {
		return func() reply {
			return e2.do("GET", r.path("/messages"), nil, e2.passFor(r.by[1], r.id.Address(), e2.name()))
		}
	}
	e2.want(poll(certs)(), 200, "") // the second process holds it
	e.want(e.do("PUT", certs.path("/revocations"), certs.certs(1), ""), 200, "")
	within("the mailbox's certificate revoked", poll(certs), 401, protocol.CodeCertificateRevoked)

	revoked := e.raw().register(protocol.MaxPrekeyLifetime)
	e2.want(poll(revoked)(), 200, "")
	rev, err := protocol.SignRevocation(revoked.signer, revoked.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", revoked.path("/revocations"), protocol.Revocations{Identity: revoked.id.Document(), Revocation: rev}, ""), 201, "")
	within("the address revoked", poll(revoked), 410, protocol.CodeRevoked)
}

// readsCounted is a backend that counts the reads of an address and of a
// mailbox's live messages: what a poll would make if it left the process.
type readsCounted struct {
	Backend
	reads atomic.Int64
}

func (b *readsCounted) ReadAddress(ctx context.Context, a protocol.Address) (*Mailbox, *Revocations, error) {
	b.reads.Add(1)
	return b.Backend.ReadAddress(ctx, a)
}

func (b *readsCounted) ReadLive(ctx context.Context, mailbox protocol.Address) ([]Header, error) {
	b.reads.Add(1)
	return b.Backend.ReadLive(ctx, mailbox)
}

// A second process in the window a revocation of an address opens there
// (dromas-dev/dromas-client#365, #505): it holds the mailbox, its record cache
// has lost the record, as --mailbox-cache's LRU does under load, and its feed
// brings the image of the revocations item before the purge's deletion of
// the record, two items whose changes DynamoDB Streams orders each alone.
// In the window its poll is 410 revoked from memory, with no read, and
// carries no record (revokedAt), and the read of the mailbox is 410 with the
// record. Once the deletion comes, the poll reads the address and carries
// the record too. Two memories over one in-memory backend, the second's
// feed handed over by the test in that order.
func TestASecondProcessInARevocationsWindow(t *testing.T) {
	t.Parallel()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	b := newMemBackend(clk.Now)
	first := newMemory(clk.Now, DefaultMailboxCache, nil, nil)
	first.backend = b
	counted := &readsCounted{Backend: b}
	second := newMemory(clk.Now, DefaultMailboxCache, nil, nil)
	second.backend = counted
	var mu sync.Mutex
	var feed []Change // the second's, not yet applied
	_ = b.Start(context.Background(), func(c Change) {
		first.apply(c)
		mu.Lock()
		feed = append(feed, c)
		mu.Unlock()
	})
	// deliver applies to the second every change made so far, in order, but
	// those hold keeps back, which it returns.
	deliver := func(hold func(Change) bool) []Change {
		b.deliver()
		mu.Lock()
		cs := feed
		feed = nil
		mu.Unlock()
		var held []Change
		for _, c := range cs {
			if hold(c) {
				held = append(held, c)
				continue
			}
			second.apply(c)
		}
		return held
	}
	serve := func(m *Memory) *env {
		srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: m, Limits: relaxed(), Now: clk.Now}).Handler()))
		t.Cleanup(srv.Close)
		return &env{t: t, clock: clk, srv: srv}
	}
	e, e2 := serve(first), serve(second)

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	deliver(func(Change) bool { return false })
	poll := func() reply { return e2.do("GET", r.path("/messages"), nil, e2.passFor(r.by[1], a, e2.name())) }
	e2.want(poll(), http.StatusOK, "")       // the second process holds the mailbox
	second.cache.write(a, evicted[*Mailbox]) // and its record cache loses it
	sig, err := protocol.SignRevocation(r.signer, a)
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	deletion := deliver(func(c Change) bool { return c.Kind == RecordChange && c.Gone })
	if len(deletion) != 1 {
		t.Fatalf("the revocation's purge deleted the record %d times", len(deletion))
	}
	if st, ok := second.Held(a); !ok || st.State != Revoked {
		t.Fatalf("the second process holds the address as %+v, %v: not the window", st, ok)
	}
	if rec, ok := second.Known(a); ok {
		t.Fatalf("the second process's record cache holds %+v: not the window", rec)
	}

	before := counted.reads.Load()
	got := poll()
	e2.want(got, http.StatusGone, protocol.CodeRevoked)
	if n := counted.reads.Load() - before; n != 0 {
		t.Errorf("the poll in the window read the store %d times", n)
	}
	if held(t, got) != nil {
		t.Error("the poll in the window carries a record, which memory does not hold")
	}
	read := e2.do("GET", r.path(""), nil, "")
	e2.want(read, http.StatusGone, protocol.CodeRevoked)
	if rec := held(t, read); rec == nil || !bytes.Equal(rec.Revocation, sig) || !bytes.Equal(rec.Identity, r.id.Document()) {
		t.Errorf("the read in the window carries %s, want the revocation", read.body)
	}

	second.apply(deletion[0])
	got = poll()
	e2.want(got, http.StatusGone, protocol.CodeRevoked)
	if rec := held(t, got); rec == nil || !bytes.Equal(rec.Revocation, sig) {
		t.Errorf("the poll after the window carries %s, want the revocation", got.body)
	}
}
