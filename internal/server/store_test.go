package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// recordRow is mailbox b's row of the mailboxes table, each column as a
// read of the table and the feed hand it over (rowsOf, pgFeed.row).
func recordRow(b *Mailbox) row {
	r := row{
		"addr": bytes.Clone(b.Addr[:]), "identity": b.Identity, "created": msTime(b.Created),
		"statement": b.Statement, "statement_sig": b.Signature, "rank": numeric(b.Rank), "signer": bytes.Clone(b.Signer[:]),
		"senders": sendersColumn(b), "retired": json.RawMessage(retiredColumn(b)), "acl": nil, "account": nil, "expires_at": nil, "rev": toInt(b.Rev),
	}
	if acl := aclColumn(b); acl != nil {
		r["acl"] = json.RawMessage(acl)
	}
	if acc := accountColumn(b); acc != nil {
		r["account"] = *acc
	}
	if exp := expiresColumn(b); exp != nil {
		r["expires_at"] = *exp
	}
	return r
}

// applyRow applies a row of table as the feed hands it to memory: changed,
// or gone (pgFeed.change).
func (s *Memory) applyRow(table string, r row, gone bool) {
	if c, err := changeOf(table, r, gone); err == nil && c.Kind != 0 {
		s.apply(c)
	}
}

// applyImage applies mailbox b's record as the feed's image of it.
func (s *Memory) applyImage(b *Mailbox) { s.applyRow("mailboxes", recordRow(b), false) }

// Each crash point between the writes, then the retry.

func TestCrashAfterTheBody(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	a, b := e.mailbox(), e.mailbox()
	failOnce(s, "put: after the body")
	if _, err := a.Send(context.Background(), b.Address(), "an orphan body first"); err == nil {
		t.Fatal("the crash was not reported")
	}
	if rs, err := a.Flush(context.Background()); err != nil || len(rs) != 1 {
		t.Fatalf("retry: %v", err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
}

// An ack deletes the message's row and its body, and nothing of it is kept
// (PROTOCOL.md §13): the same bytes posted after it are a new message,
// stored again under a body key of its own, listed and served, which the
// reader skips, and acks (§11.10 step 6, §12.3 check 8). A message's row
// holds its id, size and times, and nothing that names a sender or holds a
// signature.
func TestTheSameBytesAfterAnAckAreANewMessage(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, a, b, "once")
	e.setMiddle(nil)
	id := sha256.Sum256(sent.ciphertext)
	if cols := slices.Sorted(maps.Keys(s.storedMsg(t, b.Address(), id))); !slices.Equal(cols, []string{"box", "id", "nonce", "received_at", "size"}) {
		t.Fatalf("a message's row holds %v", cols)
	}
	first := s.bodyKeyOf(t, b.Address(), id)
	receive(t, b)
	if r := s.storedMsg(t, b.Address(), id); r != nil {
		t.Fatalf("the ack left the row: %v", r)
	}
	if s.hasBody(t, first) {
		t.Fatal("the ack left the body")
	}
	if err := s.DeleteMessage(ctx, b.Address(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second ack: %v", err)
	}
	e.clock.Add(time.Second)
	if r := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a)); r.status != http.StatusCreated {
		t.Fatalf("the same bytes after the ack: %d %s; want 201", r.status, r.body)
	}
	// In the table, too: memory's tomb for the ack would hide a message the
	// post listed again, until the feed brought it.
	if s.storedMsg(t, b.Address(), id) == nil || !s.bodyExists(t, b.Address(), id) {
		t.Fatal("the same bytes after the ack are not listed, or have no body")
	}
	if again := s.bodyKeyOf(t, b.Address(), id); again == first {
		t.Fatalf("the same bytes after the ack are kept under the first send's body key %s", first)
	}
	if _, body, err := s.Message(ctx, b.Address(), id, 0); err != nil || !bytes.Equal(body, sent.ciphertext) {
		t.Fatalf("the same bytes after the ack are not served: %v", err)
	}
	if n, _ := s.Count(ctx, b.Address()); n != 1 {
		t.Fatalf("memory counts %d; want the one posted again", n)
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatalf("the same bytes after the ack were delivered again: %d", len(res.Delivered))
	}
	if s.storedMsg(t, b.Address(), id) != nil {
		t.Fatal("the reader left the same bytes listed")
	}
}

// An ack deletes the message's row, then its body: a crash between leaves
// the ack done, the message out of the list and its body kept under a key
// no row names, for the collection by age; never a listed message without
// its body.
func TestCrashBetweenAnAcksDeletes(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "acked halfway"))
	key := s.bodyKeyOf(t, b.Address(), id)
	failOnce(s, "ack: after the row")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("first drain: delivered %d", len(res.Delivered))
	}
	if n, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("the message stayed in the list")
	}
	if r := s.storedMsg(t, b.Address(), id); r != nil {
		t.Fatalf("the ack left the row: %v", r)
	}
	if !s.hasBody(t, key) {
		t.Fatal("control: the crash between the deletes left no body")
	}
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Duplicates) != 0 || len(res.Refused) != 0 {
		t.Fatalf("second drain: %+v", res)
	}
}

func TestHeaderWithoutBodyIsGone(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "its body goes early"))
	if _, _, err := s.Message(ctx, b.Address(), id, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.pg().bodies.Delete(ctx, s.bodyKeyOf(t, b.Address(), id)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch: %v, want gone", err)
	}
	if s.storedMsg(t, b.Address(), id) != nil {
		t.Fatal("the bodiless message is still listed")
	}
	if n, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("still counted")
	}
}

// An acked message is never served, even with a body under its key: the
// ack deleted its row, and the row is what says a message is live.
func TestAckedMessageWithABodyAgainIsGone(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "acked, then its body written again"))
	key := s.bodyKeyOf(t, b.Address(), id)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	if err := s.pg().bodies.Put(ctx, key, []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch of an acked message: %v", err)
	}
}

// Two processes on one database: what one writes reaches the other through
// the feed, and an id the other has not heard of yet is read by its key.
func TestTwoProcesses(t *testing.T) {
	t.Parallel()
	e, _ := sharedEnv(t)
	ctx := context.Background()
	other := startPostgres(t, e.clock.Now)
	srv2 := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	t.Cleanup(srv2.Close)
	e2 := &env{t: t, clock: e.clock, store: other, srv: srv2}

	a, b := e.mailbox(), e.certifiedMailbox() // b renews under a new certificate
	tok := func() string { return e2.pass(b) }
	waitFor := func(what string, ok func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for time.Since(start) < 15*time.Second {
			if ok() {
				return time.Since(start)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: not within 15 s", what)
		return 0
	}
	count := func(s Store) int {
		n, _ := s.Count(ctx, b.Address())
		return n
	}

	// An ack on the other process before it has heard of the message.
	id := idOf(t, send(t, a, b, "acked elsewhere at once"))
	if r := e2.do(http.MethodDelete, "/v1/"+b.Address().String()+"/messages/"+hexID(id), nil, tok()); r.status != http.StatusNoContent {
		t.Fatalf("ack on the other process: %d %s", r.status, r.body)
	}
	took := waitFor("the ack reaching the first process", func() bool { return count(e.store) == 0 })
	t.Logf("an ack on the second process reached the first in %s", took)

	// A long poll on the other process is woken by a send stored on this
	// one, through the feed (PROTOCOL.md §11.11).
	list := "/v1/" + b.Address().String() + "/messages"
	tag := e2.do(http.MethodGet, list, nil, tok()).header.Get("ETag")
	woke := make(chan reply, 1)
	pass := tok()
	go func() { woke <- e2.doWith(http.MethodGet, list+"?wait=60", nil, pass, "If-None-Match", tag) }()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	id = idOf(t, send(t, a, b, "woke a long poll elsewhere"))
	if r := <-woke; r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("the long poll on the other process: %d %s", r.status, r.body)
	}
	t.Logf("a send on the first process woke a long poll on the second in %s", time.Since(start))
	if r := e2.do(http.MethodDelete, list+"/"+hexID(id), nil, tok()); r.status != http.StatusNoContent {
		t.Fatalf("ack on the other process: %d %s", r.status, r.body)
	}
	waitFor("the ack reaching the first process", func() bool { return count(e.store) == 0 })

	// A send reaches the other process's count.
	send(t, a, b, "seen elsewhere")
	took = waitFor("the send reaching the other process", func() bool { return count(other) == 1 })
	t.Logf("a send on the first process reached the second in %s", took)
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tok()); r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("list on the other process: %d %s", r.status, r.body)
	}

	// A new prekey comes under a new certificate: the other process, which
	// took the old pass a moment ago, refuses it from memory once the feed
	// brings the change, and takes the identity's pass, as always.
	old := tok()
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, old); r.status != http.StatusOK {
		t.Fatalf("the pass before the renewal, on the other process: %d %s", r.status, r.body)
	}
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	rec, err := e.store.Mailbox(ctx, b.Address())
	if err != nil {
		t.Fatal(err)
	}
	waitFor("the new certificate reaching the other process", func() bool {
		st, ok := other.Held(b.Address())
		return ok && st.Signer == rec.Signer
	})
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, old); r.code() != protocol.CodeCertificateNotCurrent {
		t.Fatalf("the old pass on the other process: %d %s", r.status, r.body)
	}
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tok()); r.status != http.StatusOK {
		t.Fatalf("the new pass on the other process: %d %s", r.status, r.body)
	}
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e2.passFor(signer(t, b), b.Address(), e2.name())); r.status != http.StatusOK {
		t.Fatalf("the identity's pass on the other process: %d %s", r.status, r.body)
	}
}

// A restart starts with empty memory and is ready at once; each mailbox is read
// on its first use, once, and answered from memory after that.
func TestRestartLoadsLazily(t *testing.T) {
	t.Parallel()
	e, _ := sharedEnv(t)
	ctx := context.Background()
	a, b, c, f := e.mailbox(), e.mailbox(), e.mailbox(), e.mailbox()
	one := send(t, a, b, "one")
	send(t, a, b, "two")
	send(t, a, f, "three")
	if _, err := c.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	renewed, err := e.store.Mailbox(ctx, c.Address())
	if err != nil {
		t.Fatal(err)
	}

	fresh := startPostgres(t, e.clock.Now)
	if !fresh.Ready() || fresh.loads.Load() != 0 {
		t.Fatalf("ready %v after %d loads: want ready with none", fresh.Ready(), fresh.loads.Load())
	}
	// Each of these is its mailbox's first use, then b's second.
	if held, _ := fresh.Holds(ctx, b.Address(), idOf(t, one)); !held {
		t.Fatal("the message held is not in memory")
	}
	if n, _ := fresh.Count(ctx, f.Address()); n != 1 {
		t.Fatalf("count %d", n)
	}
	if n, _ := fresh.Count(ctx, b.Address()); n != 2 {
		t.Fatalf("count %d, want 2", n)
	}
	if n := fresh.loads.Load(); n != 2 {
		t.Fatalf("%d loads for two mailboxes", n)
	}
	// A mailbox memory has not loaded has no standing there; its first use
	// loads it, as its record is now.
	if _, ok := fresh.Held(c.Address()); ok {
		t.Fatal("a mailbox nothing has used is in memory")
	}
	if n, err := fresh.Count(ctx, c.Address()); n != 0 || err != nil {
		t.Fatalf("rekeyed mailbox: %d %v", n, err)
	}
	if st, ok := fresh.Held(c.Address()); !ok || st.State != Active || st.Signer != renewed.Signer {
		t.Fatalf("rekeyed mailbox: %v %v", st, ok)
	}
	var nobody protocol.Address
	if n, err := fresh.Count(ctx, nobody); n != 0 || err != nil {
		t.Fatalf("no mailbox: %d %v", n, err)
	}
	if _, ok := fresh.Held(nobody); ok {
		t.Fatal("no mailbox, and memory holds a standing for it")
	}
}

// A revocation sent again to a process that has not loaded the address
// carries no pass, and loads nothing there (ARCHITECTURE.md § Startup;
// dromas-dev/dromas-server#42).
func TestAResentRevocationLoadsNothingElsewhere(t *testing.T) {
	t.Parallel()
	e, _ := sharedEnv(t)
	a := e.mailbox()
	rec := record(t, a)
	e.want(e.do("PUT", revocationPath(a.Address()), rec, ""), 201, "")

	fresh := startPostgres(t, e.clock.Now)
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: fresh, Limits: relaxed(), Now: e.clock.Now, Ready: fresh.Ready}).Handler()))
	t.Cleanup(srv.Close)
	e2 := &env{t: t, clock: e.clock, store: fresh, srv: srv}
	e2.want(e2.do("PUT", revocationPath(a.Address()), rec, ""), 410, protocol.CodeRevoked)
	if n := fresh.loads.Load(); n != 0 {
		t.Errorf("a revocation sent again loaded %d addresses", n)
	}
	if _, ok := fresh.Held(a.Address()); ok {
		t.Error("a revocation sent again left its address in memory")
	}
}

// Polls read a mailbox once per process, on its first use: every later poll,
// empty or not, is answered from memory, kept current by the feed.
func TestPollsReadOncePerProcess(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	a, b := e.mailbox(), e.mailbox()
	poll := func() reply {
		e.clock.Add(time.Minute) // past the poll limit
		return e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e.pass(b))
	}
	if r := poll(); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	before := s.loads.Load()
	for range 3 {
		if r := poll(); r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":0`) {
			t.Fatalf("%d %s", r.status, r.body)
		}
	}
	send(t, a, b, "counted from memory")
	if r := poll(); !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("after a send: %s", r.body)
	}
	if n := s.loads.Load() - before; n != 0 {
		t.Fatalf("%d loads after the first poll", n)
	}
}

// A throttled store answers 503 with Retry-After, never a wrong answer.
type throttled struct{ Store }

func (throttled) Count(context.Context, protocol.Address) (int, error) {
	return 0, &smithy.GenericAPIError{Code: "SlowDown", Message: "slow down"}
}

func TestThrottleIs503(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.mailbox()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: throttled{e.store}, Limits: relaxed(), Now: e.clock.Now}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e2.pass(b))
	if r.status != http.StatusServiceUnavailable || r.code() != protocol.CodeUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("%d %s, Retry-After %q", r.status, r.body, r.header.Get("Retry-After"))
	}
	if !IsThrottle(&smithy.GenericAPIError{Code: "ThrottlingException"}) || IsThrottle(errors.New("other")) {
		t.Fatal("IsThrottle")
	}
}

// Until the store has loaded its memory, every call is a 503.
func TestNotReadyIs503(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Ready: func() bool { return false }}).Handler()))
	defer srv.Close()
	e := &env{t: t, srv: srv}
	var a protocol.Address
	if r := e.do(http.MethodGet, "/v1/"+a.String()+"/messages", nil, ""); r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("%d %s", r.status, r.body)
	}
}

// An empty poll never leaves the process (ARCHITECTURE.md § Memory): a mailbox
// showing a new pass, one showing a pass the server has taken, a renewed
// one, a pass from before the renewal and a revoked mailbox are all answered
// from memory.
func TestPollStaysInMemory(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	b, c := e.mailbox(), e.certifiedMailbox() // c renews under a new certificate
	cs := &countingStore{s: e.store}
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: cs, Limits: relaxed(), Now: e.clock.Now}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	poll := func(x *client.Mailbox, pass string) reply {
		return e2.do(http.MethodGet, "/v1/"+x.Address().String()+"/messages", nil, pass)
	}

	pass := e2.pass(b)
	for range 3 {
		if r := poll(b, pass); r.status != http.StatusOK {
			t.Fatalf("active mailbox: %d %s", r.status, r.body)
		}
	}
	e.clock.Add(protocol.PassLifetime) // the mailbox signs another
	if r := poll(b, pass); r.code() != protocol.CodePassExpired {
		t.Fatalf("a pass that ran out: %d %s", r.status, r.body)
	}
	if r := poll(b, e2.pass(b)); r.status != http.StatusOK {
		t.Fatalf("the mailbox's next pass: %d %s", r.status, r.body)
	}
	old := e2.pass(c)
	if r := poll(c, old); r.status != http.StatusOK {
		t.Fatalf("before the renewal: %d %s", r.status, r.body)
	}
	if _, err := c.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if r := poll(c, e2.pass(c)); r.status != http.StatusOK {
		t.Fatalf("rekeyed mailbox: %d %s", r.status, r.body)
	}
	if r := poll(c, old); r.code() != protocol.CodeCertificateNotCurrent {
		t.Fatalf("the pass from before the renewal: %d %s", r.status, r.body)
	}
	before := cs.calls.Load()
	rv := record(t, b)
	if err := e.store.Revoke(ctx, b.Address(), &Revocations{Identity: rv.Identity, Address: rv.Revocation}, ExpectAnything); err != nil {
		t.Fatal(err)
	}
	if cs.calls.Load() != before {
		t.Fatal("the test's own calls were counted")
	}
	if r := poll(b, e2.pass(b)); r.code() != protocol.CodeRevoked {
		t.Fatalf("revoked mailbox: %d %s", r.status, r.body)
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("%d storage calls for polls", n)
	}
}

// A header past its expiry is never listed, though the sweep has not
// deleted it yet.
func TestExpiredHeadersAreNotListed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "expires first")
	e.clock.Add(protocol.TTL / 2)
	live := send(t, a, b, "still live")
	e.clock.Add(protocol.TTL / 2)
	r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, e.pass(b))
	var l protocol.MessageList
	_ = json.Unmarshal(r.body, &l)
	if r.status != http.StatusOK || l.Count != 1 || len(l.Messages) != 1 || l.Messages[0].ID != live.ID {
		t.Fatalf("%d %s", r.status, r.body)
	}
	e.clock.Add(protocol.TTL / 2)
	if r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages/"+live.ID, nil, e.pass(b)); r.code() != protocol.CodeNoSuchMessage {
		t.Fatalf("fetch after expiry: %d %s", r.status, r.body)
	}
	if r := e.do(http.MethodDelete, "/v1/"+b.Address().String()+"/messages/"+live.ID, nil, e.pass(b)); r.code() != protocol.CodeNoSuchMessage {
		t.Fatalf("ack after expiry: %d %s", r.status, r.body)
	}
}

// The dedupe spans an unacked message's life, the TTL less the hour
// (protocol.Retention): the same bytes sent again inside it get the receipt
// held. Past it, while the prekey they name lasts, nothing of the message is
// kept, and they are a new message, which any sender's pass can post and its
// reader drops by its hash (PROTOCOL.md §12.3 check 8), and that copy answers
// in its turn. No client of this protocol posts the same bytes twice: a retry
// is sealed afresh (§12.2).
func TestTheDedupeSpansAnUnackedMessagesLife(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	first := send(t, a, b, "once, then again")
	e.setMiddle(nil)
	e.clock.Add(protocol.Retention - time.Second)
	again := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a))
	var r protocol.Receipt
	_ = json.Unmarshal(again.body, &r)
	if again.status != http.StatusOK || r.ReceivedAt != first.ReceivedAt {
		t.Fatalf("inside its life: %d %s", again.status, again.body)
	}
	e.clock.Add(time.Second)
	renewed := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a))
	_ = json.Unmarshal(renewed.body, &r)
	if renewed.status != http.StatusCreated || r.ReceivedAt == first.ReceivedAt {
		t.Fatalf("past its life, inside the prekey's: %d %s", renewed.status, renewed.body)
	}
}

// A mailbox's record and its address's revocations are memory's, each a row
// of its own table, and a row of a table memory holds nothing of changes
// nothing in the feed. A revocation adds to what memory holds; the record's
// removal drops the mailbox, whose next use reads it again.
func TestTheRecordAndTheRevocationsAreMemorys(t *testing.T) {
	t.Parallel()
	s := newMemory(nil, 10, nil, nil) // never started: memory alone
	var a protocol.Address
	a[0] = 7
	if err := s.idx.ensure(context.Background(), a, func() (mailboxRead, error) {
		return mailboxRead{exists: true, st: Standing{State: Active, Rank: 5}, rev: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
	standing := func() (Standing, bool) { return s.idx.standing(a) }
	key := row{"account": "an account", "hash": make([]byte, 32), "uses": int32(1), "expires_at": int64(1)}
	s.applyRow("adopt_keys", key, false)
	if st, _ := standing(); st.State != Active {
		t.Fatalf("another table's row set the standing: %v", st)
	}
	s.applyRow("adopt_keys", key, true)
	if _, ok := standing(); !ok {
		t.Fatal("another table's row's removal dropped the mailbox")
	}
	certs := row{"addr": a[:], "identity": []byte("x"), "revocation": nil,
		"revoked_certs": []byte("x"), "revoked_certs_sig": []byte("x"), "through": numeric(5)}
	s.applyRow("revocations", certs, false)
	if st, _ := standing(); st.State != Active || !st.Listed {
		t.Fatalf("a revocation of the mailbox's certificate: %+v", st)
	}
	certs["through"] = numeric(3) // lower: changes nothing
	s.applyRow("revocations", certs, false)
	if st, _ := standing(); !st.Listed {
		t.Fatal("a lower revocation of certificates took the mailbox's back")
	}
	certs["revocation"] = []byte("x")
	s.applyRow("revocations", certs, false)
	if st, _ := standing(); st.State != Revoked {
		t.Fatalf("a revocation of the address: %+v", st)
	}
	s.applyRow("mailboxes", row{"addr": a[:]}, true)
	if _, ok := standing(); ok {
		t.Fatal("the record's removal left the mailbox in memory")
	}
}

// A mailbox record this build cannot read whole is no record: one whose
// stored identity or ACL does not read. Reading it is an error, so nothing is served or taken for the
// address, and its image on the feed makes memory forget the mailbox wherever
// it holds it, loaded or loading, its record cached, or its address
// remembered missing, rather than keep answering for it as it was
// (dromas-dev/dromas-server#87). Control: an active image keeps it.
func TestARecordThatDoesNotReadIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	it := recordRow(rec)
	if _, err := decodeMailbox(it); err != nil {
		t.Fatalf("an active record: %v", err)
	}
	if s, ok := e.store.(*Memory); ok && onPostgres() {
		// recordRow is the table's row: its columns, and what they read as.
		stored := s.storedRecord(t, a)
		if got, want := slices.Sorted(maps.Keys(it)), slices.Sorted(maps.Keys(stored)); !slices.Equal(got, want) {
			t.Fatalf("control: recordRow has the columns %v; the table %v", got, want)
		}
		from, err := decodeMailbox(stored)
		if err != nil {
			t.Fatal(err)
		}
		if made, _ := decodeMailbox(it); made.Rev != from.Rev || made.Rank != from.Rank || !bytes.Equal(made.Statement, from.Statement) {
			t.Fatal("control: recordRow does not read as the table's row does")
		}
	}
	at := func(rev uint64, set func(row)) row {
		x := recordRow(rec)
		x["rev"] = toInt(rev)
		set(x)
		return x
	}
	broken := at(rec.Rev+1, func(x row) { x["identity"] = []byte("not an identity document") })
	badACL := at(rec.Rev+1, func(x row) { x["acl"] = []byte(`{"allow":"not a list"}`) })
	if _, _, err := decodeStanding(badACL); err != nil {
		t.Fatalf("control: the standing of a record whose ACL does not read: %v", err)
	}
	read := func(rev uint64) func() (mailboxRead, error) {
		return func() (mailboxRead, error) {
			return mailboxRead{exists: true, st: Standing{State: Active, Rank: rec.Rank}, rev: rev}, nil
		}
	}
	for _, im := range []struct {
		name string
		it   row
	}{{"a record whose identity does not read", broken}, {"a record whose ACL does not read", badACL}} {
		if b, err := decodeMailbox(im.it); err == nil {
			t.Fatalf("%s read as a record at rev %d", im.name, b.Rev)
		}
		t.Run(im.name+", loaded and cached", func(t *testing.T) {
			s := newMemory(nil, 10, nil, nil)
			if err := s.idx.ensure(ctx, a, read(rec.Rev)); err != nil {
				t.Fatal(err)
			}
			s.cache.put(rec)
			s.applyRow("mailboxes", im.it, false)
			if st, ok := s.Held(a); ok {
				t.Errorf("the index kept the mailbox as %s", st.State)
			}
			if b, ok := s.Known(a); ok {
				t.Errorf("the record cache kept the mailbox (%v), which Mailbox serves with no read", b != nil)
			}
		})
		t.Run(im.name+", remembered missing", func(t *testing.T) {
			s := newMemory(nil, 10, nil, nil)
			s.cache.missed(a, s.cache.begin(a), s.now())
			if _, ok := s.Known(a); !ok {
				t.Fatal("control: the miss is not remembered")
			}
			s.applyRow("mailboxes", im.it, false)
			if _, ok := s.Known(a); ok {
				t.Error("an image of a record left the address remembered as missing")
			}
		})
		t.Run(im.name+", loading", func(t *testing.T) {
			s := newMemory(nil, 10, nil, nil)
			reading, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				done <- s.idx.ensure(ctx, a, func() (mailboxRead, error) {
					close(reading)
					<-release
					return read(rec.Rev)()
				})
			}()
			<-reading
			s.applyRow("mailboxes", im.it, false)
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if st, ok := s.Held(a); ok {
				t.Errorf("a load in flight when the image came kept the mailbox as %s", st.State)
			}
		})
	}
	t.Run("control: an active image keeps it", func(t *testing.T) {
		s := newMemory(nil, 10, nil, nil)
		if err := s.idx.ensure(ctx, a, read(rec.Rev)); err != nil {
			t.Fatal(err)
		}
		s.cache.put(rec)
		s.applyRow("mailboxes", at(rec.Rev+1, func(row) {}), false)
		if st, ok := s.Held(a); !ok || st.State != Active {
			t.Errorf("an active image: the index holds the mailbox %s, %v", st.State, ok)
		}
		if b, ok := s.Known(a); !ok || b == nil || b.Rev != rec.Rev+1 {
			t.Errorf("an active image: the record cache holds the mailbox %v (%v); want it at rev %d", b != nil, ok, rec.Rev+1)
		}
	})
}

// cannedRecord is a backend whose reads of an address answer the mailboxes
// row the test holds, decoded as a read of the table decodes it, and none of
// its revocations, over the in-memory backend for everything else.
type cannedRecord struct {
	Backend
	mu  sync.Mutex
	rec row
}

// cannedStore is memory over a cannedRecord holding r.
func cannedStore(r row) (*Memory, *cannedRecord) {
	s := NewMemStore(time.Now)
	c := &cannedRecord{Backend: s.backend, rec: r}
	s.backend = c
	return s, c
}

func (c *cannedRecord) set(r row) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rec = r
}

func (c *cannedRecord) ReadAddress(context.Context, protocol.Address) (*Mailbox, *Revocations, error) {
	c.mu.Lock()
	r := c.rec
	c.mu.Unlock()
	if r == nil {
		return nil, nil, nil
	}
	b, err := decodeMailbox(r)
	if err != nil {
		return nil, nil, err
	}
	return b, nil, nil
}

// A process that served a mailbox from its record cache, and then takes the
// feed's image of a record that does not read, does not
// serve it from the cache again: the read of the mailbox after the image reads
// the record, which fails (dromas-dev/dromas-server#87). In process, over a
// canned row.
func TestADeletedImageIsNotServedFromTheCache(t *testing.T) {
	t.Parallel()
	e0 := newEnv(t, relaxed())
	r := e0.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e0.store.Mailbox(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	s, canned := cannedStore(recordRow(rec))
	e := newEnv(t, relaxed(), func(c *Config) { c.Store = s })
	r.e = e
	e.want(e.do("GET", r.path(""), nil, ""), http.StatusOK, "")
	if _, ok := s.Known(a); !ok {
		t.Fatal("control: the read did not fill the record cache")
	}
	broken := recordRow(rec)
	broken["identity"] = []byte("not an identity document")
	broken["rev"] = toInt(rec.Rev + 1)
	canned.set(broken)
	s.applyRow("mailboxes", broken, false)
	got := e.do("GET", r.path(""), nil, "")
	t.Logf("the read of the mailbox after the image: %d %s", got.status, got.code())
	if got.status == http.StatusOK {
		t.Errorf("a mailbox whose record does not read is served from the record cache: %d", got.status)
	}
}

// A mailbox's record is only written over the revision it was read at.
func TestUpdateMailboxIsConditional(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	b := e.mailbox()
	first, _ := e.store.Mailbox(ctx, b.Address())
	second, _ := e.store.Mailbox(ctx, b.Address())
	first.Rank++
	if err := e.store.UpdateMailbox(ctx, first); err != nil {
		t.Fatal(err)
	}
	second.Rank += 2
	if err := e.store.UpdateMailbox(ctx, second); !errors.Is(err, ErrStale) {
		t.Fatalf("an update over a stale read: %v", err)
	}
	if got, _ := e.store.Mailbox(ctx, b.Address()); got.State != Active || got.Rank != first.Rank {
		t.Fatalf("stored %v at certificate serial %d", got.State, got.Rank)
	}
}

func TestMailboxCache(t *testing.T) {
	t.Parallel()
	var a1, a2, a3 protocol.Address
	a1[0], a2[0], a3[0] = 1, 2, 3
	c := newMailboxCache(2)
	c.put(&Mailbox{Addr: a1, Rev: 3})
	c.put(&Mailbox{Addr: a1, Rev: 2})
	if b, _ := c.get(a1); b.Rev != 3 {
		t.Fatalf("rev %d: an older record replaced a newer one", b.Rev)
	}
	c.write(a1, c.image(&Mailbox{Addr: a1, Rev: 3, Rank: 9}))
	if b, _ := c.get(a1); b.Rank == 9 {
		t.Fatal("refreshed at the same rev")
	}
	c.write(a1, c.image(&Mailbox{Addr: a1, Rev: 4}))
	if b, _ := c.get(a1); b.Rev != 4 {
		t.Fatal("not refreshed to a newer rev")
	}
	c.write(a2, c.image(&Mailbox{Addr: a2, Rev: 1}))
	if _, ok := c.get(a2); ok {
		t.Fatal("an image cached a record the cache did not hold")
	}
	c.put(&Mailbox{Addr: a2, Rev: 1})
	c.get(a1)
	c.put(&Mailbox{Addr: a3, Rev: 1}) // evicts a2, the least recently used
	if _, ok := c.get(a2); ok {
		t.Fatal("over its size")
	}
	if _, ok := c.get(a1); !ok {
		t.Fatal("evicted the recently used record")
	}
	c.evict(a1)
	if _, ok := c.get(a1); ok {
		t.Fatal("not evicted")
	}
}

// A mailbox's state answers before its pass is looked at: a call naming no mailbox,
// one the server forgot or a revoked one is told so whatever it carries, and
// only a call on a mailbox in use is asked for that mailbox's pass.
func TestTheMailboxsStateAnswersBeforeItsPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	poll := func(a protocol.Address, pass string) reply {
		return e.do(http.MethodGet, "/v1/"+a.String()+"/messages", nil, pass)
	}
	b, c, d := e.mailbox(), e.mailbox(), e.mailbox()
	if r := poll(b.Address(), "dromas-pass not-a-pass"); r.code() != protocol.CodeUnauthorized {
		t.Fatalf("not a pass: %d %s", r.status, r.body)
	}
	if r := poll(b.Address(), e.pass(c)); r.code() != protocol.CodeUnauthorized {
		t.Fatalf("another mailbox's pass: %d %s", r.status, r.body)
	}
	var nobody protocol.Address
	if r := poll(nobody, e.pass(c)); r.code() != protocol.CodeNoSuchMailbox {
		t.Fatalf("unknown mailbox: %d %s", r.status, r.body)
	}
	pass := e.pass(c)
	if err := e.store.DeleteMailbox(ctx, c.Address()); err != nil { // as the sweep deletes it
		t.Fatal(err)
	}
	for _, p := range []string{"", pass} {
		if r := poll(c.Address(), p); r.code() != protocol.CodeNoSuchMailbox {
			t.Fatalf("a mailbox the server forgot: %d %s", r.status, r.body)
		}
	}
	pass = e.pass(d)
	rv := record(t, d)
	if err := e.store.Revoke(ctx, d.Address(), &Revocations{Identity: rv.Identity, Address: rv.Revocation}, ExpectAnything); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", pass} {
		if r := poll(d.Address(), p); r.code() != protocol.CodeRevoked {
			t.Fatalf("revoked mailbox: %d %s", r.status, r.body)
		}
	}
}
