package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The suite runs against the in-memory store, or, with
// DROMAS_TEST_MESSAGES_TABLE set, against DynamoDB + S3 Express: every test,
// plus the ones here that need AWS, on the tables and the bucket that
// variable and the three of awsTestNames name, each of which must then be
// set. Name tables and a directory bucket kept for tests, never the ones a
// running server uses.

var awsTestNames = []string{"DROMAS_TEST_MAILBOXES_TABLE", "DROMAS_TEST_MESSAGES_TABLE", "DROMAS_TEST_ACCOUNTS_TABLE", "DROMAS_TEST_BUCKET"}

func onAWS() bool { return os.Getenv("DROMAS_TEST_MESSAGES_TABLE") != "" }

func newTestStore(t *testing.T, now func() time.Time) (Store, func() bool) {
	t.Helper()
	if !onAWS() {
		return NewMemStore(now), nil
	}
	s := startDynamo(t, now)
	return s, s.Ready
}

func startDynamo(t *testing.T, now func() time.Time) *Memory {
	t.Helper()
	for _, name := range awsTestNames {
		if os.Getenv(name) == "" {
			t.Fatalf("DROMAS_TEST_MESSAGES_TABLE is set, and %s is not: the tests on AWS need all four of %s", name, strings.Join(awsTestNames, ", "))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewDynamoStore(DynamoConfig{
		AWS:            cfg,
		MailboxesTable: os.Getenv("DROMAS_TEST_MAILBOXES_TABLE"),
		MessagesTable:  os.Getenv("DROMAS_TEST_MESSAGES_TABLE"),
		AccountsTable:  os.Getenv("DROMAS_TEST_ACCOUNTS_TABLE"),
		Bucket:         os.Getenv("DROMAS_TEST_BUCKET"),
		Now:            now,
		MailboxCache:   100,
		StreamInterval: 200 * time.Millisecond,
		// The tests read back what they wrote within milliseconds.
		ConsistentReads: true,
		Fatal:           func(err error) { t.Errorf("stream: %v", err) },
	})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// dynamoEnv is an env on DynamoDB + S3 Express; the test is skipped without.
func dynamoEnv(t *testing.T) (*env, *Memory) {
	t.Helper()
	if !onAWS() {
		t.Skip("needs the AWS tables: DROMAS_TEST_MESSAGES_TABLE and the three beside it (awsTestNames)")
	}
	e := newEnv(t, relaxed())
	return e, e.store.(*Memory)
}

// failOnce makes the DynamoDB backend fail once between the two steps of a
// write, as a crash there would.
func failOnce(s *Memory, point string) {
	var mu sync.Mutex
	done := false
	s.dynamo().crash = func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		if p == point && !done {
			done = true
			return errors.New("injected: a crash " + p)
		}
		return nil
	}
}

func idOf(t *testing.T, r *protocol.Receipt) [32]byte {
	t.Helper()
	var id [32]byte
	copy(id[:], mustHex(t, r.ID))
	return id
}

// lists holds the mailboxes table's index of each account's mailboxes to whether it
// lists mailbox a under account: the index is read eventually consistent, as
// every global secondary index is, so it is asked for up to ten seconds.
func (s *Memory) lists(t *testing.T, account string, a protocol.Address, want bool) {
	t.Helper()
	for range 100 {
		out, err := s.dynamo().db.Query(context.Background(), &dynamodb.QueryInput{
			TableName:                 &s.dynamo().mailboxes,
			IndexName:                 aws.String(accountIndex),
			KeyConditionExpression:    aws.String("#c = :c AND #a = :a"),
			ExpressionAttributeNames:  map[string]string{"#c": "account", "#a": "addr"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":c": bin([]byte(account)), ":a": bin(a[:])},
		})
		if err != nil {
			t.Fatal(err)
		}
		if (len(out.Items) > 0) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("after ten seconds the account index does not list %s under %q: want %v", a, account, want)
}

// stored reads a message's item from the table as it is, or nil.
func (s *Memory) stored(t *testing.T, mailbox protocol.Address, id [32]byte) item {
	t.Helper()
	out, err := s.dynamo().db.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: &s.dynamo().msgs, Key: msgKey(mailbox, id), ConsistentRead: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item
}

func (s *Memory) bodyExists(t *testing.T, mailbox protocol.Address, id [32]byte) bool {
	t.Helper()
	_, err := s.dynamo().s3.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &s.dynamo().bucket, Key: aws.String(bodyKey(mailbox, id))})
	if err != nil && !isNoSuchKey(err) {
		t.Fatal(err)
	}
	return err == nil
}

// listed reports whether the table lists the message: its item is in the
// live index.
func (s *Memory) listed(t *testing.T, mailbox protocol.Address, id [32]byte) bool {
	t.Helper()
	_, ok := s.stored(t, mailbox, id)["live"]
	return ok
}

// Each crash point between the writes, then the retry.

func TestCrashAfterTheBody(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
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

// An ack deletes the message's item and its body, and nothing of it is
// kept (PROTOCOL.md §13): the same bytes posted after it are a new message,
// stored and listed again, which the reader skips, and acks (§11.10 step
// 6, §12.3 check 8). No item names a sender or holds a signature.
func TestTheSameBytesAfterAnAckAreANewMessage(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, a, b, "once")
	e.setMiddle(nil)
	id := sha256.Sum256(sent.ciphertext)
	for k := range s.stored(t, b.Address(), id) {
		if k == "from" || k == "sig" {
			t.Fatalf("a message's item holds %q", k)
		}
	}
	receive(t, b)
	if it := s.stored(t, b.Address(), id); it != nil {
		t.Fatalf("the ack left the item: %v", it)
	}
	if s.bodyExists(t, b.Address(), id) {
		t.Fatal("the ack left the body")
	}
	if err := s.DeleteMessage(ctx, b.Address(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second ack: %v", err)
	}
	if r := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a)); r.status != http.StatusCreated {
		t.Fatalf("the same bytes after the ack: %d %s; want 201", r.status, r.body)
	}
	// In the table, too: memory's tomb for the ack would hide a message the
	// post listed again, until the stream brought it.
	if !s.listed(t, b.Address(), id) || !s.bodyExists(t, b.Address(), id) {
		t.Fatal("the same bytes after the ack are not listed, or have no body")
	}
	if n, _ := s.Count(ctx, b.Address()); n != 1 {
		t.Fatalf("memory counts %d; want the one posted again", n)
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatalf("the same bytes after the ack were delivered again: %d", len(res.Delivered))
	}
	if s.listed(t, b.Address(), id) {
		t.Fatal("the reader left the same bytes listed")
	}
}

func TestCrashBetweenAnAcksDeletes(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	send(t, a, b, "acked halfway")
	failOnce(s, "ack: after the body")
	res, err := b.Receive(ctx)
	if err == nil || res == nil || len(res.Delivered) != 1 {
		t.Fatalf("first drain: %v", err)
	}
	if n, _ := s.Count(ctx, b.Address()); n != 1 {
		t.Fatal("the message left the list with the body")
	}
	// The client acks again on its next drain, and it leaves the list.
	res = receive(t, b)
	if len(res.Delivered) != 0 || len(res.Duplicates) != 0 || len(res.Refused) != 0 {
		t.Fatalf("second drain: %+v", res)
	}
	if n, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("not acked on the second drain")
	}
}

func TestHeaderWithoutBodyIsGone(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "its body expires early"))
	if _, _, err := s.Message(ctx, b.Address(), id, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.dynamo().deleteBody(ctx, b.Address(), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch: %v, want gone", err)
	}
	if s.listed(t, b.Address(), id) {
		t.Fatal("the bodiless message is still listed")
	}
	if n, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("still counted")
	}
}

// An acked message is never served, even if its body comes back, as an
// orphan the lifecycle rule reaps does: the ack deleted its item.
func TestAckedMessageWithABodyAgainIsGone(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	a, b := e.mailbox(), e.mailbox()
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "acked, then its body rewritten"))
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	if _, err := s.dynamo().s3.PutObject(ctx, &s3.PutObjectInput{Bucket: &s.dynamo().bucket, Key: aws.String(bodyKey(b.Address(), id)), Body: strings.NewReader("ciphertext")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch of an acked message: %v", err)
	}
}

// Two processes on one pair of tables: what one writes reaches the other
// through the streams, and an id the other has not heard of yet is read by
// its key.
func TestTwoProcesses(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	ctx := context.Background()
	other := startDynamo(t, e.clock.Now)
	srv2 := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	t.Cleanup(srv2.Close)
	e2 := &env{t: t, clock: e.clock, store: other, srv: srv2}

	a, b := e.mailbox(), e.mailbox()
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

	// A list held on the other process is woken by a send stored on this
	// one, through the stream (PROTOCOL.md §11.11).
	list := "/v1/" + b.Address().String() + "/messages"
	tag := e2.do(http.MethodGet, list, nil, tok()).header.Get("ETag")
	woke := make(chan reply, 1)
	pass := tok()
	go func() { woke <- e2.doWith(http.MethodGet, list+"?wait=60", nil, pass, "If-None-Match", tag) }()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	id = idOf(t, send(t, a, b, "woke a list held elsewhere"))
	if r := <-woke; r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("the list held on the other process: %d %s", r.status, r.body)
	}
	t.Logf("a send on the first process woke a list held on the second in %s", time.Since(start))
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
	// took the old pass a moment ago, refuses it from memory once the stream
	// brings the change.
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
}

// A restart starts with empty memory and is ready at once; each mailbox is read
// on its first use, once, and answered from memory after that.
func TestRestartLoadsLazily(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
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

	fresh := startDynamo(t, e.clock.Now)
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
	e, _ := dynamoEnv(t)
	a := e.mailbox()
	rec := record(t, a)
	e.want(e.do("PUT", revocationPath(a.Address()), rec, ""), 201, "")

	fresh := startDynamo(t, e.clock.Now)
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
// empty or not, is answered from memory, kept current by the stream.
func TestPollsReadOncePerProcess(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
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
	return 0, &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "slow down"}
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
func (c *countingStore) NextExpiry(a protocol.Address) time.Time    { return c.s.NextExpiry(a) }

func (c *countingStore) Known(a protocol.Address) (*Mailbox, bool) { return c.s.Known(a) }

func (c *countingStore) Begin(a protocol.Address) uint64 { return c.s.Begin(a) }

func (c *countingStore) Reread(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	c.count()
	return c.s.Reread(ctx, a)
}

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

// An empty poll never leaves the process (ARCHITECTURE.md § Memory): a mailbox
// showing a new pass, one showing a pass the server has taken, a renewed
// one, a pass from before the renewal and a revoked mailbox are all answered
// from memory.
func TestPollStaysInMemory(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	b, c := e.mailbox(), e.workingMailbox() // c renews under a new certificate
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

// A header past its expiry is never listed, though the TTL has not deleted
// it yet.
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

// A mailbox's record (sk 0x00) and its address's revocations (sk 0x01) are
// memory's, and nothing else under the address is: another item, whatever it
// holds, changes nothing on the stream. A revocation adds to what memory
// holds; the record's removal drops the mailbox, whose next use reads it again.
func TestTheRecordAndTheRevocationsAreMemorys(t *testing.T) {
	t.Parallel()
	s := NewDynamoStore(DynamoConfig{MailboxCache: 10})
	var a protocol.Address
	a[0] = 7
	if err := s.idx.ensure(context.Background(), a, func() (mailboxRead, error) {
		return mailboxRead{exists: true, st: Standing{State: Active, Rank: 5}, rev: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
	b := func(v []byte) stypes.AttributeValue { return &stypes.AttributeValueMemberB{Value: v} }
	keys := func(sk []byte) map[string]stypes.AttributeValue {
		return map[string]stypes.AttributeValue{"addr": b(a[:]), "sk": b(sk)}
	}
	other := keys([]byte("a-later-item"))
	img := map[string]stypes.AttributeValue{
		"addr": other["addr"], "sk": other["sk"], "state": &stypes.AttributeValueMemberS{Value: string(Active)},
		"identity": b([]byte("x")), "revocation": b([]byte("x")), "rev": &stypes.AttributeValueMemberN{Value: "9"},
	}
	record := func(op stypes.OperationType, k, img map[string]stypes.AttributeValue) stypes.Record {
		return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: k, NewImage: img}}
	}
	standing := func() (Standing, bool) { return s.idx.standing(a) }
	s.applyMailboxRecord(record(stypes.OperationTypeInsert, other, img))
	if st, _ := standing(); st.State != Active {
		t.Fatalf("another item set the standing: %v", st)
	}
	s.applyMailboxRecord(record(stypes.OperationTypeRemove, other, nil))
	if _, ok := standing(); !ok {
		t.Fatal("another item's removal dropped the mailbox")
	}
	revs := keys([]byte{skRevocations})
	certs := map[string]stypes.AttributeValue{"addr": revs["addr"], "sk": revs["sk"], "identity": b([]byte("x")),
		"revoked_certs": b([]byte("x")), "revoked_certs_sig": b([]byte("x")), "through": &stypes.AttributeValueMemberN{Value: "5"}}
	s.applyMailboxRecord(record(stypes.OperationTypeInsert, revs, certs))
	if st, _ := standing(); st.State != Active || !st.Listed {
		t.Fatalf("a revocation of the mailbox's certificate: %+v", st)
	}
	certs["through"] = &stypes.AttributeValueMemberN{Value: "3"} // lower: changes nothing
	s.applyMailboxRecord(record(stypes.OperationTypeModify, revs, certs))
	if st, _ := standing(); !st.Listed {
		t.Fatal("a lower revocation of certificates took the mailbox's back")
	}
	certs["revocation"] = b([]byte("x"))
	s.applyMailboxRecord(record(stypes.OperationTypeModify, revs, certs))
	if st, _ := standing(); st.State != Revoked {
		t.Fatalf("a revocation of the address: %+v", st)
	}
	s.applyMailboxRecord(record(stypes.OperationTypeRemove, keys([]byte{skMailbox}), nil))
	if _, ok := standing(); ok {
		t.Fatal("the record's removal left the mailbox in memory")
	}
}

// A mailbox record this build cannot read whole is no record: one in a state it
// never writes, "deleted" among them (dromas-dev/dromas-client#312), or an active one whose stored ACL does
// not read. Reading it is an error, so nothing is served or taken for the
// address, and its image on the stream makes memory forget the mailbox wherever
// it holds it, loaded or loading, its record cached, or its address
// remembered missing, rather than keep answering for it as it was
// (dromas-dev/dromas-server#87). Control: an active image keeps it.
func TestARecordInAStateNotWrittenIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	it := item(mailboxItem(rec))
	if _, err := decodeMailbox(it); err != nil {
		t.Fatalf("an active record: %v", err)
	}
	at := func(rev uint64, set func(item)) item {
		x := item(mailboxItem(rec))
		x["rev"] = num(rev)
		set(x)
		return x
	}
	deleted := at(rec.Rev+1, func(x item) { x["state"] = str("deleted") })
	badACL := at(rec.Rev+1, func(x item) { x["acl"] = bin([]byte(`{"allow":"not a list"}`)) })
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
		it   item
	}{{"a record in the state \"deleted\"", deleted}, {"an active record whose ACL does not read", badACL}} {
		if b, err := decodeMailbox(im.it); err == nil {
			t.Fatalf("%s read as %s", im.name, b.State)
		}
		t.Run(im.name+", loaded and cached", func(t *testing.T) {
			s := NewDynamoStore(DynamoConfig{MailboxCache: 10})
			if err := s.idx.ensure(ctx, a, read(rec.Rev)); err != nil {
				t.Fatal(err)
			}
			s.cache.put(rec)
			s.applyMailboxImage(im.it)
			if st, ok := s.Held(a); ok {
				t.Errorf("the index kept the mailbox as %s", st.State)
			}
			if b, ok := s.Known(a); ok {
				t.Errorf("the record cache kept the mailbox (%v), which Mailbox serves with no read", b != nil)
			}
		})
		t.Run(im.name+", remembered missing", func(t *testing.T) {
			s := NewDynamoStore(DynamoConfig{MailboxCache: 10})
			s.cache.missed(a, s.cache.begin(a), s.now())
			if _, ok := s.Known(a); !ok {
				t.Fatal("control: the miss is not remembered")
			}
			s.applyMailboxImage(im.it)
			if _, ok := s.Known(a); ok {
				t.Error("an image of a record left the address remembered as missing")
			}
		})
		t.Run(im.name+", loading", func(t *testing.T) {
			s := NewDynamoStore(DynamoConfig{MailboxCache: 10})
			reading, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				done <- s.idx.ensure(ctx, a, func() (mailboxRead, error) {
					close(reading)
					<-release
					return read(rec.Rev)()
				})
			}()
			<-reading
			s.applyMailboxImage(im.it)
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
		s := NewDynamoStore(DynamoConfig{MailboxCache: 10})
		if err := s.idx.ensure(ctx, a, read(rec.Rev)); err != nil {
			t.Fatal(err)
		}
		s.cache.put(rec)
		s.applyMailboxImage(at(rec.Rev+1, func(item) {}))
		if st, ok := s.Held(a); !ok || st.State != Active {
			t.Errorf("an active image: the index holds the mailbox %s, %v", st.State, ok)
		}
		if b, ok := s.Known(a); !ok || b == nil || b.Rev != rec.Rev+1 {
			t.Errorf("an active image: the record cache holds the mailbox %v (%v); want it at rev %d", b != nil, ok, rec.Rev+1)
		}
	})
}

// A process that served a mailbox from its record cache, and then takes the
// stream's image of the record in a state this build never writes, does not
// serve it from the cache again: the read of the mailbox after the image reads
// the record, which fails (dromas-dev/dromas-server#87). In process
// over canned tables.
func TestADeletedImageIsNotServedFromTheCache(t *testing.T) {
	t.Parallel()
	e0 := newEnv(t, relaxed())
	r := e0.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e0.store.Mailbox(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	tables := &cannedTables{address: []map[string]types.AttributeValue{mailboxItem(rec)}}
	s := tables.store()
	e := newEnv(t, relaxed(), func(c *Config) { c.Store = s })
	r.e = e
	e.want(e.do("GET", r.path(""), nil, ""), http.StatusOK, "")
	if _, ok := s.Known(a); !ok {
		t.Fatal("control: the read did not fill the record cache")
	}
	deleted := item(mailboxItem(rec))
	deleted["state"] = str("deleted")
	deleted["rev"] = num(rec.Rev + 1)
	tables.set(deleted)
	s.applyMailboxImage(deleted)
	got := e.do("GET", r.path(""), nil, "")
	t.Logf("the read of the mailbox after the image: %d %s", got.status, got.code())
	if got.status == http.StatusOK {
		t.Errorf("a mailbox whose record is in a state this build never writes is served from the record cache: %d", got.status)
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
	if err := e.store.DeleteMailbox(ctx, c.Address()); err != nil { // as the TTL deletes it
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

// On DynamoDB the answer to a message write carries its mailbox's item
// collection's size, which the metric observes: the messages table has its
// LSI, so the metric is not blind, and a new mailbox's estimate tops out at 1 GB.
func TestDynamoObservesTheItemCollection(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	m := NewMetrics(prometheus.NewRegistry())
	s.dynamo().metrics = m
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "sized")
	if err := testutil.CollectAndCompare(m.collections, strings.NewReader(collectionsWant(1)), "dromas_server_item_collection_estimate_bytes"); err != nil {
		t.Error(err)
	}
}
