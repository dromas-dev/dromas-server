package server

// The bound of every call to AWS the store makes, and of each read a send's
// shared call makes apart from its request (dromas-dev/dromas-server#91).
// awsfake_test.go has the fake of AWS.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

// streamOp is the prefix of a DynamoDB Streams operation's name, as the fake
// of AWS sees it.
const streamOp = "DynamoDBStreams_20120810."

// Every call the DynamoDB backend makes to AWS ends at storeTimeout, on a
// context its caller handed it with no deadline and no end, against a
// DynamoDB, its streams and an S3 that never answer: the reads as the
// writes, whoever calls them, and a stream follower's
// (dromas-dev/dromas-server#91). The bound is in one place for each
// client (bound, boundedStreams), not at each call
// (dromas-dev/dromas-client#411 item 4). Where a call comes after
// another, the fake answers the first and holds the one named: a delete of
// a box's mail reaches its delete of the bodies so.
func TestEveryCallToAWSEndsAtItsBound(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	_, _, box := heldRecord(t)
	hang := answer{hang: true}
	now := time.Now().UTC().Truncate(time.Millisecond)
	msg := &Header{ID: [32]byte{7}, From: box.Addr, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	// answered is a 200 whose body is v as JSON (itemJSON writes an item).
	answered := func(v any) answer {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return answer{status: http.StatusOK, body: string(b)}
	}
	// first answers the first call of op with a, and holds every other.
	first := func(op string, a answer) func(string, int, []byte) answer {
		return func(o string, n int, _ []byte) answer {
			if o == op && n == 1 {
				return a
			}
			return hang
		}
	}
	// What a table's stream answers: its description, and one open shard.
	described := answered(map[string]any{"Table": map[string]any{"LatestStreamArn": "fake-stream",
		"StreamSpecification": map[string]any{"StreamEnabled": true, "StreamViewType": "NEW_IMAGE"}}})
	oneShard := answered(map[string]any{"StreamDescription": map[string]any{"Shards": []any{
		map[string]any{"ShardId": "s", "SequenceNumberRange": map[string]any{"StartingSequenceNumber": "0"}}}}})
	s3ok := func(method string, _ int) answer {
		if method == http.MethodDelete {
			return answer{status: http.StatusNoContent}
		}
		return answer{status: http.StatusOK}
	}
	cases := []struct {
		name   string
		dynamo func(string, int, []byte) answer // nil: every call is held
		s3     func(string, int) answer         // nil: every call is held
		call   func(context.Context, *Memory) error
	}{
		{name: "Box", call: func(ctx context.Context, s *Memory) error { _, err := s.Box(ctx, protocol.Address{5}); return err }},
		{name: "a load's read of the record", call: func(ctx context.Context, s *Memory) error { _, err := s.Count(ctx, box.Addr); return err }},
		{name: "a load's read of the live index", dynamo: first("Query", answered(map[string]any{"Items": []any{itemJSON(boxItem(box))}, "Count": 1, "ScannedCount": 1})),
			call: func(ctx context.Context, s *Memory) error { _, err := s.Count(ctx, box.Addr); return err }},
		{name: "Dedupe", call: func(ctx context.Context, s *Memory) error { _, err := s.Dedupe(ctx, box.Addr, msg.ID); return err }},
		{name: "List", call: func(ctx context.Context, s *Memory) error { _, err := s.List(ctx, box.Addr, nil, 10); return err }},
		{name: "Message's read of the item", call: func(ctx context.Context, s *Memory) error {
			_, _, err := s.Message(ctx, box.Addr, msg.ID, 0)
			return err
		}},
		{name: "Message's read of the body", dynamo: first("GetItem", answered(map[string]any{"Item": itemJSON(msgItem(box.Addr, msg))})),
			call: func(ctx context.Context, s *Memory) error {
				_, _, err := s.Message(ctx, box.Addr, msg.ID, 0)
				return err
			}},
		{name: "Message's read of the body's bytes", dynamo: first("GetItem", answered(map[string]any{"Item": itemJSON(msgItem(box.Addr, msg))})),
			s3: func(string, int) answer { return answer{status: http.StatusOK, body: "ab", stall: true} },
			call: func(ctx context.Context, s *Memory) error {
				_, _, err := s.Message(ctx, box.Addr, msg.ID, 0)
				return err
			}},
		{name: "Account", call: func(ctx context.Context, s *Memory) error { _, err := s.Account(ctx, "acct"); return err }},
		{name: "AdoptKey", call: func(ctx context.Context, s *Memory) error {
			_, err := s.AdoptKey(ctx, "acct", [32]byte{1})
			return err
		}},
		{name: "CreateAccount", call: func(ctx context.Context, s *Memory) error { return s.CreateAccount(ctx, &Account{ID: "acct"}) }},
		{name: "PutAdoptKey", call: func(ctx context.Context, s *Memory) error {
			return s.PutAdoptKey(ctx, &AdoptKey{Account: "acct", Hash: [32]byte{1}, Uses: 1, Expires: now.Add(time.Hour)})
		}},
		{name: "CreateBox", call: func(ctx context.Context, s *Memory) error { return s.CreateBox(ctx, cloneBox(box)) }},
		{name: "UpdateBox", call: func(ctx context.Context, s *Memory) error { return s.UpdateBox(ctx, cloneBox(box)) }},
		{name: "DeleteBox", call: func(ctx context.Context, s *Memory) error { return s.DeleteBox(ctx, box.Addr) }},
		{name: "Revoke", call: func(ctx context.Context, s *Memory) error {
			return s.Revoke(ctx, box.Addr, &Revocations{Identity: box.Identity, Address: []byte("r")}, ExpectAnything)
		}},
		{name: "PutMessage's body", call: func(ctx context.Context, s *Memory) error {
			_, err := s.PutMessage(ctx, box.Addr, msg, []byte("abc"))
			return err
		}},
		{name: "PutMessage's item", s3: s3ok, call: func(ctx context.Context, s *Memory) error {
			_, err := s.PutMessage(ctx, box.Addr, msg, []byte("abc"))
			return err
		}},
		{name: "DeleteMessage's body", call: func(ctx context.Context, s *Memory) error { return s.DeleteMessage(ctx, box.Addr, msg.ID) }},
		{name: "DeleteMessage's item", s3: s3ok, call: func(ctx context.Context, s *Memory) error { return s.DeleteMessage(ctx, box.Addr, msg.ID) }},
		{name: "DeleteFrom", call: func(ctx context.Context, s *Memory) error { return s.DeleteMessages(ctx, box.Addr) }},
		{name: "DeleteFrom's delete of the bodies", dynamo: first("Query", answered(map[string]any{"Items": []any{itemJSON(msgItem(box.Addr, msg))}, "Count": 1, "ScannedCount": 1})),
			call: func(ctx context.Context, s *Memory) error { return s.DeleteMessages(ctx, box.Addr) }},
		{name: "Adopt", call: func(ctx context.Context, s *Memory) error {
			return s.Adopt(ctx, cloneBox(box), "acct", [32]byte{1})
		}},
		{name: "Leave", call: func(ctx context.Context, s *Memory) error { return s.Leave(ctx, cloneBox(box)) }},
		{name: "Start's DescribeTable", call: func(ctx context.Context, s *Memory) error { return s.Start(ctx) }},
		{name: "a stream's DescribeStream", dynamo: first("DescribeTable", described),
			call: func(ctx context.Context, s *Memory) error { return s.Start(ctx) }},
		{name: "a stream's GetShardIterator at the start", dynamo: func(op string, n int, b []byte) answer {
			if op == streamOp+"DescribeStream" && n == 1 {
				return oneShard
			}
			return first("DescribeTable", described)(op, n, b)
		}, call: func(ctx context.Context, s *Memory) error { return s.Start(ctx) }},
		{name: "a stream's GetShardIterator in a read", call: func(ctx context.Context, s *Memory) error {
			s.dynamo().boxFeed.arn = "fake-stream"
			return s.dynamo().boxFeed.read(ctx, &shard{id: "s", seq: "1"})
		}},
		{name: "a stream's GetRecords", call: func(ctx context.Context, s *Memory) error {
			s.dynamo().boxFeed.arn = "fake-stream"
			return s.dynamo().boxFeed.read(ctx, &shard{id: "s", iter: aws.String("i")})
		}},
	}
	// Every call at once, each on a fake of its own, then each judged.
	type result struct {
		err  error
		took time.Duration
	}
	ended := make([]chan result, len(cases))
	for i, c := range cases {
		f := newFakeAWS()
		f.dynamo, f.s3 = c.dynamo, c.s3
		if f.dynamo == nil {
			f.dynamo = func(string, int, []byte) answer { return hang }
		}
		if f.s3 == nil {
			f.s3 = func(string, int) answer { return hang }
		}
		s := fakeStore(t, f)
		ended[i] = make(chan result, 1)
		go func() {
			start := time.Now()
			err := c.call(context.WithoutCancel(t.Context()), s)
			ended[i] <- result{err, time.Since(start)}
		}()
	}
	// Each is waited for until storeTimeout and 3 s after they began, and a
	// call that ended by then is judged by its end, however long the calls
	// judged before it waited.
	deadline := time.NewTimer(storeTimeout + 3*time.Second)
	defer deadline.Stop()
	late := false
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r result
			ok := false
			select {
			case r = <-ended[i]:
				ok = true
			default:
				if !late {
					select {
					case r = <-ended[i]:
						ok = true
					case <-deadline.C:
						late = true
					}
				}
			}
			switch {
			case !ok:
				t.Errorf("still waiting after storeTimeout and 3 s: a call to AWS that never answers is not bounded by storeTimeout")
			case !errors.Is(r.err, context.DeadlineExceeded):
				t.Errorf("ended after %v by %v, not by its bound", r.took.Round(100*time.Millisecond), r.err)
			default:
				t.Logf("ended after %v: %v", r.took.Round(100*time.Millisecond), r.err)
			}
		})
	}
}

// hangingDedupe holds the dedupe read of one id until its context ends or
// the test lets it go, as a GetItem on a connection that went silent does
// (an AWS SDK call ends with its context, and by default with nothing else).
// It records the deadline that read was handed, and the one a lookup's read
// of address probe was.
type hangingDedupe struct {
	Store
	id                             [32]byte
	probe                          protocol.Address
	started, let                   chan struct{}
	once                           sync.Once
	reads, ended                   atomic.Int64
	dedupeDeadline, lookupDeadline atomic.Value // time.Duration from the read's start, or -1 for none
}

// deadlineOf is how long ctx has left, or -1 if it has no deadline.
func deadlineOf(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return -1
}

func (s *hangingDedupe) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	if id == s.id {
		s.reads.Add(1)
		s.dedupeDeadline.Store(deadlineOf(ctx))
		s.once.Do(func() { close(s.started) })
		select {
		case <-ctx.Done():
			s.ended.Add(1)
			return nil, ctx.Err()
		case <-s.let:
		}
	}
	return s.Store.Dedupe(ctx, box, id)
}

func (s *hangingDedupe) Known(a protocol.Address) (*Box, bool) {
	if a == s.probe {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s *hangingDedupe) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if a == s.probe {
		s.lookupDeadline.Store(deadlineOf(ctx))
	}
	return s.Store.Box(ctx, a)
}

// postBytes posts ciphertext ct to url, prekey 1 under certificate 1, with pass,
// through c: its status, or 0 when the client gave up.
func postBytes(c *http.Client, url string, ct []byte, pass string) int {
	req, _ := http.NewRequest(http.MethodPost, url+"?"+protocol.SendQuery{PrekeySerial: 1, CertificateSerial: 1}.Encode(), bytes.NewReader(ct))
	req.Header.Set("Content-Type", protocol.CiphertextContentType)
	req.Header.Set("Authorization", pass)
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The posts of the same bytes from one sender share one call (deliver),
// which runs apart from the request that leads it, and each post waits on
// it however its own request ends: its dedupe read ends at its bound, though
// every post that waited on it has gone and a later post joined it
// (dromas-dev/dromas-server#91). The controls: a post of other bytes from
// the same sender is answered at once, and a lookup's shared read (lead) is
// bounded the same way.
func TestAPostsSharedReadEndsAtItsBound(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	h := &hangingDedupe{started: make(chan struct{}), let: make(chan struct{})}
	e := newEnv(t, relaxed(), func(c *Config) { h.Store, c.Store = c.Store, h })
	to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	ct := sealFor(t, to, 1)
	h.id = sha256.Sum256(ct)
	h.probe[0] = 5
	pass := from.pass(1)
	url := e.srv.URL + to.path("/messages")
	impatient := &http.Client{Timeout: 300 * time.Millisecond}
	t.Cleanup(sync.OnceFunc(func() { close(h.let) })) // or the server's Close waits on the handlers for ever

	first := postBytes(impatient, url, ct, pass)
	<-h.started
	second := postBytes(impatient, url, ct, pass)
	time.Sleep(time.Second)
	third := postBytes(impatient, url, ct, pass)
	other := postBytes(http.DefaultClient, url, sealFor(t, to, 1), pass)
	e.do("GET", "/v1/"+h.probe.String(), nil, "")
	dd, _ := h.dedupeDeadline.Load().(time.Duration)
	ld, _ := h.lookupDeadline.Load().(time.Duration)
	t.Logf("first %d, second %d, third %d (0: gave up at 300 ms); other bytes %d; the shared read: %d made, deadline %v; the lookup's read: deadline %v",
		first, second, third, other, h.reads.Load(), dd, ld)
	if ld <= 0 || ld > storeTimeout {
		t.Fatalf("control: the lookup's shared read has deadline %v, want at most %v", ld, storeTimeout)
	}
	if other != http.StatusCreated {
		t.Fatalf("control: a post of other bytes from the same sender: %d", other)
	}
	if dd <= 0 || dd > storeTimeout {
		t.Fatalf("the dedupe read of a call every post of those bytes waits on has deadline %v (-1: none), and has outlived all 3 of their callers; want at most %v", dd, storeTimeout)
	}
	deadline := time.Now().Add(storeTimeout + 2*time.Second)
	for h.ended.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.ended.Load() == 0 {
		t.Errorf("the shared read did not end by its own deadline")
	}
}

// holdDedupe holds the next dedupe read until its context ends or the test
// lets it go, as a GetItem on a connection that went silent does.
type holdDedupe struct {
	Store
	hold    atomic.Bool
	entered chan struct{}
	let     chan struct{}
	ended   atomic.Bool
}

func (s *holdDedupe) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	if s.hold.CompareAndSwap(true, false) {
		close(s.entered)
		select {
		case <-ctx.Done():
			s.ended.Store(true)
			return nil, ctx.Err()
		case <-s.let:
		}
	}
	return s.Store.Dedupe(ctx, box, id)
}

// A sender whose account lifts its cap posts a body past the free cap, and
// its client goes while the send's dedupe read is held: the send holds the
// one large read until that read ends, and gives it back within storeTimeout,
// though a large send meanwhile, from any sender, is refused 503
// (dromas-dev/dromas-server#91).
func TestAHeldReadGivesBackTheLargeRead(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10
	l.BodyTimeout = 300 * time.Millisecond
	h := &holdDedupe{entered: make(chan struct{}), let: make(chan struct{})}
	e := newEnv(t, l, func(c *Config) { h.Store, c.Store = c.Store, h })
	t.Cleanup(sync.OnceFunc(func() { close(h.let) })) // or the server's Close waits on the handler for ever
	_, key := accountEnv(t, e, true, 1)
	lifted, to := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, lifted, key)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	big := func() []byte { // an age file past the free cap
		var b bytes.Buffer
		w, _ := age.Encrypt(&b, id.Recipient())
		_, _ = w.Write(make([]byte, 30000))
		_ = w.Close()
		return b.Bytes()
	}
	send := func(body []byte, wait time.Duration) (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(1, 1, nil).Encode(), bytes.NewReader(body))
		req.Header.Set("Content-Type", protocol.CiphertextContentType)
		req.Header.Set("Authorization", e.pass(lifted))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	h.hold.Store(true)
	_, err1 := send(big(), 300*time.Millisecond)
	<-h.entered
	time.Sleep(time.Second)
	start := time.Now()
	code, err2 := send(big(), 5*time.Second)
	t.Logf("the first large send, its dedupe held: %v; a second after its client went, the large read is held %d; a large send of other bytes: %d %v after %v",
		err1, len(e.server.largeRead), code, err2, time.Since(start).Round(10*time.Millisecond))
	deadline := time.Now().Add(storeTimeout + 2*time.Second)
	for len(e.server.largeRead) != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("after %v: the large read is held %d; the held dedupe read ended: %v", time.Since(start).Round(100*time.Millisecond), len(e.server.largeRead), h.ended.Load())
	if len(e.server.largeRead) != 0 {
		t.Errorf("a send whose client went still holds the one large read after storeTimeout and 2 s: every large send meanwhile is refused 503")
	}
}

// readDeadlines records the deadline handed to each read a send's shared
// call makes of its recipient (deliver): the dedupe, the caps' reads, its
// account, and its record read again after the write.
type readDeadlines struct {
	Store
	to      protocol.Address
	account string
	mu      sync.Mutex
	seen    map[string]time.Duration
}

func (s *readDeadlines) note(read string, ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[read] = deadlineOf(ctx)
}

func (s *readDeadlines) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	if box == s.to {
		s.note("Dedupe", ctx)
	}
	return s.Store.Dedupe(ctx, box, id)
}

func (s *readDeadlines) Count(ctx context.Context, box protocol.Address) (int, error) {
	if box == s.to {
		s.note("Count", ctx)
	}
	return s.Store.Count(ctx, box)
}

func (s *readDeadlines) PairCount(ctx context.Context, box, from protocol.Address) (int, time.Time, error) {
	if box == s.to {
		s.note("PairCount", ctx)
	}
	return s.Store.PairCount(ctx, box, from)
}

func (s *readDeadlines) Account(ctx context.Context, id string) (*Account, error) {
	if id == s.account {
		s.note("Account", ctx)
	}
	return s.Store.Account(ctx, id)
}

func (s *readDeadlines) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if a == s.to {
		s.note("Box", ctx)
	}
	return s.Store.Box(ctx, a)
}

// Each read a send's shared call makes runs apart from the request that
// leads it, and is handed a context bounded by storeTimeout, so the bound
// holds on any store: the dedupe, the pair and box caps' reads, the
// recipient's account and its record read again after the write
// (dromas-dev/dromas-server#91).
func TestEveryReadOfASendsSharedCallIsBounded(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := &readDeadlines{seen: map[string]time.Duration{}}
	e := newEnv(t, relaxed(), func(c *Config) { s.Store, c.Store = c.Store, s })
	to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	acc, key := accountEnv(t, e, false, 1)
	_, hash, _ := parseAdopt(key)
	rec, err := e.store.Box(ctx, to.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Adopt(ctx, rec, acc.ID, hash); err != nil {
		t.Fatal(err)
	}
	s.to, s.account = to.id.Address(), acc.ID
	e.want(e.sendTo(to, 1, 1, from, 1), http.StatusCreated, "")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, read := range []string{"Dedupe", "Count", "PairCount", "Account", "Box"} {
		d, ok := s.seen[read]
		t.Logf("%s: deadline %v (-1: none)", read, d)
		if !ok || d <= 0 || d > storeTimeout {
			t.Errorf("the send's %s read, made apart from its request, is handed deadline %v (made %v); want at most %v", read, d, ok, storeTimeout)
		}
	}
}

// boundedFirstRead is a stream whose first GetRecords records the deadline
// it was handed and fails as a call that reached it does.
type boundedFirstRead struct {
	*fakeStream
	mu       sync.Mutex
	read     bool
	deadline time.Duration
}

func (b *boundedFirstRead) GetRecords(ctx context.Context, in *dynamodbstreams.GetRecordsInput, opts ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error) {
	b.mu.Lock()
	first := !b.read
	if first {
		b.read, b.deadline = true, deadlineOf(ctx)
	}
	b.mu.Unlock()
	if first {
		return nil, context.DeadlineExceeded
	}
	return b.fakeStream.GetRecords(ctx, in, opts...)
}

// A stream follower's read is handed a bound of its own, and one that ends
// there is no lost place: the follower logs it and reads the shard again at
// its next pass, as after any failed read (dromas-dev/dromas-server#91).
func TestAFollowersReadEndedAtItsBoundIsReadAgain(t *testing.T) {
	t.Parallel()
	fs, f, s, box, now := feedFixture(t)
	b := &boundedFirstRead{fakeStream: fs}
	var mu sync.Mutex
	var logged []string
	f.streams, f.interval = b, 10*time.Millisecond
	f.logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	fs.open("a", "")
	if err := f.position(t.Context(), "arn"); err != nil {
		t.Fatal(err)
	}
	fs.write("a", msgEvent(stypes.OperationTypeInsert, box, 1, now))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var lost atomic.Value
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.run(ctx, func(err error) { lost.Store(err) })
	}()
	for until := time.Now().Add(2 * time.Second); s.countOf(box) == 0 && time.Now().Before(until); {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	b.mu.Lock()
	d := b.deadline
	b.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("the first read's deadline %v (-1: none); logged %q; the record applied %v; lost %v", d, logged, s.countOf(box) == 1, lost.Load())
	if d <= 0 || d > storeTimeout {
		t.Errorf("the follower's read is handed deadline %v; want at most %v", d, storeTimeout)
	}
	if lost.Load() != nil || s.countOf(box) != 1 || len(logged) == 0 {
		t.Errorf("after a read that ended at its bound the follower lost its place %v, applied the record %v, logged %d lines; want it read again", lost.Load(), s.countOf(box) == 1, len(logged))
	}
}
