package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

// fakeStream is a DynamoDB stream whose shards a test opens, writes and
// closes, to check what live AWS cannot be made to do on demand: a shard
// ending and its child taking over, and iterators that expire.
type fakeStream struct {
	mu      sync.Mutex
	shards  []*fakeShard
	seq     int
	expire  map[string]bool // shard ids whose next GetRecords finds the iterator expired
	trimmed bool
	denied  bool // every GetRecords is refused, as AWS refuses a role without the grant
}

type fakeShard struct {
	id, parent string
	closed     bool
	records    []stypes.Record
}

func (f *fakeStream) shard(id string) *fakeShard {
	for _, s := range f.shards {
		if s.id == id {
			return s
		}
	}
	return nil
}

func (f *fakeStream) open(id, parent string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shards = append(f.shards, &fakeShard{id: id, parent: parent})
}

func (f *fakeStream) close(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shard(id).closed = true
}

func (f *fakeStream) write(id string, r stypes.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	r.Dynamodb.SequenceNumber = aws.String(fmt.Sprintf("%021d", f.seq))
	s := f.shard(id)
	s.records = append(s.records, r)
}

func (f *fakeStream) DescribeStream(_ context.Context, _ *dynamodbstreams.DescribeStreamInput, _ ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []stypes.Shard
	for _, s := range f.shards {
		sh := stypes.Shard{ShardId: aws.String(s.id), SequenceNumberRange: &stypes.SequenceNumberRange{StartingSequenceNumber: aws.String("0")}}
		if s.parent != "" {
			sh.ParentShardId = aws.String(s.parent)
		}
		if s.closed {
			sh.SequenceNumberRange.EndingSequenceNumber = aws.String("9")
		}
		out = append(out, sh)
	}
	return &dynamodbstreams.DescribeStreamOutput{StreamDescription: &stypes.StreamDescription{Shards: out}}, nil
}

// An iterator is "<shard>:<position>".
func (f *fakeStream) GetShardIterator(_ context.Context, in *dynamodbstreams.GetShardIteratorInput, _ ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetShardIteratorOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.shard(*in.ShardId)
	pos := 0
	switch in.ShardIteratorType {
	case stypes.ShardIteratorTypeLatest:
		pos = len(s.records)
	case stypes.ShardIteratorTypeAfterSequenceNumber:
		pos = slices.IndexFunc(s.records, func(r stypes.Record) bool { return *r.Dynamodb.SequenceNumber == *in.SequenceNumber }) + 1
	}
	return &dynamodbstreams.GetShardIteratorOutput{ShardIterator: aws.String(fmt.Sprintf("%s:%d", s.id, pos))}, nil
}

func (f *fakeStream) GetRecords(_ context.Context, in *dynamodbstreams.GetRecordsInput, _ ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, p, _ := strings.Cut(*in.ShardIterator, ":")
	if f.trimmed {
		return nil, &stypes.TrimmedDataAccessException{}
	}
	if f.denied {
		return nil, errors.New("AccessDeniedException: not authorized to perform dynamodb:GetRecords")
	}
	if f.expire[id] {
		delete(f.expire, id)
		return nil, &stypes.ExpiredIteratorException{}
	}
	pos, _ := strconv.Atoi(p)
	s := f.shard(id)
	recs := s.records[pos:]
	out := &dynamodbstreams.GetRecordsOutput{Records: recs}
	if !s.closed {
		out.NextShardIterator = aws.String(fmt.Sprintf("%s:%d", id, len(s.records)))
	}
	return out, nil
}

// msgEvent is a message item's stream record: an insert lists the message;
// an ack deletes the item, a removal whose record carries its keys alone.
func msgEvent(op stypes.OperationType, mailbox protocol.Address, id byte, recvMs uint64) stypes.Record {
	var mid [32]byte
	mid[0] = id
	b := func(v []byte) stypes.AttributeValue { return &stypes.AttributeValueMemberB{Value: v} }
	n := func(v uint64) stypes.AttributeValue {
		return &stypes.AttributeValueMemberN{Value: strconv.FormatUint(v, 10)}
	}
	img := map[string]stypes.AttributeValue{
		"box": b(mailbox[:]), "id": b(mid[:]), "size": n(1), "received_at": n(recvMs), "live": b(liveKey(recvMs, mid)),
	}
	keys := map[string]stypes.AttributeValue{"box": img["box"], "id": img["id"]}
	if op == stypes.OperationTypeRemove {
		img = nil
	}
	return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: keys, NewImage: img}}
}

func feedFixture(t *testing.T) (*fakeStream, *feed, *Memory, protocol.Address, uint64) {
	t.Helper()
	now := time.Now()
	s := &Memory{idx: newIndex(), cache: newMailboxCache(0), now: func() time.Time { return now }}
	fs := &fakeStream{expire: map[string]bool{}}
	f := &feed{streams: fs, interval: time.Hour, apply: s.applyMsgRecord, logf: func(string, ...any) {}, shards: map[string]*shard{}}
	var mailbox protocol.Address
	mailbox[0] = 1
	// The mailbox is in memory: a change to one that is not is dropped.
	if err := s.idx.ensure(context.Background(), mailbox, func() (mailboxRead, error) { return mailboxRead{exists: true}, nil }); err != nil {
		t.Fatal(err)
	}
	return fs, f, s, mailbox, ms(now)
}

func (s *Memory) countOf(mailbox protocol.Address) int {
	n, _ := s.Count(context.Background(), mailbox)
	return n
}

// A follower whose reads fail, refused as AWS refuses a role without the
// grant, is not current once unsyncedAfter has passed since it last read its
// stream to the end, so the process answers 503 (dynamoBackend.Ready); a
// pass that reads to the end makes it current again.
func TestAFollowerWhoseReadsFailIsNotCurrent(t *testing.T) {
	t.Parallel()
	fs, f, _, _, _ := feedFixture(t)
	now := time.Now()
	f.clock = func() time.Time { return now }
	fs.open("s1", "")
	ctx := context.Background()
	if err := f.position(ctx, "arn"); err != nil {
		t.Fatal(err)
	}
	if !f.current(now) {
		t.Fatal("a follower just positioned is not current")
	}
	deny := func(d bool) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.denied = d
	}
	deny(true)
	for range 3 {
		now = now.Add(f.unsyncedAfter() / 2)
		if err := f.once(ctx); err == nil {
			t.Fatal("a pass whose reads are refused passed")
		}
	}
	if f.current(now) {
		t.Errorf("a follower whose reads are refused is current %s after it was positioned", 3*f.unsyncedAfter()/2)
	}
	deny(false)
	if err := f.once(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.current(now) || f.current(now.Add(f.unsyncedAfter()+time.Second)) {
		t.Error("a pass that reads to the end does not make the follower current from then")
	}
}

func TestFeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	insert, ack := stypes.OperationTypeInsert, stypes.OperationTypeRemove

	t.Run("closed shards are skipped and open ones start at LATEST", func(t *testing.T) {
		fs, f, s, mailbox, now := feedFixture(t)
		fs.open("a", "")
		fs.write("a", msgEvent(insert, mailbox, 1, now)) // before startup: the load's job
		fs.close("a")
		fs.open("b", "a")
		fs.write("b", msgEvent(insert, mailbox, 2, now)) // also before startup
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		fs.write("b", msgEvent(insert, mailbox, 3, now))
		if err := f.pass(ctx); err != nil {
			t.Fatal(err)
		}
		if n := s.countOf(mailbox); n != 1 {
			t.Fatalf("count %d: want only the change made after startup", n)
		}
	})

	t.Run("a parent is read before its child", func(t *testing.T) {
		fs, f, s, mailbox, now := feedFixture(t)
		fs.open("p", "")
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		// The message arrives in the parent; the shard ends; its ack lands
		// in the child, whose id sorts first.
		fs.write("p", msgEvent(insert, mailbox, 1, now))
		fs.close("p")
		fs.open("0child", "p")
		fs.write("0child", msgEvent(ack, mailbox, 1, now))
		f.listed = time.Time{} // list now
		for range 3 {
			if err := f.pass(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if n := s.countOf(mailbox); n != 0 {
			t.Fatal("the child's ack was applied before the parent's insert")
		}
	})

	t.Run("a child found when its parent ends", func(t *testing.T) {
		fs, f, s, mailbox, now := feedFixture(t)
		fs.open("p", "")
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		fs.close("p")
		fs.open("c", "p")
		fs.write("c", msgEvent(insert, mailbox, 1, now))
		for range 2 {
			if err := f.pass(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if n := s.countOf(mailbox); n != 1 {
			t.Fatal("the child shard was not followed")
		}
	})

	t.Run("an expired iterator resumes after the last record", func(t *testing.T) {
		fs, f, s, mailbox, now := feedFixture(t)
		fs.open("a", "")
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		fs.write("a", msgEvent(insert, mailbox, 1, now))
		if err := f.pass(ctx); err != nil {
			t.Fatal(err)
		}
		fs.expire["a"] = true
		fs.write("a", msgEvent(insert, mailbox, 2, now))
		for range 2 {
			if err := f.pass(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if n := s.countOf(mailbox); n != 2 {
			t.Fatalf("count %d after an expired iterator", n)
		}
	})

	t.Run("an expired iterator with nothing read is lost", func(t *testing.T) {
		fs, f, _, _, _ := feedFixture(t)
		fs.open("a", "")
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		fs.expire["a"] = true
		_ = f.pass(ctx)
		var l *errLost
		if err := f.pass(ctx); !errors.As(err, &l) {
			t.Fatalf("%v: want lost", err)
		}
	})

	t.Run("trimmed data is lost", func(t *testing.T) {
		fs, f, _, _, _ := feedFixture(t)
		fs.open("a", "")
		if err := f.position(ctx, "arn"); err != nil {
			t.Fatal(err)
		}
		fs.trimmed = true
		var l *errLost
		if err := f.pass(ctx); !errors.As(err, &l) {
			t.Fatalf("%v: want lost", err)
		}
	})
}

// The accounts stream refreshes a cached account to a newer rev and evicts
// a deleted one; an account's other items, and accounts not cached, are not
// memory's.
func TestAccountRecords(t *testing.T) {
	t.Parallel()
	s := &Memory{accCache: newAccountCache(10)}
	b := func(v []byte) stypes.AttributeValue { return &stypes.AttributeValueMemberB{Value: v} }
	rec := func(op stypes.OperationType, id string, sk []byte, rev uint64, unmetered bool) stypes.Record {
		keys := map[string]stypes.AttributeValue{"account": b([]byte(id)), "sk": b(sk)}
		img := map[string]stypes.AttributeValue{"account": keys["account"], "sk": keys["sk"],
			"rev": &stypes.AttributeValueMemberN{Value: strconv.FormatUint(rev, 10)}, "unmetered": &stypes.AttributeValueMemberBOOL{Value: unmetered}}
		return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: keys, NewImage: img}}
	}
	modify, remove := stypes.OperationTypeModify, stypes.OperationTypeRemove
	other := append([]byte{skAdoptKey}, make([]byte, 32)...) // an adopt key's item
	s.accCache.put(&Account{ID: "acme", Rev: 1})
	s.applyAccountRecord(rec(modify, "acme", other, 5, true))
	s.applyAccountRecord(rec(modify, "other", []byte{skAccount}, 2, true))
	if a, _ := s.accCache.get("acme"); a.Unmetered || a.Rev != 1 {
		t.Fatalf("another item changed the account: %+v", a)
	}
	if _, ok := s.accCache.get("other"); ok {
		t.Fatal("an account not cached was cached")
	}
	s.applyAccountRecord(rec(modify, "acme", []byte{skAccount}, 2, true))
	if a, _ := s.accCache.get("acme"); !a.Unmetered || a.Rev != 2 {
		t.Fatalf("not refreshed: %+v", a)
	}
	s.applyAccountRecord(rec(remove, "acme", other, 0, false))
	if _, ok := s.accCache.get("acme"); !ok {
		t.Fatal("a removed adopt key evicted the account")
	}
	s.applyAccountRecord(rec(remove, "acme", []byte{skAccount}, 0, false))
	if _, ok := s.accCache.get("acme"); ok {
		t.Fatal("a deleted account is still cached")
	}
}

// busyShard is shard "busy" with a new record at every read, dated behind before
// the fake clock, and each read taking 20 ms, so a follower never meets an empty
// page there. Any other shard is the fake stream's.
type busyShard struct {
	*fakeStream
	now    *time.Time
	behind time.Duration
	pages  int
	during func() // run at each page, to look at the follower mid-pass
}

func (b *busyShard) GetRecords(ctx context.Context, in *dynamodbstreams.GetRecordsInput, o ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error) {
	if !strings.HasPrefix(*in.ShardIterator, "busy:") {
		return b.fakeStream.GetRecords(ctx, in, o...)
	}
	b.pages++
	*b.now = b.now.Add(20 * time.Millisecond)
	if b.during != nil {
		b.during()
	}
	if b.pages > 5000 { // a follower that never leaves a busy shard is stopped here, to fail
		return &dynamodbstreams.GetRecordsOutput{NextShardIterator: in.ShardIterator}, nil
	}
	at := b.now.Add(-b.behind)
	return &dynamodbstreams.GetRecordsOutput{NextShardIterator: in.ShardIterator, Records: []stypes.Record{{
		Dynamodb: &stypes.StreamRecord{SequenceNumber: aws.String(strconv.Itoa(b.pages)), ApproximateCreationDateTime: &at},
	}}}, nil
}

func busyFollower(t *testing.T, behind time.Duration) (*feed, *busyShard, *fakeStream, *time.Time) {
	t.Helper()
	fs, f, _, _, _ := feedFixture(t)
	now := time.Now()
	f.interval, f.clock = time.Second, func() time.Time { return now }
	fs.open("busy", "")
	fs.open("quiet", "")
	if err := f.position(context.Background(), "arn"); err != nil {
		t.Fatal(err)
	}
	b := &busyShard{fakeStream: fs, now: &now, behind: behind}
	f.streams = b
	f.apply = func(stypes.Record) {}
	return f, b, fs, &now
}

// A shard that always has another record ends no pass by an empty page. A follower
// keeping up with it is current for as long as it keeps up, and the shards beside
// it are read: without this every process answers 503 under sustained writes.
func TestAFollowerKeepingUpWithABusyShardIsCurrent(t *testing.T) {
	t.Parallel()
	f, b, fs, now := busyFollower(t, time.Second)
	var quiet []stypes.Record
	f.apply = func(r stypes.Record) { quiet = append(quiet, r) }
	b.during = func() {
		if !f.current(*now) {
			t.Fatalf("not current at page %d, a second behind its shard", b.pages)
		}
	}
	for range 120 { // two minutes of passes, four unsyncedAfter
		fs.write("quiet", stypes.Record{Dynamodb: &stypes.StreamRecord{}})
		before := b.pages
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.pages-before > 100 {
			t.Fatalf("one pass read %d pages of a busy shard: an interval is 50", b.pages-before)
		}
	}
	if !f.current(*now) {
		t.Error("not current after two minutes, a second behind its shard")
	}
	if len(quiet) < 120 {
		t.Errorf("%d records of the quiet shard read in 120 passes", len(quiet))
	}
}

// A follower that a busy shard's last record shows is behind by more than
// unsyncedAfter is not current, however fast it reads.
func TestAFollowerFarBehindABusyShardIsNotCurrent(t *testing.T) {
	t.Parallel()
	f, _, _, now := busyFollower(t, 2*time.Minute)
	for range 40 {
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.current(*now) {
		t.Errorf("current, two minutes behind, with unsyncedAfter %s", f.unsyncedAfter())
	}
}

// A busy shard's record that carries no date shows nothing, so it cannot make the
// follower current.
func TestAPageWithNoDateShowsNothing(t *testing.T) {
	t.Parallel()
	f, b, _, now := busyFollower(t, 0)
	f.streams = undated{b}
	for range 40 {
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.current(*now) {
		t.Error("current, with no date to show it by")
	}
}

type undated struct{ *busyShard }

func (u undated) GetRecords(ctx context.Context, in *dynamodbstreams.GetRecordsInput, o ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error) {
	out, err := u.busyShard.GetRecords(ctx, in, o...)
	if err == nil {
		for i := range out.Records {
			out.Records[i].Dynamodb.ApproximateCreationDateTime = nil
		}
	}
	return out, err
}

// A pass that met an expired iterator has read nothing of that shard from there, so
// it does not make the follower current; the next pass reads it from where it was.
func TestAnExpiredIteratorDoesNotMakeAFollowerCurrent(t *testing.T) {
	t.Parallel()
	fs, f, s, mailbox, nowMs := feedFixture(t)
	now := time.Now()
	f.interval, f.clock = time.Second, func() time.Time { return now }
	fs.open("s1", "")
	ctx := context.Background()
	if err := f.position(ctx, "arn"); err != nil {
		t.Fatal(err)
	}
	if err := f.once(ctx); err != nil {
		t.Fatal(err)
	}
	fs.write("s1", msgEvent(stypes.OperationTypeInsert, mailbox, 1, nowMs))
	if err := f.once(ctx); err != nil {
		t.Fatal(err)
	}
	if s.countOf(mailbox) != 1 {
		t.Fatal("the first record was not read")
	}
	now = now.Add(20 * time.Minute) // a stall, of AWS or of this process
	fs.write("s1", msgEvent(stypes.OperationTypeInsert, mailbox, 2, nowMs))
	fs.expire["s1"] = true
	if err := f.once(ctx); err != nil {
		t.Fatal(err)
	}
	if f.current(now) {
		t.Errorf("current with a record unread on the shard (count %d)", s.countOf(mailbox))
	}
	if err := f.once(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.current(now) || s.countOf(mailbox) != 2 {
		t.Errorf("after the next pass: current %v, count %d", f.current(now), s.countOf(mailbox))
	}
}

// A process answers only while every one of its followers is current: one follower
// behind makes it not ready, whichever it is (ARCHITECTURE.md § The in-process plan,
// item 6).
func TestAProcessIsNotReadyWhileAFollowerIsBehind(t *testing.T) {
	t.Parallel()
	now := time.Now()
	follower := func() *feed {
		f := &feed{interval: time.Second, clock: func() time.Time { return now }}
		f.synced.Store(now.UnixNano())
		return f
	}
	s := &dynamoBackend{mailboxFeed: follower(), msgFeed: follower(), accFeed: follower()}
	if s.Ready() {
		t.Fatal("ready before Start")
	}
	s.ready.Store(true)
	if !s.Ready() {
		t.Fatal("not ready, with every follower current")
	}
	for name, f := range map[string]*feed{"mailboxes": s.mailboxFeed, "messages": s.msgFeed, "accounts": s.accFeed} {
		f.synced.Store(now.Add(-f.unsyncedAfter() - time.Second).UnixNano())
		if s.Ready() {
			t.Errorf("ready, with the %s follower behind", name)
		}
		f.synced.Store(now.UnixNano())
		if !s.Ready() {
			t.Errorf("not ready, with the %s follower current again", name)
		}
	}
}
