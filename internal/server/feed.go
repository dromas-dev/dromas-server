package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// feed follows one table's DynamoDB stream: every shard, each parent before
// its children (AWS docs, DynamoDB Streams, reading and processing a stream),
// handing each change to memory (dynamoBackend.Start). It keeps no position
// across restarts: a restart rebuilds memory from the tables and follows the
// streams from then on. Each of its calls to AWS is bounded as the store's
// are (boundedStreams): one that never answers ends there, and fails its
// pass as any failed read does, so the follower reads again at its next
// pass.
type feed struct {
	streams  streamsAPI
	interval time.Duration
	apply    func(stypes.Record)
	logf     func(format string, args ...any)

	// Read by the follower's goroutine only, once position has returned.
	arn    string
	shards map[string]*shard
	listed time.Time // the last full listing of shards
	ended  bool      // a shard ended since: list again for its children
}

// streamsAPI is the part of the DynamoDB Streams client the follower uses.
type streamsAPI interface {
	DescribeStream(context.Context, *dynamodbstreams.DescribeStreamInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error)
	GetShardIterator(context.Context, *dynamodbstreams.GetShardIteratorInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetShardIteratorOutput, error)
	GetRecords(context.Context, *dynamodbstreams.GetRecordsInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error)
}

// boundedStreams is the follower's view of its streams, each call bounded by
// storeTimeout whatever context the follower hands it: the one bound of the
// streams' calls, as bound is of the store's other calls to AWS.
type boundedStreams struct{ streamsAPI }

func (b boundedStreams) DescribeStream(ctx context.Context, in *dynamodbstreams.DescribeStreamInput, o ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return b.streamsAPI.DescribeStream(ctx, in, o...)
}

func (b boundedStreams) GetShardIterator(ctx context.Context, in *dynamodbstreams.GetShardIteratorInput, o ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetShardIteratorOutput, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return b.streamsAPI.GetShardIterator(ctx, in, o...)
}

func (b boundedStreams) GetRecords(ctx context.Context, in *dynamodbstreams.GetRecordsInput, o ...func(*dynamodbstreams.Options)) (*dynamodbstreams.GetRecordsOutput, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return b.streamsAPI.GetRecords(ctx, in, o...)
}

// api is the follower's streams, each call bounded.
func (f *feed) api() streamsAPI { return boundedStreams{f.streams} }

type shard struct {
	id, parent string
	iter       *string
	seq        string // the last sequence number applied
	latest     bool   // positioned at LATEST at startup, nothing read since
	done       bool   // read to its end, or closed before startup
}

// relistEvery is how often the follower lists every shard, to find ones it
// was not told about when their parent ended.
const relistEvery = time.Minute

// errLost is a follower that can no longer show it saw every change: it fell
// more than the stream's 24 hours behind, an iterator expired before it read
// anything, or the stream is gone.
type errLost struct{ err error }

func (e *errLost) Error() string { return "stream: lost its place: " + e.err.Error() }
func (e *errLost) Unwrap() error { return e.err }

func lost(err error) bool {
	var t *stypes.TrimmedDataAccessException
	var nf *stypes.ResourceNotFoundException
	return errors.As(err, &t) || errors.As(err, &nf)
}

// streamARN returns a table's stream, which must carry new images.
func streamARN(ctx context.Context, db *dynamodb.Client, table string) (string, error) {
	t, err := db.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &table})
	if err != nil {
		return "", err
	}
	if t.Table.LatestStreamArn == nil || t.Table.StreamSpecification == nil || !aws.ToBool(t.Table.StreamSpecification.StreamEnabled) {
		return "", fmt.Errorf("table %s has no stream", table)
	}
	if v := t.Table.StreamSpecification.StreamViewType; v != types.StreamViewTypeNewImage && v != types.StreamViewTypeNewAndOldImages {
		return "", fmt.Errorf("table %s: the stream must carry new images, not %s", table, v)
	}
	return *t.Table.LatestStreamArn, nil
}

// position puts an iterator at LATEST on every open shard of the stream. A
// closed shard holds only changes from before the load, which the load
// covers.
func (f *feed) position(ctx context.Context, arn string) error {
	f.arn = arn
	all, err := f.list(ctx)
	if err != nil {
		return err
	}
	for _, s := range all {
		sh := &shard{id: aws.ToString(s.ShardId), parent: aws.ToString(s.ParentShardId)}
		if s.SequenceNumberRange != nil && s.SequenceNumberRange.EndingSequenceNumber != nil {
			sh.done = true
		} else {
			out, err := f.api().GetShardIterator(ctx, &dynamodbstreams.GetShardIteratorInput{
				StreamArn: &f.arn, ShardId: s.ShardId, ShardIteratorType: stypes.ShardIteratorTypeLatest,
			})
			if err != nil {
				return err
			}
			sh.iter, sh.latest = out.ShardIterator, true
		}
		f.shards[sh.id] = sh
	}
	f.listed = time.Now()
	return nil
}

func (f *feed) list(ctx context.Context) ([]stypes.Shard, error) {
	var all []stypes.Shard
	in := &dynamodbstreams.DescribeStreamInput{StreamArn: &f.arn}
	for {
		out, err := f.api().DescribeStream(ctx, in)
		if err != nil {
			return nil, err
		}
		all = append(all, out.StreamDescription.Shards...)
		if out.StreamDescription.LastEvaluatedShardId == nil {
			return all, nil
		}
		in.ExclusiveStartShardId = out.StreamDescription.LastEvaluatedShardId
	}
}

// run reads every shard each interval until ctx ends, or the follower loses
// its place, which it reports to fatal.
func (f *feed) run(ctx context.Context, fatal func(error)) {
	// A panic here would end the process with its words on stderr, past the
	// redaction: it is logged through the store's log, which redacts, and
	// ends the process as a lost place does, so a restart rebuilds memory.
	defer func() {
		if p := recover(); p != nil {
			f.logf("stream: panic: %v\n%s", p, debug.Stack())
			fatal(fmt.Errorf("stream: panic: %v", p))
		}
	}()
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		if err := f.pass(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			var l *errLost
			if errors.As(err, &l) {
				fatal(err)
				return
			}
			f.logf("stream: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pass reads each shard whose parent is done, from where it left off.
func (f *feed) pass(ctx context.Context) error {
	if f.ended || time.Since(f.listed) > relistEvery {
		if err := f.relist(ctx); err != nil {
			if lost(err) {
				return &errLost{err}
			}
			return err
		}
	}
	ids := make([]string, 0, len(f.shards))
	for id := range f.shards {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		sh := f.shards[id]
		if sh.done {
			continue
		}
		if p, ok := f.shards[sh.parent]; ok && !p.done {
			continue // a child waits for its parent
		}
		if err := f.read(ctx, sh); err != nil {
			return err
		}
	}
	return nil
}

// relist adds shards not seen before, read from their start, and forgets
// finished ones the stream no longer lists.
func (f *feed) relist(ctx context.Context) error {
	all, err := f.list(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range all {
		id := aws.ToString(s.ShardId)
		seen[id] = true
		if _, ok := f.shards[id]; !ok {
			f.shards[id] = &shard{id: id, parent: aws.ToString(s.ParentShardId)}
		}
	}
	for id, sh := range f.shards {
		if !seen[id] && sh.done {
			delete(f.shards, id)
		}
	}
	f.listed, f.ended = time.Now(), false
	return nil
}

// read drains a shard as far as it goes now.
func (f *feed) read(ctx context.Context, sh *shard) error {
	if sh.iter == nil {
		in := &dynamodbstreams.GetShardIteratorInput{StreamArn: &f.arn, ShardId: &sh.id}
		switch {
		case sh.seq != "":
			in.ShardIteratorType, in.SequenceNumber = stypes.ShardIteratorTypeAfterSequenceNumber, aws.String(sh.seq)
		case sh.latest:
			return &errLost{fmt.Errorf("the iterator for shard %s expired before anything was read", sh.id)}
		default:
			in.ShardIteratorType = stypes.ShardIteratorTypeTrimHorizon
		}
		out, err := f.api().GetShardIterator(ctx, in)
		if lost(err) {
			return &errLost{err}
		}
		if err != nil {
			return err
		}
		if sh.iter = out.ShardIterator; sh.iter == nil {
			sh.done, f.ended = true, true
			return nil
		}
	}
	for {
		out, err := f.api().GetRecords(ctx, &dynamodbstreams.GetRecordsInput{ShardIterator: sh.iter, Limit: aws.Int32(1000)})
		var expired *stypes.ExpiredIteratorException
		if errors.As(err, &expired) {
			sh.iter = nil // re-positioned after the last record, next pass
			return nil
		}
		if lost(err) {
			return &errLost{err}
		}
		if err != nil {
			return err
		}
		for _, r := range out.Records {
			f.apply(r)
			if r.Dynamodb != nil && r.Dynamodb.SequenceNumber != nil {
				sh.seq, sh.latest = *r.Dynamodb.SequenceNumber, false
			}
		}
		if sh.iter = out.NextShardIterator; sh.iter == nil {
			sh.done, f.ended = true, true
			return nil
		}
		if len(out.Records) == 0 {
			return nil
		}
	}
}

// boxStreamChange is the change a record of the --boxes-table stream makes:
// to a box's record (sk 0x00), or to an address's revocations (sk 0x01).
// Other items under an address are not memory's, and make none (Kind 0). An
// image that does not read is a change with Err; a key that does not read
// is an error, and the record is skipped.
func boxStreamChange(r stypes.Record) (Change, error) {
	if r.Dynamodb == nil {
		return Change{}, nil
	}
	gone := r.EventName == stypes.OperationTypeRemove
	it := fromStream(r.Dynamodb.NewImage)
	if gone {
		it = fromStream(r.Dynamodb.Keys)
	}
	a, sk, err := boxItemKey(it)
	if err != nil {
		return Change{}, err
	}
	c := Change{Addr: a, Gone: gone}
	switch {
	case bytes.Equal(sk, []byte{skBox}):
		c.Kind = RecordChange
		if !gone {
			c.Box, c.Err = decodeBox(it)
		}
	case bytes.Equal(sk, []byte{skRevocations}):
		c.Kind = RevocationsChange
		if !gone {
			c.Revocations, c.Err = decodeRevocations(it)
		}
	}
	return c, nil
}

// msgStreamChange is the change a record of the --msgs-table stream makes to
// a message: in the list, or gone (acked, its body found gone, its box's
// address revoked, or expired and taken by the TTL). A deletion's record
// carries the item's keys alone (NEW_IMAGE), so its Header is the id.
func msgStreamChange(r stypes.Record) (Change, error) {
	if r.Dynamodb == nil {
		return Change{}, nil
	}
	gone := r.EventName == stypes.OperationTypeRemove
	it := fromStream(r.Dynamodb.NewImage)
	if gone {
		it = fromStream(r.Dynamodb.Keys)
	}
	box, err := it.hash("box")
	if err != nil {
		return Change{}, err
	}
	c := Change{Kind: MessageChange, Addr: box, Gone: gone}
	if !gone {
		c.Header, c.Live, c.Err = decodeMsg(it)
		return c, nil
	}
	id, err := it.hash("id")
	if err != nil {
		return Change{}, err
	}
	c.Header = &Header{ID: id}
	return c, nil
}

// accountStreamChange is the change a record of the --accounts-table stream
// makes to an account's record (sk 0x00). Its other items, adopt keys, are
// not memory's.
func accountStreamChange(r stypes.Record) (Change, error) {
	if r.Dynamodb == nil {
		return Change{}, nil
	}
	gone := r.EventName == stypes.OperationTypeRemove
	it := fromStream(r.Dynamodb.NewImage)
	if gone {
		it = fromStream(r.Dynamodb.Keys)
	}
	id, rec, err := accountRecord(it)
	if err != nil || !rec {
		return Change{}, err
	}
	c := Change{Kind: AccountChange, AccountID: id, Gone: gone}
	if !gone {
		c.Account, c.Err = decodeAccount(it)
	}
	return c, nil
}

// fromStream converts a stream image to the DynamoDB client's types: the two
// SDK packages declare the same shapes separately.
func fromStream(m map[string]stypes.AttributeValue) item {
	out := make(item, len(m))
	for k, v := range m {
		if c := convertAV(v); c != nil {
			out[k] = c
		}
	}
	return out
}

func convertAV(v stypes.AttributeValue) types.AttributeValue {
	switch v := v.(type) {
	case *stypes.AttributeValueMemberB:
		return &types.AttributeValueMemberB{Value: v.Value}
	case *stypes.AttributeValueMemberS:
		return &types.AttributeValueMemberS{Value: v.Value}
	case *stypes.AttributeValueMemberN:
		return &types.AttributeValueMemberN{Value: v.Value}
	case *stypes.AttributeValueMemberBOOL:
		return &types.AttributeValueMemberBOOL{Value: v.Value}
	case *stypes.AttributeValueMemberNULL:
		return &types.AttributeValueMemberNULL{Value: v.Value}
	case *stypes.AttributeValueMemberBS:
		return &types.AttributeValueMemberBS{Value: v.Value}
	case *stypes.AttributeValueMemberSS:
		return &types.AttributeValueMemberSS{Value: v.Value}
	case *stypes.AttributeValueMemberNS:
		return &types.AttributeValueMemberNS{Value: v.Value}
	case *stypes.AttributeValueMemberL:
		l := make([]types.AttributeValue, 0, len(v.Value))
		for _, e := range v.Value {
			if c := convertAV(e); c != nil {
				l = append(l, c)
			}
		}
		return &types.AttributeValueMemberL{Value: l}
	case *stypes.AttributeValueMemberM:
		return &types.AttributeValueMemberM{Value: fromStream(v.Value)}
	}
	return nil
}
