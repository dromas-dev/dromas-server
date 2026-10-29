package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/dromas-dev/dromas-client/protocol"
)

// dynamoBackend is the production backend (ARCHITECTURE.md § Storage): box
// records in one DynamoDB table, messages in another (each item a live
// message's header), accounts in a third, bodies in an S3 Express One
// Zone directory bucket, and each table's stream for the feed (feed). It is
// the mapping of the AWS SDK to the Backend's operations and their three
// outcomes, and nothing more: what a write's answer means is read in one
// place (written), and every call to AWS is bounded in one place (bound, and
// boundedStreams for the streams).
//
// A send writes the body, then the message item; an ack deletes the body,
// then the item. Neither pair is atomic, and neither
// needs to be: each step is safe to repeat.
type dynamoBackend struct {
	db     *dynamodb.Client
	s3     *s3.Client
	boxes  string // -boxes-table
	msgs   string // -msgs-table
	accts  string // -accounts-table
	bucket string
	now    func() time.Time
	log    *log.Logger

	// consistent makes every read strongly consistent; otherwise only the
	// reads that fill memory, and a held list's page, are
	// (DynamoConfig.ConsistentReads).
	consistent bool

	streams                   streamsAPI
	interval                  time.Duration
	boxFeed, msgFeed, accFeed *feed
	apply                     func(Change) // what Start was given
	metrics                   *Metrics
	fatal                     func(error)
	ready                     atomic.Bool

	// crash, in tests, fails a write of two steps between them, as a
	// crash there would leave it: "put: after the body", "ack: after the
	// body".
	crash func(step string) error
}

// DynamoConfig configures a store over DynamoDB and S3 Express.
type DynamoConfig struct {
	AWS                                          aws.Config
	BoxesTable, MsgsTable, AccountsTable, Bucket string
	Now                                          func() time.Time // time.Now if nil
	// BoxCache is how many box records memory holds, as many account
	// records, and as many boxes remembered as missing; 0: none.
	BoxCache       int
	StreamInterval time.Duration // how often each stream shard is read
	Log            *log.Logger   // nil: no log
	// ConsistentReads makes every read strongly consistent, at twice the
	// read units: for tests, which read back what they wrote within
	// milliseconds. Otherwise only the reads that fill memory are, a box's
	// load and a read of what is held of an address, since a stale copy
	// there would decide later answers, and the page of a list asked to
	// wait, which a client may hold on: a strongly consistent read costs
	// twice the read units, and polls are the load, which never fill. A
	// stale read elsewhere costs a retry or one poll; the conditional writes
	// keep the data right.
	ConsistentReads bool
	// Fatal is called if a stream follower loses its place in its stream.
	// Memory can no longer be shown current; the process must restart, which
	// rebuilds it from the tables.
	Fatal func(error)
	// Metrics, if set, count the caches' hits, misses and evictions, how far
	// behind each stream memory follows, and how large each box's item
	// collection a message write grows is. Calls to AWS are counted by
	// Metrics.InstrumentAWS on the AWS config.
	Metrics *Metrics
}

// NewDynamoStore returns the store over DynamoDB and S3 Express: Memory
// over the DynamoDB backend, not ready until Start returns.
func NewDynamoStore(c DynamoConfig) *Memory {
	s := newMemory(c.Now, c.BoxCache, c.Log, c.Metrics)
	if c.StreamInterval <= 0 {
		c.StreamInterval = time.Second
	}
	d := &dynamoBackend{
		db:         dynamodb.NewFromConfig(c.AWS, func(o *dynamodb.Options) { o.APIOptions = append(o.APIOptions, bound) }),
		s3:         newS3(c.AWS),
		streams:    dynamodbstreams.NewFromConfig(c.AWS),
		boxes:      c.BoxesTable,
		msgs:       c.MsgsTable,
		accts:      c.AccountsTable,
		bucket:     c.Bucket,
		now:        s.clock,
		log:        s.log,
		consistent: c.ConsistentReads,
		interval:   c.StreamInterval,
		metrics:    c.Metrics,
		fatal:      c.Fatal,
	}
	d.boxFeed, d.msgFeed, d.accFeed = d.newFeed("boxes", boxStreamChange), d.newFeed("messages", msgStreamChange), d.newFeed("accounts", accountStreamChange)
	s.backend = d
	return s
}

// newS3 is an S3 client on cfg, each call bounded (bound).
func newS3(cfg aws.Config, opts ...func(*s3.Options)) *s3.Client {
	return s3.NewFromConfig(cfg, append([]func(*s3.Options){func(o *s3.Options) { o.APIOptions = append(o.APIOptions, bound) }}, opts...)...)
}

// bound is the one bound on each call the DynamoDB backend makes to
// DynamoDB and S3, its retries included, whatever context its caller handed
// it: storeTimeout, as the first step of every operation's stack, which the
// SDK's documented way to change every call of a client is (its APIOptions).
// A body S3 answers with is read after its call returns, within the same
// bound, which ends when the body is closed. A call that never answers ends
// there, and its caller is answered 503; a write's caller meets a write
// whose outcome is unknown.
func bound(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("dromasBound", func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		ctx, cancel := context.WithTimeout(ctx, storeTimeout)
		out, md, err := next.HandleInitialize(ctx, in)
		if o, ok := out.Result.(*s3.GetObjectOutput); ok && err == nil && o.Body != nil {
			o.Body = cancelOnClose{o.Body, cancel}
			return out, md, err
		}
		cancel()
		return out, md, err
	}), middleware.Before)
}

// cancelOnClose is a body read within its call's bound, which ends when the
// body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

func (s *dynamoBackend) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Printf(format, args...)
	}
}

// newFeed is the follower of a table's stream, which hands each change,
// as change decodes it, to what Start was given.
func (s *dynamoBackend) newFeed(table string, change func(stypes.Record) (Change, error)) *feed {
	applied := func(r stypes.Record) {
		switch c, err := change(r); {
		case err != nil:
			s.logf("%s: skipping a record whose key does not read: %v", table, err)
		case c.Kind != 0 && s.apply != nil:
			s.apply(c)
		}
		if r.Dynamodb != nil && r.Dynamodb.ApproximateCreationDateTime != nil {
			s.metrics.applied(table, *r.Dynamodb.ApproximateCreationDateTime, s.now())
		}
	}
	return &feed{streams: s.streams, interval: s.interval, apply: applied, logf: s.logf, shards: map[string]*shard{}}
}

// Start implements Backend: it positions a follower on every open shard of
// the three streams, then returns; the streams are followed until ctx ends,
// each change handed to apply.
func (s *dynamoBackend) Start(ctx context.Context, apply func(Change)) error {
	s.apply = apply
	feeds := []struct {
		f     *feed
		table string
	}{{s.boxFeed, s.boxes}, {s.msgFeed, s.msgs}, {s.accFeed, s.accts}}
	for _, x := range feeds {
		arn, err := streamARN(ctx, s.db, x.table)
		if err != nil {
			return err
		}
		if err := x.f.position(ctx, arn); err != nil {
			return err
		}
	}
	lostPlace := func(err error) {
		s.ready.Store(false)
		if s.fatal != nil {
			s.fatal(err)
		}
	}
	for _, x := range feeds {
		go x.f.run(ctx, lostPlace)
	}
	s.ready.Store(true)
	return nil
}

// Ready implements Backend: the three streams are followed.
func (s *dynamoBackend) Ready() bool { return s.ready.Load() }

// Keys. Every key is binary. Boxes: addr is the address, sk 0x00 its box's
// record and 0x01 its revocations, the identity's, kept with or without a
// box; one Query of the address reads both. A record in an account carries
// account, the key of the sparse index of each account's boxes. Messages: box
// and id, and while the message is unacked, live = received_at (ms, u64
// big-endian) ‖ id, the sort key of the sparse index that lists a box's
// unacked mail oldest first.
const (
	skBox         byte = 0x00
	skRevocations byte = 0x01
	liveIndex          = "live"
	accountIndex       = "account"
)

func (s *dynamoBackend) nowMs() uint64 { return ms(s.now()) }

// ttlSeconds is the TTL attribute: DynamoDB deletes the item some time after
// it, so reads judge expiry from received_at.
func ttlSeconds(expMs uint64) uint64 { return (expMs + 999) / 1000 }

func boxKey(a protocol.Address) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"addr": bin(a[:]), "sk": bin([]byte{skBox})}
}

func revocationsKey(a protocol.Address) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"addr": bin(a[:]), "sk": bin([]byte{skRevocations})}
}

func msgKey(box protocol.Address, id [32]byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"box": bin(box[:]), "id": bin(id[:])}
}

func liveKey(receivedMs uint64, id [32]byte) []byte {
	k := binary.BigEndian.AppendUint64(make([]byte, 0, 40), receivedMs)
	return append(k, id[:]...)
}

// fromLiveKey reads received_at in ms, and the id, from a live key.
func fromLiveKey(k []byte) (uint64, [32]byte, error) {
	var id [32]byte
	if len(k) != 40 {
		return 0, id, errors.New("item: not a live key")
	}
	copy(id[:], k[8:])
	return binary.BigEndian.Uint64(k[:8]), id, nil
}

func bodyKey(box protocol.Address, id [32]byte) string { return box.String() + "/" + hexID(id) }

func bin(b []byte) types.AttributeValue { return &types.AttributeValueMemberB{Value: b} }
func num(v uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(v, 10)}
}
func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// item is a DynamoDB item, read with checks.
type item map[string]types.AttributeValue

func (it item) bytes(name string) ([]byte, error) {
	if v, ok := it[name].(*types.AttributeValueMemberB); ok {
		return v.Value, nil
	}
	return nil, fmt.Errorf("item: %s is missing or not binary", name)
}

// hash reads a 32-byte binary attribute: an address or an id.
func (it item) hash(name string) ([32]byte, error) {
	var h [32]byte
	b, err := it.bytes(name)
	if err != nil {
		return h, err
	}
	if len(b) != len(h) {
		return h, fmt.Errorf("item: %s is not 32 bytes", name)
	}
	copy(h[:], b)
	return h, nil
}

func (it item) uint(name string) (uint64, error) {
	if v, ok := it[name].(*types.AttributeValueMemberN); ok {
		return strconv.ParseUint(v.Value, 10, 64)
	}
	return 0, fmt.Errorf("item: %s is missing or not a number", name)
}

// size reads a message's size: a number no larger than the protocol's
// largest ciphertext, so it is an int on every platform.
func (it item) size(name string) (int, error) {
	if v, ok := it[name].(*types.AttributeValueMemberN); ok {
		n, err := strconv.ParseUint(v.Value, 10, 31)
		if err != nil || n > protocol.MaxCiphertext {
			return 0, fmt.Errorf("item: %s is not a size of at most %d bytes", name, protocol.MaxCiphertext)
		}
		return int(n), nil
	}
	return 0, fmt.Errorf("item: %s is missing or not a number", name)
}

func (it item) string(name string) (string, error) {
	if v, ok := it[name].(*types.AttributeValueMemberS); ok {
		return v.Value, nil
	}
	return "", fmt.Errorf("item: %s is missing or not a string", name)
}

// boxItemKey reads the key of an item of the -boxes-table table: its
// address, and its sk.
func boxItemKey(it item) (protocol.Address, []byte, error) {
	a, err := it.hash("addr")
	if err != nil {
		return a, nil, err
	}
	sk, err := it.bytes("sk")
	return a, sk, err
}

// The box record.

// boxState is every attribute of a box record that can change.
func boxState(b *Box) map[string]types.AttributeValue {
	retired := make([]types.AttributeValue, 0, len(b.Retired))
	for _, r := range b.Retired {
		retired = append(retired, &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
			"type":      str(string(r.Type)),
			"not_after": num(ms(r.NotAfter)),
			"key_hash":  bin(r.KeyHash[:]),
		}})
	}
	senders := make([]types.AttributeValue, 0, len(b.SenderKeyTypes))
	for _, t := range b.SenderKeyTypes {
		senders = append(senders, str(t))
	}
	st := map[string]types.AttributeValue{
		"senders":       &types.AttributeValueMemberL{Value: senders},
		"state":         str(string(b.State)),
		"statement":     bin(b.Statement),
		"statement_sig": bin(b.Signature),
		"cert_serial":   num(b.CertSerial),
		"cert":          bin(b.Cert[:]),
		"retired":       &types.AttributeValueMemberL{Value: retired},
		"rev":           num(b.Rev),
	}
	// The TTL attribute: DynamoDB deletes the record some time after it.
	if !b.Expires.IsZero() {
		st["expires_at"] = num(uint64(b.Expires.Unix())) //nolint:gosec // a time after 1970
	}
	// The box's ACL, as the document GET answers: absent until the box puts
	// one, then replaced whole. No route removes it, and UpdateBox only sets.
	if b.ACL != nil {
		doc, err := json.Marshal(b.ACL.Document())
		if err == nil { // a document of strings and a number always marshals
			st["acl"] = bin(doc)
		}
	}
	return st
}

func boxItem(b *Box) map[string]types.AttributeValue {
	it := boxKey(b.Addr)
	it["identity"] = bin(b.Identity)
	it["created"] = num(ms(b.Created))
	for k, v := range boxState(b) {
		it[k] = v
	}
	return it
}

// decodeStanding reads from a box record what memory holds of it, at its
// rev. Listed is the revocations' to say (index.standing).
func decodeStanding(it item) (Standing, uint64, error) {
	state, err := it.string("state")
	if err != nil {
		return Standing{}, 0, err
	}
	if State(state) != Active { // a record is written active and no other way
		return Standing{}, 0, fmt.Errorf("item: a record's state is %q, not %q", state, Active)
	}
	doc, err := it.bytes("identity")
	if err != nil {
		return Standing{}, 0, err
	}
	key, err := identityWire(doc)
	if err != nil {
		return Standing{}, 0, fmt.Errorf("item: the stored identity: %w", err)
	}
	cert, err := it.hash("cert")
	if err != nil {
		return Standing{}, 0, err
	}
	rev, err := it.uint("rev")
	if err != nil {
		return Standing{}, 0, err
	}
	serial, err := it.uint("cert_serial")
	if err != nil {
		return Standing{}, 0, err
	}
	st := Standing{State: State(state), Key: key, Cert: cert, CertSerial: serial}
	if _, ok := it["account"]; ok {
		acc, err := it.bytes("account")
		if err != nil {
			return Standing{}, 0, err
		}
		st.InAccount = len(acc) > 0
	}
	return st, rev, nil
}

// decodeACL reads a box record's ACL. It was checked when it was stored, so
// one that does not read is a fault of the record.
func decodeACL(it item) (*protocol.ACL, error) {
	doc, err := it.bytes("acl")
	if err != nil {
		return nil, err
	}
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("item: the stored ACL: %w", err)
	}
	acl, err := protocol.CheckACL(&d, 0)
	if err != nil {
		return nil, fmt.Errorf("item: the stored ACL: %w", err)
	}
	return acl, nil
}

func decodeBox(it item) (*Box, error) {
	a, err := it.hash("addr")
	if err != nil {
		return nil, err
	}
	st, rev, err := decodeStanding(it)
	if err != nil {
		return nil, err
	}
	b := &Box{Addr: a, State: st.State, Cert: st.Cert, CertSerial: st.CertSerial, Rev: rev}
	if b.Identity, err = it.bytes("identity"); err != nil {
		return nil, err
	}
	if _, ok := it["account"]; ok {
		acc, err := it.bytes("account")
		if err != nil {
			return nil, err
		}
		b.Account = string(acc)
	}
	if _, ok := it["expires_at"]; ok {
		exp, err := it.uint("expires_at")
		if err != nil {
			return nil, err
		}
		b.Expires = time.Unix(int64(exp), 0).UTC() //nolint:gosec // written from a time after 1970
	}
	if _, ok := it["acl"]; ok {
		if b.ACL, err = decodeACL(it); err != nil {
			return nil, err
		}
	}
	if b.Statement, err = it.bytes("statement"); err != nil {
		return nil, err
	}
	if b.Signature, err = it.bytes("statement_sig"); err != nil {
		return nil, err
	}
	created, err := it.uint("created")
	if err != nil {
		return nil, err
	}
	b.Created = fromMs(created)
	if b.Prekey, err = protocol.ParsePrekey(b.Statement); err != nil {
		return nil, fmt.Errorf("item: the stored prekey: %w", err)
	}
	// A record written before boxes declared sender key types has none: it
	// declared nothing.
	if v, ok := it["senders"]; ok {
		l, ok := v.(*types.AttributeValueMemberL)
		if !ok {
			return nil, errors.New("item: senders is not a list")
		}
		for _, e := range l.Value {
			t, ok := e.(*types.AttributeValueMemberS)
			if !ok {
				return nil, errors.New("item: a sender key type is not a string")
			}
			b.SenderKeyTypes = append(b.SenderKeyTypes, t.Value)
		}
	}
	l, ok := it["retired"].(*types.AttributeValueMemberL)
	if !ok {
		return nil, errors.New("item: retired is missing or not a list")
	}
	for _, v := range l.Value {
		m, ok := v.(*types.AttributeValueMemberM)
		if !ok {
			return nil, errors.New("item: a retired prekey is not a map")
		}
		r := item(m.Value)
		t, err := r.string("type")
		if err != nil {
			return nil, err
		}
		notAfter, err := r.uint("not_after")
		if err != nil {
			return nil, err
		}
		h, err := r.bytes("key_hash")
		if err != nil || len(h) != 32 {
			return nil, errors.New("item: bad key_hash")
		}
		ret := Retired{Type: protocol.KeyType(t), NotAfter: fromMs(notAfter)}
		copy(ret.KeyHash[:], h)
		b.Retired = append(b.Retired, ret)
	}
	return b, nil
}

// The revocations item.

// decodeRevocations reads an address's revocations item.
func decodeRevocations(it item) (*Revocations, error) {
	rv := &Revocations{}
	var err error
	if rv.Identity, err = it.bytes("identity"); err != nil {
		return nil, err
	}
	if _, ok := it["revocation"]; ok {
		if rv.Address, err = it.bytes("revocation"); err != nil {
			return nil, err
		}
	}
	if _, ok := it["through"]; ok {
		if rv.Through, err = it.uint("through"); err != nil {
			return nil, err
		}
		if rv.Certs, err = it.bytes("revoked_certs"); err != nil {
			return nil, err
		}
		if rv.CertsSig, err = it.bytes("revoked_certs_sig"); err != nil {
			return nil, err
		}
	}
	return rv, nil
}

// ReadAddress implements Backend: one strongly consistent Query of the
// address's items, its box's record and its revocations.
func (s *dynamoBackend) ReadAddress(ctx context.Context, a protocol.Address) (*Box, *Revocations, error) {
	var rec *Box
	var rv *Revocations
	p := dynamodb.NewQueryPaginator(s.db, &dynamodb.QueryInput{
		TableName:                 &s.boxes,
		KeyConditionExpression:    aws.String("#a = :a"),
		ExpressionAttributeNames:  map[string]string{"#a": "addr"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":a": bin(a[:])},
		ConsistentRead:            aws.Bool(true),
	})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, it := range out.Items {
			_, sk, err := boxItemKey(it)
			if err != nil {
				return nil, nil, err
			}
			switch {
			case bytes.Equal(sk, []byte{skBox}):
				if rec, err = decodeBox(it); err != nil {
					return nil, nil, err
				}
			case bytes.Equal(sk, []byte{skRevocations}):
				if rv, err = decodeRevocations(it); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	return rec, rv, nil
}

// Message items.

// msgItem is a new message's item: its header, and its entry in the live
// index. It names no sender (PROTOCOL.md §13).
func msgItem(box protocol.Address, h *Header) map[string]types.AttributeValue {
	recv := ms(h.ReceivedAt)
	it := msgKey(box, h.ID)
	it["size"] = num(uint64(h.Size)) //nolint:gosec // a size is not negative
	it["received_at"] = num(recv)
	it["expires_at"] = num(ttlSeconds(recv + ttlMs))
	it["live"] = bin(liveKey(recv, h.ID))
	return it
}

// decodeMsg reads a message item, and whether it is in the list: every item
// this build writes is, until it is deleted; one out of it is an ack of a
// build before dromas-dev/dromas-client#507, kept until its TTL, and no
// message. Expiry is the caller's to judge.
func decodeMsg(it item) (*Header, bool, error) {
	id, err := it.hash("id")
	if err != nil {
		return nil, false, err
	}
	recv, err := it.uint("received_at")
	if err != nil {
		return nil, false, err
	}
	size, err := it.size("size")
	if err != nil {
		return nil, false, err
	}
	h := &Header{ID: id, Size: size, ReceivedAt: fromMs(recv), ExpiresAt: fromMs(recv + ttlMs)}
	_, live := it["live"]
	return h, live, nil
}

// decodeLive reads an entry of the live index: the key and the size.
func decodeLive(it item) (*Header, error) {
	k, err := it.bytes("live")
	if err != nil {
		return nil, err
	}
	recv, id, err := fromLiveKey(k)
	if err != nil {
		return nil, err
	}
	size, err := it.size("size")
	if err != nil {
		return nil, err
	}
	return &Header{ID: id, Size: size, ReceivedAt: fromMs(recv), ExpiresAt: fromMs(recv + ttlMs)}, nil
}

func isConditionFailed(err error) (*types.ConditionalCheckFailedException, bool) {
	var ccf *types.ConditionalCheckFailedException
	return ccf, errors.As(err, &ccf)
}

func isNoSuchKey(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

// IsThrottle reports whether err is AWS refusing for capacity: a throttle,
// or the SDK's own retry quota running out.
func IsThrottle(err error) bool {
	var q ratelimit.QuotaExceededError
	if errors.As(err, &q) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		_, ok := retry.DefaultThrottleErrorCodes[api.ErrorCode()]
		return ok
	}
	return false
}

// note records whether a write's calls made an attempt that left open
// whether it was applied: a fault of AWS's own, an answer lost, a timeout,
// which the SDK retries. One note serves every call of one write, a
// transaction's tries among them (dromas-dev/dromas-server#101), so a
// write one attempt of which left it open stays open whatever came after
// (written).
type note struct{ seen atomic.Bool }

// noting is the SDK's retryer, noting each failed attempt it would retry
// for an error that is not a throttle: one that leaves open whether the
// attempt was applied. It is asked of every failed attempt, the last
// included, and of one whose retry the retry quota then refuses.
type noting struct {
	aws.RetryerV2
	n *note
}

func (n noting) IsErrorRetryable(err error) bool {
	ok := n.RetryerV2.IsErrorRetryable(err)
	if ok && !IsThrottle(err) {
		n.n.seen.Store(true)
	}
	return ok
}

// option is the option of each write call the note serves: the client's
// retryer, noting. The SDK's retryers, retry.Standard and
// retry.AdaptiveMode, are each a RetryerV2.
func (n *note) option() func(*dynamodb.Options) {
	return func(o *dynamodb.Options) {
		if v2, ok := o.Retryer.(aws.RetryerV2); ok {
			o.Retryer = noting{RetryerV2: v2, n: n}
		}
	}
}

// written is the one reading of what AWS answered a write of this backend,
// as one of the three outcomes (Backend); cond is the refusal the write's
// condition states when it fails, or nil for a write with none. err nil:
// applied. After an attempt that left it open (n): unknown, whatever came
// after, a failed condition or a throttle among them, since a failed
// condition may be the one that attempt's own write makes
// (dromas-dev/dromas-server#89). Otherwise a refusal stated: the
// write's condition failed (cond), or it met a transaction on its item,
// which changes the item if it commits, so it is answered as its failed
// condition; a throttle or the SDK's retry quota running out; or any other
// answer of 4xx, whatever fault the SDK gives it (those of DynamoDB's
// refusals the SDK does not model carry none; #90). Anything else is
// unknown: an answer lost, a timeout, a fault of AWS's own.
func written(err error, n *note, cond error) error {
	if err == nil {
		return nil
	}
	if n != nil && n.seen.Load() {
		return fmt.Errorf("%w, after an attempt that left it open: %w", ErrUnknown, err)
	}
	if _, ok := isConditionFailed(err); ok && cond != nil || isTransactionConflict(err) && cond != nil {
		return cond
	}
	var status interface{ HTTPStatusCode() int }
	if IsThrottle(err) || errors.As(err, &status) && status.HTTPStatusCode() >= 400 && status.HTTPStatusCode() < 500 {
		return refused(err)
	}
	return unknown(err)
}

// ReadLive implements Backend: one strongly consistent Query of the box's
// entries in the live index, which a local secondary index allows.
func (s *dynamoBackend) ReadLive(ctx context.Context, box protocol.Address) ([]Header, error) {
	var hs []Header
	p := dynamodb.NewQueryPaginator(s.db, s.liveQuery(box, s.liveFrom(), true))
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			h, err := decodeLive(it)
			if err != nil {
				return nil, err
			}
			hs = append(hs, *h)
		}
	}
	return hs, nil
}

// liveFrom is the lowest live key at now: received_at > now − Retention
// (ttlMs, protocol.Retention), so an expired message the TTL has not yet
// deleted is never read.
func (s *dynamoBackend) liveFrom() []byte { return liveKey(s.nowMs()-ttlMs+1, [32]byte{}) }

// liveQuery is a Query of a box's entries in the live index from lo.
func (s *dynamoBackend) liveQuery(box protocol.Address, lo []byte, consistent bool) *dynamodb.QueryInput {
	return &dynamodb.QueryInput{
		TableName:                 &s.msgs,
		IndexName:                 aws.String(liveIndex),
		KeyConditionExpression:    aws.String("#b = :b AND #l BETWEEN :lo AND :hi"),
		ProjectionExpression:      aws.String("#l, #s"),
		ExpressionAttributeNames:  map[string]string{"#b": "box", "#l": "live", "#s": "size"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":b": bin(box[:]), ":lo": bin(lo), ":hi": bin(bytes.Repeat([]byte{0xff}, 40))},
		ConsistentRead:            aws.Bool(consistent),
	}
}

// CreateBox implements Backend.
func (s *dynamoBackend) CreateBox(ctx context.Context, b *Box) error {
	n := new(note)
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.boxes,
		Item:                     boxItem(b),
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "addr"},
	}, n.option())
	return written(err, n, ErrExists) // it has a record, whoever wrote it
}

// UpdateBox implements Backend: every attribute that can change, if the
// record is still at b.Rev. Attributes it does not name are left alone.
func (s *dynamoBackend) UpdateBox(ctx context.Context, b *Box) error {
	next := cloneBox(b)
	next.Rev = b.Rev + 1
	names := map[string]string{}
	values := map[string]types.AttributeValue{":old": num(b.Rev)}
	var sets []string
	for k, v := range boxState(next) {
		names["#"+k] = k
		values[":"+k] = v
		sets = append(sets, "#"+k+" = :"+k)
	}
	slices.Sort(sets)
	n := new(note)
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.boxes,
		Key:                       boxKey(b.Addr),
		UpdateExpression:          aws.String("SET " + strings.Join(sets, ", ")),
		ConditionExpression:       aws.String("#rev = :old"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}, n.option())
	return written(err, n, ErrStale)
}

// DeleteBox implements Backend.
func (s *dynamoBackend) DeleteBox(ctx context.Context, a protocol.Address) error {
	n := new(note)
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.boxes, Key: boxKey(a)}, n.option())
	return written(err, n, nil)
}

// Revoke implements Backend: one UpdateItem of the address's revocations
// item, which keeps the revocation of the address once and takes a
// revocation of certificates only through a higher serial than the one it
// holds, and, where want asks it, only where the item exists, or only where
// it does not: its identity, which every write of it sets, is there or not.
func (s *dynamoBackend) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, error) {
	names := map[string]string{"#i": "identity"}
	values := map[string]types.AttributeValue{":i": bin(rv.Identity)}
	sets := []string{"#i = if_not_exists(#i, :i)"}
	var conds []string
	if len(rv.Address) > 0 {
		names["#r"], values[":r"] = "revocation", bin(rv.Address)
		sets = append(sets, "#r = if_not_exists(#r, :r)")
	}
	if rv.Through > 0 {
		names["#c"], names["#s"], names["#t"] = "revoked_certs", "revoked_certs_sig", "through"
		values[":c"], values[":s"], values[":t"] = bin(rv.Certs), bin(rv.CertsSig), num(rv.Through)
		sets = append(sets, "#c = :c", "#s = :s", "#t = :t")
		conds = append(conds, "attribute_not_exists(#t) OR #t < :t")
	}
	switch want {
	case ExpectHeld:
		conds = append(conds, "attribute_exists(#i)")
	case ExpectNone:
		conds = append(conds, "attribute_not_exists(#i)")
	}
	var cond *string
	switch len(conds) {
	case 0:
	case 1:
		cond = aws.String(conds[0])
	default:
		cond = aws.String("(" + strings.Join(conds, ") AND (") + ")")
	}
	n := new(note)
	out, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.boxes,
		Key:                       revocationsKey(a),
		UpdateExpression:          aws.String("SET " + strings.Join(sets, ", ")),
		ConditionExpression:       cond,
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
	}, n.option())
	if err := written(err, n, ErrStale); err != nil { // one through as high a serial is held
		return nil, err
	}
	held, err := decodeRevocations(out.Attributes)
	if err != nil {
		return nil, unknown(fmt.Errorf("applied, and its answer does not read: %w", err))
	}
	return held, nil
}

// getMsg reads a live message's item; ErrNotFound if there is none, it is
// out of the list (decodeMsg), or it has expired.
func (s *dynamoBackend) getMsg(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.msgs, Key: msgKey(box, id), ConsistentRead: aws.Bool(s.consistent)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	h, live, err := decodeMsg(out.Item)
	if err != nil {
		return nil, err
	}
	if !live || ms(h.ExpiresAt) <= s.nowMs() {
		return nil, ErrNotFound // the TTL deletes it later
	}
	return h, nil
}

// Dedupe implements Backend: the live message's item. A stale miss is
// caught by PutMessage's conditional write.
func (s *dynamoBackend) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	return s.getMsg(ctx, box, id)
}

// crashed is a step of a two-step write failing as a crash there would.
func (s *dynamoBackend) crashed(step string) error {
	if s.crash == nil {
		return nil
	}
	return s.crash(step)
}

// PutMessage implements Backend (ARCHITECTURE.md § Storage): the body, then the
// item, if no live one has this id. A crash after the body leaves an orphan
// the lifecycle rule reaps, and the retry writes both again. A body that
// fails stores nothing, whatever S3 answered (errNotStored). A failed
// condition that hands back the item it met tells, whatever came before it:
// one of this write's own time, which an attempt the SDK retried applied, is
// the write, applied (dromas-dev/dromas-server#89), and so is another post's
// of the same bytes in the same millisecond, whose item is this one's to the
// byte; another's is a duplicate.
func (s *dynamoBackend) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) error {
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    aws.String(bodyKey(box, h.ID)),
		Body:   bytes.NewReader(body),
	}); err != nil {
		return fmt.Errorf("%w: %w", errNotStored, err)
	}
	if err := s.crashed("put: after the body"); err != nil {
		return err
	}
	now := s.nowMs()
	n := new(note)
	out, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                           &s.msgs,
		Item:                                msgItem(box, h),
		ConditionExpression:                 aws.String("attribute_not_exists(#l) OR #r <= :cutoff"),
		ExpressionAttributeNames:            map[string]string{"#l": "live", "#r": "received_at"},
		ExpressionAttributeValues:           map[string]types.AttributeValue{":cutoff": num(now - ttlMs)},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
		ReturnItemCollectionMetrics:         types.ReturnItemCollectionMetricsSize,
	}, n.option())
	if ccf, ok := isConditionFailed(err); ok {
		orig, _, err := decodeMsg(ccf.Item) // a live send of the same ciphertext got there first, whose body is the same bytes
		switch {
		case err != nil:
			return unknown(fmt.Errorf("the item its condition met does not read: %w", err))
		case orig.ReceivedAt.Equal(h.ReceivedAt):
			return nil // this send's own item, from an attempt the SDK retried: it is stored
		}
		return duplicate{orig}
	}
	if err := written(err, n, nil); err != nil {
		return err
	}
	if c := out.ItemCollectionMetrics; c != nil && len(c.SizeEstimateRangeGB) == 2 {
		s.metrics.collection(c.SizeEstimateRangeGB[1])
	}
	return nil
}

// Retire implements Backend: the item is deleted, if it is live, and nothing
// of the message is kept.
func (s *dynamoBackend) Retire(ctx context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	now := s.nowMs()
	n := new(note)
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.msgs,
		Key:                       msgKey(box, id),
		ConditionExpression:       aws.String("attribute_exists(#l) AND #r > :cutoff"),
		ExpressionAttributeNames:  map[string]string{"#l": "live", "#r": "received_at"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":cutoff": num(now - ttlMs)},
		ReturnValues:              types.ReturnValueAllOld,
	}, n.option())
	if err := written(err, n, ErrNotFound); err != nil {
		return time.Time{}, err
	}
	k, err := item(out.Attributes).bytes("live")
	if err == nil {
		var recv uint64
		if recv, _, err = fromLiveKey(k); err == nil {
			return fromMs(recv), nil
		}
	}
	return time.Time{}, unknown(fmt.Errorf("applied, and its answer does not read: %w", err))
}

func (s *dynamoBackend) deleteBody(ctx context.Context, box protocol.Address, id [32]byte) error {
	_, err := s.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(box, id))})
	if err != nil && !isNoSuchKey(err) {
		return err
	}
	return nil
}

// Message implements Backend. A live message whose body is gone is
// errNoBody. The body's bytes from byte from on are read with the same
// range (GetObject's Range, RFC 9110 §14.2), so a fetch that resumes moves
// only the rest out of S3.
func (s *dynamoBackend) Message(ctx context.Context, box protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, err := s.getMsg(ctx, box, id)
	if err != nil {
		return nil, nil, err
	}
	in := &s3.GetObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(box, id))}
	if from > 0 && from < int64(h.Size) {
		in.Range = aws.String(protocol.RangeAsk(from))
	}
	out, err := s.s3.GetObject(ctx, in)
	if isNoSuchKey(err) {
		return nil, nil, errNoBody
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, nil, err
	}
	return h, body, nil
}

// DeleteMessage implements Backend (ack): the body, then the item. A body
// that was not deleted leaves the list as it was: a refusal.
func (s *dynamoBackend) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) (time.Time, error) {
	if err := s.deleteBody(ctx, box, id); err != nil {
		return time.Time{}, refused(fmt.Errorf("the body was not deleted, and the message is listed as it was: %w", err))
	}
	if err := s.crashed("ack: after the body"); err != nil {
		return time.Time{}, err
	}
	return s.Retire(ctx, box, id)
}

// DeleteAll implements Backend: the box's live messages, as acks: bodies
// first, then each item. One Query of the live index finds them, strongly
// consistent, which a local secondary index allows: a message stored just
// before it is in it (dromas-dev/dromas-server#15). Until a retire is made,
// nothing a reader of the list sees has changed: a failure there is a
// refusal.
func (s *dynamoBackend) DeleteAll(ctx context.Context, box protocol.Address, retired func([32]byte, time.Time)) error {
	var ids [][32]byte
	p := dynamodb.NewQueryPaginator(s.db, s.liveQuery(box, s.liveFrom(), true))
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return refused(err)
		}
		for _, it := range out.Items {
			k, err := item(it).bytes("live")
			if err != nil {
				return refused(err)
			}
			_, id, err := fromLiveKey(k)
			if err != nil {
				return refused(err)
			}
			ids = append(ids, id)
		}
	}
	for chunk := range slices.Chunk(ids, 1000) {
		objs := make([]s3types.ObjectIdentifier, 0, len(chunk))
		for _, id := range chunk {
			objs = append(objs, s3types.ObjectIdentifier{Key: aws.String(bodyKey(box, id))})
		}
		out, err := s.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &s.bucket, Delete: &s3types.Delete{Objects: objs, Quiet: aws.Bool(true)}})
		if err != nil {
			return refused(err)
		}
		if len(out.Errors) > 0 {
			return refused(fmt.Errorf("deleting bodies: %s", aws.ToString(out.Errors[0].Message)))
		}
	}
	for _, id := range ids {
		switch received, err := s.Retire(ctx, box, id); {
		case err == nil:
			retired(id, received)
		case !errors.Is(err, ErrNotFound):
			return err
		}
	}
	return nil
}

// List implements Backend: a Query of the live index over its live key
// range, strongly consistent where consistent is set, which a local secondary
// index allows. Eventually consistent, a page read just after a write may
// miss it while memory's count has it.
func (s *dynamoBackend) List(ctx context.Context, box protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error) {
	lo := s.liveFrom()
	in := s.liveQuery(box, lo, consistent || s.consistent)
	if after != nil {
		if start := liveKey(ms(after.ReceivedAt), after.ID); bytes.Compare(start, lo) >= 0 {
			k := msgKey(box, after.ID)
			k["live"] = bin(start)
			in.ExclusiveStartKey = k
		}
	}
	var hs []Header
	for len(hs) < limit {
		in.Limit = aws.Int32(int32(limit - len(hs))) //nolint:gosec // a page is small
		out, err := s.db.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			h, err := decodeLive(it)
			if err != nil {
				return nil, err
			}
			hs = append(hs, *h)
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
	return hs, nil
}
