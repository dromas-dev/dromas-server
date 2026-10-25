package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

// put caches v whatever was written since it was read: how a test makes the
// cache hold a key. No read puts but by fill.
func (c *recCache[K, V]) put(v V) {
	if c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(v)
}

// A copy read before a write is kept out of the record cache where the cache
// did not hold its address: the stream's image of that write was dropped
// there, so the copy may be older than the table
// (dromas-dev/dromas-server#12). A copy of an address the cache holds
// merges, as a put does, and a write to another shard's address leaves a
// read's token standing.
func TestAFillAfterAWriteItDidNotSeeIsNotKept(t *testing.T) {
	t.Parallel()
	var a, other protocol.Address
	a[0], other[0] = 1, 2
	c := newBoxCache(10)
	tok := c.begin(a)
	c.write(a, c.image(&Box{Addr: a, Rev: 3})) // rev 3's image, dropped: a is not held
	c.fill(&Box{Addr: a, Rev: 2}, tok)
	if b, ok := c.get(a); ok {
		t.Fatalf("a copy at rev %d, read before a write it did not see, was kept", b.Rev)
	}
	c.fill(&Box{Addr: a, Rev: 2}, c.begin(a))
	if b, ok := c.get(a); !ok || b.Rev != 2 {
		t.Fatal("a copy read with no write since was not kept")
	}
	c.put(&Box{Addr: a, Rev: 3})
	c.fill(&Box{Addr: a, Rev: 2}, tok)
	if b, ok := c.get(a); !ok || b.Rev != 3 {
		t.Fatalf("a copy of an address held: %v, %v; want rev 3 held", b, ok)
	}
	c.evict(a)
	tok = c.begin(a)
	c.write(other, evicted[*Box])
	c.fill(&Box{Addr: a, Rev: 3}, tok)
	if _, ok := c.get(a); !ok {
		t.Fatal("a write to another shard kept a copy out")
	}
}

// A write and a fill are each one step under the cache's lock: a write
// counts before it applies, and applies under the lock, and a fill whose
// token a write has passed never puts its copy, not even to evict it after,
// while one whose token stands puts it under the lock
// (dromas-dev/dromas-server#95, #96). The cache is made here with a
// clone that notes each copy it is handed to put, and whether the lock is
// held then.
func TestAWriteAndAFillAreEachOneStepUnderTheLock(t *testing.T) {
	t.Parallel()
	var a protocol.Address
	a[0] = 7
	var put []uint64 // the revs of the copies put
	unlocked := 0    // steps taken without the cache's lock
	var c *boxCache
	held := func() bool {
		if c.mu.TryLock() {
			c.mu.Unlock()
			return false
		}
		return true
	}
	c = newRecCache(10, 256, func(a protocol.Address) int { return int(a[0]) },
		func(b *Box) protocol.Address { return b.Addr }, versionOf,
		func(b *Box) *Box {
			if !held() {
				unlocked++
			}
			put = append(put, b.Rev)
			return cloneBox(b)
		})
	tok := c.begin(a)
	c.write(a, func(cur *Box, isHeld, _ bool) (*Box, bool) {
		if !held() {
			unlocked++
		}
		if got := c.writes[a[0]]; token(got) != tok+1 {
			t.Errorf("a write applied at the count %d, its read's token %d: it counts after it applies", got, tok)
		}
		return cur, isHeld
	})
	c.fill(&Box{Addr: a, Rev: 1}, tok)
	if len(put) > 0 {
		t.Errorf("a fill whose token a write passed put its copy (revs %v), which a reader may be given", put)
	}
	c.fill(&Box{Addr: a, Rev: 1}, c.begin(a))
	if len(put) != 1 {
		t.Errorf("a fill whose token stands put %v; want its copy", put)
	}
	if unlocked > 0 {
		t.Errorf("%d steps of a write or a fill were taken without the cache's lock", unlocked)
	}
}

// A registration that raced a revocation of its address leaves no copy
// without the revocation in the record cache (dromas-dev/dromas-server#41):
// the revocation's image came while the cache did not hold the address, and
// the registration's view is put after it. A registration with no write to
// its address meanwhile is cached, so the box's first call reads nothing.
func TestARegistrationThatRacedARevocationIsNotCachedWithoutIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	s := NewDynamoStore(DynamoConfig{BoxCache: 10}) // never started: memory alone
	now := time.Now()
	register := func(r *raw, during func()) {
		a := r.id.Address()
		if !s.cache.missingAt(a, now) {
			s.cache.missed(a, s.cache.begin(a), now) // the registration's read finds nothing
		}
		during()
		s.applyBox(&Box{Addr: a, Identity: r.id.Document(), State: Active, Rev: 1})
	}
	raced, alone := e.raw(), e.raw()
	register(raced, func() {
		s.applyRevocations(raced.id.Address(), &Revocations{Identity: raced.id.Document(), Address: []byte("the identity's revocation")})
	})
	if b, ok := s.Known(raced.id.Address()); ok && b != nil && b.State != Revoked {
		t.Errorf("after a registration that raced a revocation, memory holds the box %s, without the revocation", b.State)
	}
	register(alone, func() {})
	if b, ok := s.Known(alone.id.Address()); !ok || b == nil || b.State != Active {
		t.Errorf("a registration with no write meanwhile is not cached: %v, %v", b, ok)
	}
}

// Two copies of an address merge to every revocation either holds, whichever
// is the newer record and whether or not a stored revocation of certificates
// parses (dromas-dev/dromas-server#64): one that does not parse stands in
// place of one that does, so that its next use fails closed.
func TestMergedCopiesKeepEveryRevocation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw()
	a, doc := r.id.Address(), r.id.Document()
	revocation := []byte("the identity's revocation")
	bad := []byte("not a revocation of certificates\n")
	low, high := r.certs(1), r.certs(5)
	revoked := &Box{Addr: a, Identity: doc, State: Revoked, Rev: 1, Revocation: revocation}
	badList := &Box{Addr: a, Identity: doc, State: Active, Rev: 2, RevokedCerts: bad, RevokedCertsSig: []byte("x")}
	at := func(rev uint64, c protocol.Revocations) *Box {
		return &Box{Addr: a, Identity: doc, State: Active, Rev: rev, RevokedCerts: c.RevokedCertificates, RevokedCertsSig: c.RevokedCertificatesSignature}
	}
	revokedBad := &Box{Addr: a, Identity: doc, State: Revoked, Rev: 1, Revocation: revocation, RevokedCerts: bad, RevokedCertsSig: []byte("x")}
	for _, c := range []struct {
		name     string
		old, cur *Box
		revoked  bool
		certs    []byte
	}{
		{"the newer copy's list does not parse", revoked, badList, true, bad},
		{"the older copy's list does not parse", revokedBad, at(2, low), true, bad},
		{"the older copy's list reaches higher", at(1, high), at(2, low), false, high.RevokedCertificates},
		{"the newer copy's list reaches higher", at(1, low), at(2, high), false, high.RevokedCertificates},
		{"the older copy holds the revocation", revoked, at(2, low), true, low.RevokedCertificates},
	} {
		for _, order := range []string{"older cached", "newer cached"} {
			old, cur := c.old, c.cur
			if order == "newer cached" {
				old, cur = cur, old
			}
			m := mergeViews(old, cur)
			if got := m.State == Revoked && len(m.Revocation) > 0; got != c.revoked {
				t.Errorf("%s, %s: revoked %v, want %v", c.name, order, got, c.revoked)
			}
			if string(m.RevokedCerts) != string(c.certs) {
				t.Errorf("%s, %s: the revocation of certificates kept is not the one that stands", c.name, order)
			}
			if m.Rev != 2 {
				t.Errorf("%s, %s: the record of rev %d, want the newer", c.name, order, m.Rev)
			}
		}
	}
	cache := newBoxCache(10)
	cache.put(revoked)
	cache.put(badList)
	if b, _ := cache.get(a); b.State != Revoked {
		t.Errorf("the cache, given the issue's two copies, holds the box %s", b.State)
	}
}

// cannedTables answers a store on DynamoDB from items held in the test, in
// process: a Query of the boxes table with the address's items, one of the
// live index with none, a GetItem of the accounts table with the account's
// record, and a PutItem with a failed condition, as a registration that
// another made first meets. No AWS is called.
type cannedTables struct {
	mu      sync.Mutex
	address []map[string]types.AttributeValue
	account map[string]types.AttributeValue
}

// set makes the address's items it.
func (c *cannedTables) set(it ...map[string]types.AttributeValue) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.address = it
}

// attrJSON is v in DynamoDB's JSON.
func attrJSON(v types.AttributeValue) any {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return map[string]any{"B": v.Value}
	case *types.AttributeValueMemberN:
		return map[string]any{"N": v.Value}
	case *types.AttributeValueMemberS:
		return map[string]any{"S": v.Value}
	case *types.AttributeValueMemberBOOL:
		return map[string]any{"BOOL": v.Value}
	case *types.AttributeValueMemberL:
		l := []any{}
		for _, e := range v.Value {
			l = append(l, attrJSON(e))
		}
		return map[string]any{"L": l}
	case *types.AttributeValueMemberM:
		return map[string]any{"M": itemJSON(v.Value)}
	}
	panic(fmt.Sprintf("attrJSON: %T", v))
}

func itemJSON(it map[string]types.AttributeValue) map[string]any {
	m := map[string]any{}
	for k, v := range it {
		m[k] = attrJSON(v)
	}
	return m
}

func (c *cannedTables) Do(r *http.Request) (*http.Response, error) {
	var q struct{ TableName, IndexName string }
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &q)
	status, out := http.StatusOK, any(nil)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "DynamoDB_20120810."); {
	case op == "Query" && q.TableName == "b":
		var items []any
		for _, it := range c.address {
			items = append(items, itemJSON(it))
		}
		out = map[string]any{"Count": len(items), "ScannedCount": len(items), "Items": items}
	case op == "Query":
		out = map[string]any{"Count": 0, "ScannedCount": 0, "Items": []any{}}
	case op == "GetItem" && q.TableName == "a":
		out = map[string]any{"Item": itemJSON(c.account)}
	case op == "PutItem":
		status = http.StatusBadRequest
		out = map[string]any{"__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException", "message": "The conditional request failed"}
	default:
		return nil, fmt.Errorf("cannedTables: no answer for %s of %s", op, q.TableName)
	}
	b, _ := json.Marshal(out)
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/x-amz-json-1.0"}, "X-Amzn-Requestid": {"t"}},
		Body:   io.NopCloser(bytes.NewReader(b)), Request: r}, nil
}

func (c *cannedTables) store() *Memory {
	return NewDynamoStore(DynamoConfig{AWS: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "x", ""),
		HTTPClient: c, BaseEndpoint: aws.String("http://127.0.0.1:1")}, BoxesTable: "b", MsgsTable: "m", AccountsTable: "a", Bucket: "s", BoxCache: 10})
}

// A write this process applies while a read is in flight keeps that read's
// copy out of memory, a read of the address (Box), a box's load and an
// account's read alike: each takes its token before it reads. Control: a
// read with no write during it is kept. In process over canned tables;
// TestAnImageDuringAReadKeepsItsFillOut and
// TestAnAccountChangeDuringItsReadKeepsTheFillOut hold the same on AWS.
func TestAWriteDuringAReadKeepsItsFillOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := t.Context()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	newer := item(boxItem(rec))
	newer["rev"] = num(rec.Rev + 1)
	acc := &Account{ID: "an account", Rev: 1}
	s := (&cannedTables{address: []map[string]types.AttributeValue{boxItem(rec)}, account: accountItem(acc)}).store()
	f := injectFaults(s)
	for _, c := range []struct {
		name, read string // the read of the backend, at whose answer the write lands
		call       func() error
		write      func()
		kept       func() bool
	}{
		{"a read of the address", "ReadAddress", func() error { _, err := s.Box(ctx, a); return err },
			func() { s.applyBoxImage(newer) }, func() bool { _, ok := s.cache.get(a); return ok }},
		{"the box's load", "ReadAddress", func() error { s.idx.forget(a); _, err := s.Count(ctx, a); return err },
			func() { s.applyBoxImage(newer) }, func() bool { _, ok := s.cache.get(a); return ok }},
		{"an account's read", "Account", func() error { _, err := s.Account(ctx, acc.ID); return err },
			func() { s.applyAccountRecord(accountChange(stypes.OperationTypeModify, acc.ID, 2)) }, func() bool { _, ok := s.accCache.get(acc.ID); return ok }},
	} {
		for _, during := range []bool{true, false} {
			s.cache.evict(a)
			s.accCache.evict(acc.ID)
			f.read = func(method string) {
				if during && method == c.read {
					c.write()
				}
			}
			err := c.call()
			f.read = nil
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			switch kept := c.kept(); {
			case during && kept:
				t.Errorf("%s: memory keeps a copy from before a write applied during the read", c.name)
			case !during && !kept:
				t.Errorf("%s, control: a read with no write during it is not kept", c.name)
			}
		}
	}
}

// A registration that finds the address's record written by another, its
// PutItem's condition failed, counts that write: the miss its read
// remembered ends, so the next call reads the record, and a read begun
// before it puts nothing. In process over canned tables.
func TestARegistrationThatFindsARecordCountsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	s := (&cannedTables{}).store()
	tok := s.cache.begin(a)
	s.cache.missed(a, tok, s.now()) // the registration's read found nothing
	if _, ok := s.Known(a); !ok {
		t.Fatal("control: the miss is not remembered")
	}
	if err := s.CreateBox(t.Context(), cloneBox(rec)); !errors.Is(err, ErrExists) {
		t.Fatalf("a registration whose condition failed: %v", err)
	}
	if b, ok := s.Known(a); ok {
		t.Errorf("after a registration found the address's record, memory answers %v for it with no read", b)
	}
	s.cache.fill(rec, tok)
	if _, ok := s.cache.get(a); ok {
		t.Error("a read begun before the record was found is kept")
	}
}

// The stream's image of a box's record, and its record of a change to an
// account or of an account's removal, are counted when they are applied, so
// a fill whose read began before one keeps its copy out
// (dromas-dev/dromas-server#97): memory alone, nothing read.
func TestTheStreamsChangesAreCounted(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	s := NewDynamoStore(DynamoConfig{BoxCache: 10})

	tok := s.cache.begin(a)
	next := cloneBox(rec)
	next.Rev++
	s.applyBoxImage(item(boxItem(next)))
	s.cache.fill(rec, tok)
	if _, ok := s.cache.get(a); ok {
		t.Error("a read begun before a record's image is kept: the image is not counted")
	}

	const id = "an account"
	for _, c := range []struct {
		name string
		rec  stypes.Record
	}{
		{"a change", accountChange(stypes.OperationTypeModify, id, 2)},
		{"a removal", accountChange(stypes.OperationTypeRemove, id, 2)},
	} {
		s.accCache.evict(id)
		tok := s.accCache.begin(id)
		s.applyAccountRecord(c.rec)
		s.accCache.fill(&Account{ID: id, Rev: 1}, tok)
		if _, ok := s.accCache.get(id); ok {
			t.Errorf("an account read begun before %s is kept: the stream's record is not counted", c.name)
		}
	}
}

// On DynamoDB: an image the stream brings while a read of the address is in
// flight is not lost to that read's fill, neither a read of what is held of
// the address (Box) nor a box's load (dromas-dev/dromas-server#12): the
// image of a newer record, or of a revocation of the address's certificates,
// each through applyBoxImage, which counts it (#97).
func TestAnImageDuringAReadKeepsItsFillOut(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	f := injectFaults(s)
	ctx := context.Background()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := s.Box(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	newer := item(boxItem(rec))
	newer["rev"] = num(rec.Rev + 1)
	certs := r.certs(1)
	revoked := item(revocationsKey(a))
	revoked["identity"], revoked["through"] = bin(r.id.Document()), num(1)
	revoked["revoked_certs"], revoked["revoked_certs_sig"] = bin(certs.RevokedCertificates), bin(certs.RevokedCertificatesSignature)
	for _, im := range []struct {
		name   string
		it     item
		before func(b *Box) bool // the copy is from before the image
	}{
		{"a newer record", newer, func(b *Box) bool { return b.Rev <= rec.Rev }},
		{"a revocation of its certificates", revoked, func(b *Box) bool { return len(b.RevokedCerts) == 0 }},
	} {
		for _, c := range []struct {
			name string
			read func() error
		}{
			{"a read of the address", func() error { _, err := s.Box(ctx, a); return err }},
			{"the box's load", func() error { s.idx.forget(a); _, err := s.Count(ctx, a); return err }},
		} {
			s.cache.evict(a)
			f.read = func(method string) {
				if method == "ReadAddress" {
					s.applyBoxImage(im.it)
				}
			}
			err := c.read()
			f.read = nil
			if err != nil {
				t.Fatal(err)
			}
			if b, ok := s.cache.get(a); ok && im.before(b) {
				t.Errorf("%s, the image of %s: the cache keeps a copy from before an image applied during the read", c.name, im.name)
			}
		}
	}
	// A read with no write during it is kept. The stream's echo of the
	// box's own registration, or of another test's write to its shard, can
	// land during one and rightly keep it out, so a few are allowed.
	kept := false
	for range 20 {
		s.cache.evict(a)
		if _, err := s.Box(ctx, a); err != nil {
			t.Fatal(err)
		}
		if _, kept = s.cache.get(a); kept {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !kept {
		t.Error("no read of the address in two seconds is kept")
	}
}

// On DynamoDB: an account's read during which this process saw a change to
// an account, through applyAccountRecord, which counts it (#97), keeps its
// copy out of the account cache, as a box's does.
func TestAnAccountChangeDuringItsReadKeepsTheFillOut(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	ctx := context.Background()
	acc, _ := accountEnv(t, e, false, 1)
	s.accCache.evict(acc.ID)
	f := injectFaults(s)
	f.read = func(method string) {
		if method == "Account" {
			s.applyAccountRecord(accountChange(stypes.OperationTypeModify, acc.ID, acc.Rev+1)) // the stream brought a change meanwhile
		}
	}
	_, err := s.Account(ctx, acc.ID)
	f.read = nil
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.accCache.get(acc.ID); ok {
		t.Error("the account cache keeps a copy read before a change seen during the read")
	}
	// One with no change during it is kept. The stream brings every
	// account's changes, other tests' among them, and one landing during a
	// read rightly keeps it out, so a few are allowed.
	kept := false
	for range 20 {
		s.accCache.evict(acc.ID)
		if _, err := s.Account(ctx, acc.ID); err != nil {
			t.Fatal(err)
		}
		if _, kept = s.accCache.get(acc.ID); kept {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !kept {
		t.Error("no read of the account in two seconds is kept")
	}
}

// orders calls f with every interleaving of a steps of one actor and b of
// another, as a list of 0s and 1s.
func orders(a, b int, f func(order []int)) {
	var rec func(order []int, i, j int)
	rec = func(order []int, i, j int) {
		if i == a && j == b {
			f(append([]int(nil), order...))
			return
		}
		if i < a {
			rec(append(order, 0), i+1, j)
		}
		if j < b {
			rec(append(order, 1), i, j+1)
		}
	}
	rec(nil, 0, 0)
}

// accountChange is the accounts stream's record of a change to account id's
// record at rev, or of its removal.
func accountChange(op stypes.OperationType, id string, rev uint64) stypes.Record {
	it := map[string]stypes.AttributeValue{
		"account": &stypes.AttributeValueMemberB{Value: []byte(id)}, "sk": &stypes.AttributeValueMemberB{Value: []byte{skAccount}},
		"unmetered": &stypes.AttributeValueMemberBOOL{Value: true}, "rev": &stypes.AttributeValueMemberN{Value: strconv.FormatUint(rev, 10)},
	}
	return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: it, NewImage: it}}
}

// What memory answers of an address with no read never goes back to before
// a write this process has applied, in any order of a fill and the write
// (dromas-dev/dromas-server#12, #41, #95, #96), nor what it holds of an
// account. Each actor is the code's own calls, a step for each stretch that
// another can come between, and each order of the two actors' steps runs on
// a store of its own, never started: memory alone. Each touches the cache in
// one step under its lock, so a write is its function, and a read is its
// fill, at the token it took before it read. Once the write is applied,
// after every step and at the end, memory answers the write or nothing: an
// answer without it at the end is a copy kept, and one after a step is a
// copy shown, which every reader of the cache is given.
func TestEveryOrderOfAFillAndAWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	older, err := e.store.Box(t.Context(), a) // the record a read began before the write finds
	if err != nil {
		t.Fatal(err)
	}
	if older.Rev != 1 {
		t.Fatalf("control: the record is at rev %d", older.Rev)
	}
	newer := cloneBox(older) // the record the write makes
	newer.Rev = 2
	revocation := &Revocations{Identity: older.Identity, Address: []byte("the identity's revocation")}
	const id = "an account"

	// A read of the address begun before the write, whose copy is v, fills
	// the cache once it has read (Memory.Box, readBox).
	read := func(s *Memory, v *Box) []func() {
		tok := s.cache.begin(a)
		return []func(){func() { s.cache.fill(v, tok) }}
	}
	// applyBox, this process's write of a record whose view, b, it read
	// before the write.
	applyBox := func(s *Memory, b *Box) []func() { return []func(){func() { s.applyBox(b) }} }
	revoke := func(s *Memory) func() { return func() { s.applyRevocations(a, revocation) } }
	accountRead := func(s *Memory) []func() {
		tok := s.accCache.begin(id)
		return []func(){func() { s.accCache.fill(&Account{ID: id, Rev: 1}, tok) }}
	}
	// What memory answers of the address with no read, as a lookup and a
	// send's check of its recipient ask it.
	known := func(s *Memory) (*Box, bool) { return s.Known(a) }
	withoutTheRevocation := func(s *Memory) bool { b, ok := known(s); return ok && (b == nil || b.State != Revoked) }
	withoutTheRecord := func(s *Memory) bool { b, ok := known(s); return ok && (b == nil || b.Rev < 2) }

	type actors struct {
		fill, write []func()
		applied     int // the write is applied once this many of its steps have run
	}
	for _, c := range []struct {
		name  string
		mk    func(s *Memory) actors
		stale func(s *Memory) bool // memory answers without the write
	}{
		{"a read's fill and applyBox of this process's write", func(s *Memory) actors {
			w := applyBox(s, newer)
			return actors{read(s, older), w, len(w)}
		}, withoutTheRecord},
		{"a read's fill and a revocation of the address", func(s *Memory) actors {
			return actors{read(s, older), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"a read's fill and a revocation with its purge", func(s *Memory) actors {
			return actors{read(s, older), []func(){revoke(s), func() { s.forget(a) }}, 1}
		}, withoutTheRevocation},
		{"a read's fill and the record's removal", func(s *Memory) actors {
			return actors{read(s, older), []func(){func() { s.forget(a) }}, 1}
		}, func(s *Memory) bool { b, ok := known(s); return ok && b != nil && b.hasRecord() }},
		{"a read's fill and the stream's image of a newer record", func(s *Memory) actors {
			return actors{read(s, older), []func(){func() { s.applyBoxImage(item(boxItem(newer))) }}, 1}
		}, withoutTheRecord},
		{"a read that found nothing and a revocation of the address", func(s *Memory) actors {
			tok := s.cache.begin(a)
			return actors{[]func(){func() { s.cache.missed(a, tok, s.now()) }}, []func(){revoke(s)}, 1}
		}, func(s *Memory) bool { b, ok := known(s); return ok && b == nil }},
		{"a registration's applyBox and a revocation of the address", func(s *Memory) actors {
			s.cache.missed(a, s.cache.begin(a), s.now()) // the registration's read finds nothing
			return actors{applyBox(s, older), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"applyBox of a write whose view predates a revocation the cache did not hold", func(s *Memory) actors {
			return actors{applyBox(s, newer), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"an account's read and the stream's change to it", func(s *Memory) actors {
			return actors{accountRead(s), []func(){func() { s.applyAccountRecord(accountChange(stypes.OperationTypeModify, id, 2)) }}, 1}
		}, func(s *Memory) bool { got, ok := s.accCache.get(id); return ok && got.Rev < 2 }},
		{"an account's read and its removal", func(s *Memory) actors {
			return actors{accountRead(s), []func(){func() { s.applyAccountRecord(accountChange(stypes.OperationTypeRemove, id, 1)) }}, 1}
		}, func(s *Memory) bool { _, ok := s.accCache.get(id); return ok }},
	} {
		t.Run(c.name, func(t *testing.T) {
			first := c.mk(NewDynamoStore(DynamoConfig{BoxCache: 10}))
			n, kept, shown := 0, 0, 0
			orders(len(first.fill), len(first.write), func(order []int) {
				n++
				s := NewDynamoStore(DynamoConfig{BoxCache: 10})
				x := c.mk(s)
				i, j, window := 0, 0, false
				for _, who := range order {
					if who == 0 {
						x.fill[i]()
						i++
					} else {
						x.write[j]()
						j++
					}
					if j >= x.applied && c.stale(s) {
						window = true
					}
				}
				switch {
				case c.stale(s):
					kept++
					t.Logf("order %v (0 the fill's steps, 1 the write's) keeps a copy without the write", order)
				case window:
					shown++
					t.Logf("order %v (0 the fill's steps, 1 the write's) shows a copy without the write once it is applied", order)
				}
			})
			t.Logf("%d orders: %d keep a copy without the write, %d more show one for a while", n, kept, shown)
			if kept+shown > 0 {
				t.Errorf("memory answers without a write this process applied: kept in %d of %d orders, shown in %d", kept, n, shown)
			}
		})
	}
}

// heldRead is a store's memory over a table of one address, held in the
// test: each read of the address answers what the table holds as the read
// begins, as a strongly consistent read does, and the first read is held
// until released.
type heldRead struct {
	*Memory
	mu      sync.Mutex
	table   *Box
	reads   int
	release chan struct{}
}

func (s *heldRead) set(b *Box) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table = b
}

func (s *heldRead) Box(context.Context, protocol.Address) (*Box, error) {
	s.mu.Lock()
	b := s.table
	s.reads++
	first := s.reads == 1
	s.mu.Unlock()
	if first {
		<-s.release
	}
	if b == nil {
		return nil, ErrNotFound
	}
	return cloneBox(b), nil
}

// A lookup that comes once this process has applied a revocation of the
// address and purged its record, and finds a read of the address in flight
// that began before them, is not answered from that read: it reads again
// (the fifth case of dromas-dev/dromas-server#95's class). Control: one
// that comes before them shares the read, which costs one read, and is
// answered what it found. The lookups run in a synctest bubble, so the test
// knows each is waiting on the shared read before it lets the read go.
func TestALookupJoinedToAReadBegunBeforeARevocationReadsAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	revocation := &Revocations{Identity: rec.Identity, Address: []byte("the identity's revocation")}
	for _, c := range []struct {
		name         string
		revokedFirst bool
		state        State
		reads        int
	}{
		{"a lookup after the revocation and its purge", true, Revoked, 2},
		{"control: a lookup before them", false, Active, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &heldRead{Memory: NewDynamoStore(DynamoConfig{BoxCache: 10}), table: rec, release: make(chan struct{})}
				srv := New(Config{Store: s, Limits: relaxed()})
				lookup := func() chan *Box {
					got := make(chan *Box, 1)
					go func() {
						b, err := srv.lookup(httptest.NewRequest(http.MethodGet, r.path(""), nil), a)
						if err != nil {
							t.Error(err)
						}
						got <- b
					}()
					return got
				}
				first := lookup()
				synctest.Wait() // its read has begun, and is held
				revoke := func() {
					s.set(view(a, nil, revocation))   // the table: the revocation kept, the record deleted
					s.applyRevocations(a, revocation) // as Revoke applies it
					s.forget(a)                       // as the purge's DeleteBox does
				}
				if c.revokedFirst {
					revoke()
				}
				second := lookup()
				synctest.Wait() // it waits on the read in flight
				if !c.revokedFirst {
					revoke()
				}
				close(s.release)
				if b := <-first; b == nil || b.State != Active {
					t.Errorf("the lookup whose read began before the revocation: %v", b)
				}
				b := <-second
				switch {
				case b == nil:
					t.Errorf("the second lookup found nothing; want the box %s", c.state)
				case b.State != c.state:
					t.Errorf("the second lookup was answered the box %s; want %s", b.State, c.state)
				}
				if s.reads != c.reads {
					t.Errorf("%d reads of the address; want %d", s.reads, c.reads)
				}
			})
		})
	}
}

// A box registered again once the TTL took its record starts at rev 1 again,
// and its record is newer than the removed one whatever their revs: a
// record's place in its address's history is when its box registered, then
// its rev. So a read of the address begun before the removal, whose copy of
// the removed record (rev 5) lands once the new registration is held, puts
// nothing of it over the new one, and the new record's next image (rev 2) is
// taken; and an index that held the removed box takes the registration's
// standing (dromas-dev/dromas-client#407 item 2). Memory alone.
func TestARegistrationAfterTheTTLsRemovalIsNewerThanTheRemovedRecord(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	old := cloneBox(rec) // the record the TTL takes: registered 40 days before, renewed since
	old.Rev, old.CertSerial, old.Created = 5, 3, rec.Created.Add(-40*24*time.Hour)
	fresh := cloneBox(rec) // the identity's registration once the TTL took it
	fresh.Rev, fresh.CertSerial = 1, 4
	next := cloneBox(fresh) // the new box renews, and the stream brings it
	next.Rev, next.CertSerial = 2, 5

	t.Run("a read begun before the removal", func(t *testing.T) {
		s := NewDynamoStore(DynamoConfig{BoxCache: 10})
		tok := s.cache.begin(a)                      // a read of the address begins, and will find old
		s.forget(a)                                  // the stream's removal of old, by the TTL
		s.cache.missed(a, s.cache.begin(a), s.now()) // the registration's read finds nothing
		s.applyBox(fresh)                            // its CreateBox, at rev 1
		if b, ok := s.Known(a); !ok || b == nil || b.CertSerial != fresh.CertSerial {
			t.Fatalf("control: memory holds %s, not the new registration", standsAt(b))
		}
		s.cache.fill(old, tok) // the first read's fill lands
		if b, ok := s.Known(a); !ok || b == nil || b.CertSerial != fresh.CertSerial {
			t.Errorf("memory answers %s in place of the new registration (rev 1, certificate serial %d): the removed record is rev 5, serial %d", standsAt(b), fresh.CertSerial, old.CertSerial)
		}
		s.applyBoxImage(item(boxItem(next)))
		if b, ok := s.Known(a); !ok || b == nil || b.CertSerial != next.CertSerial {
			t.Errorf("after the new box's image at rev 2 memory answers %s; want certificate serial %d", standsAt(b), next.CertSerial)
		}
	})
	t.Run("an index that held the removed box", func(t *testing.T) {
		s := NewDynamoStore(DynamoConfig{BoxCache: 10})
		st, _, err := old.standing()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.idx.ensure(t.Context(), a, func() (boxRead, error) {
			return boxRead{exists: true, st: st, created: ms(old.Created), rev: old.Rev}, nil
		}); err != nil {
			t.Fatal(err)
		}
		s.applyBox(fresh) // the registration, before the stream's removal of old arrives
		if st, ok := s.Held(a); !ok || st.CertSerial != fresh.CertSerial {
			t.Errorf("the index holds the box at certificate serial %d (%v) after its registration at serial %d: the removed record's standing", st.CertSerial, ok, fresh.CertSerial)
		}
	})
}

// standsAt is a record's rev and certificate serial, or that there is none.
func standsAt(b *Box) string {
	if b == nil {
		return "no record"
	}
	return fmt.Sprintf("rev %d, certificate serial %d", b.Rev, b.CertSerial)
}

// A fill's check of its token and its put are one step under the cache's
// lock, and so are a miss's check and its record: no write can be counted
// between them, which would leave a copy from before it kept
// (dromas-dev/dromas-server#95). The hook between the check and the put
// sees the lock held, by the same taking of it as the check
// (dromas-dev/dromas-client#407 item 3).
func TestAFillAndAMissAreEachOneStepUnderTheLock(t *testing.T) {
	t.Parallel()
	var a, other protocol.Address
	a[0], other[0] = 7, 8
	c := newBoxCache(10)
	steps := 0
	c.between = func(checked uint64) {
		steps++
		if c.mu.TryLock() {
			c.mu.Unlock()
			t.Error("between a check and its put the cache's lock is not held")
		} else if c.mu.n != checked {
			t.Errorf("between a check and its put the cache's lock was let go and taken again (%d takings since the check)", c.mu.n-checked)
		}
	}
	c.fill(&Box{Addr: a, Rev: 1}, c.begin(a))
	c.missed(other, c.begin(other), time.Now())
	if steps != 2 {
		t.Fatalf("control: the hook ran %d times for a fill and a miss whose tokens stand, want 2", steps)
	}
	if _, ok := c.get(a); !ok || !c.missingAt(other, time.Now()) {
		t.Fatal("control: the fill or the miss was not kept")
	}
}
