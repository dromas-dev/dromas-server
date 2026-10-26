package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// An adopt key names its account, and is known by its SHA-256.
func TestAdoptKeys(t *testing.T) {
	t.Parallel()
	key, hash, err := NewAdoptKey("echo")
	if err != nil {
		t.Fatal(err)
	}
	if acc, got, ok := parseAdopt(key); !ok || acc != "echo" || got != hash || got != sha256.Sum256([]byte(key)) {
		t.Fatalf("parse: %q %x %v", acc, got, ok)
	}
	if again, _, _ := NewAdoptKey("echo"); again == key {
		t.Fatal("two keys alike")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, adoptPrefix))
	if !bytes.HasPrefix(raw, []byte("echo")) || len(raw) != len("echo")+adoptSecretLen {
		t.Fatalf("a key of %d bytes: %q", len(raw), raw)
	}
	enc := func(b []byte) string { return adoptPrefix + base64.RawURLEncoding.EncodeToString(b) }
	secret := raw[len("echo"):]
	for name, bad := range map[string]string{
		"no prefix":           strings.TrimPrefix(key, adoptPrefix),
		"not base64":          adoptPrefix + "!!",
		"padded":              key + "=",
		"an empty one":        "",
		"too short":           adoptPrefix + "AAAA",
		"no account":          enc(secret),
		"a bad account id":    enc(append([]byte("Echo"), secret...)),
		"an account too long": enc(append([]byte(strings.Repeat("a", 33)), secret...)),
	} {
		if _, _, ok := parseAdopt(bad); ok {
			t.Errorf("%s: parsed", name)
		}
	}
	for _, a := range []string{"", "Echo", strings.Repeat("a", 33)} {
		if _, _, err := NewAdoptKey(a); err == nil {
			t.Errorf("a key into %q", a)
		}
	}
}

// The accounts table keeps an adopt key's SHA-256 and never the key, so a
// copy of the table holds no key.
func TestAnAdoptKeyIsKeptAsItsHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 1)
	hash := sha256.Sum256([]byte(key))
	if k, err := e.store.AdoptKey(ctx, acc.ID, hash); err != nil || k.Uses != 1 || k.Hash != hash || k.Account != acc.ID {
		t.Fatalf("the key, by its hash: %+v %v", k, err)
	}
	if _, err := e.store.AdoptKey(ctx, acc.ID, sha256.Sum256([]byte(key+"A"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another key: %v", err)
	}
	s, ok := onDynamo(e.store)
	if !ok {
		return
	}
	out, err := s.dynamo().db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.dynamo().accts, Key: adoptKeyKey(acc.ID, hash), ConsistentRead: aws.Bool(true)})
	if err != nil || out.Item == nil {
		t.Fatalf("the key's item: %v", err)
	}
	if sk := out.Item["sk"].(*types.AttributeValueMemberB).Value; !bytes.Equal(sk, append([]byte{skAdoptKey}, hash[:]...)) {
		t.Fatalf("the key's item is at %x", sk)
	}
	names := slices.Sorted(maps.Keys(out.Item))
	if !slices.Equal(names, []string{"account", "expires", "expires_at", "sk", "uses"}) {
		t.Fatalf("the key's item holds %v", names)
	}
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

func (e *env) accountOf(b *client.Box) string {
	e.t.Helper()
	r, err := e.store.Box(context.Background(), b.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Account
}

func adopt(t *testing.T, b *client.Box, key string) string {
	t.Helper()
	acc, err := b.Adopt(context.Background(), key)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	return acc
}

func TestAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.MaxSize, l.AccountMaxSize = 2, 4096, 16384 // the smallest message is 2,048 bytes

	t.Run("an unmetered account lifts the daily limit and the cap", func(t *testing.T) {
		e := newEnv(t, l)
		acc, key := accountEnv(t, e, true, 1)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		if got := adopt(t, a, key); got != acc.ID || e.accountOf(a) != acc.ID {
			t.Fatalf("adopted into %q, the record says %q", got, e.accountOf(a))
		}
		for i := range 3 {
			send(t, a, b, strings.Repeat("x", 100*i))
		}
		send(t, a, b, strings.Repeat("x", 5000)) // over 4096
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 20000)); codeOf(err) != protocol.CodeTooLarge || !strings.Contains(err.Error(), "16384") {
			t.Fatalf("over the largest cap: %v", err)
		}
		// A box in no account has the server's limits.
		send(t, c, b, "1")
		if _, err := c.Send(ctx, b.Address(), strings.Repeat("x", 5000)); codeOf(err) != protocol.CodeTooLarge || !strings.Contains(err.Error(), "4096") {
			t.Fatalf("over the cap: %v", err)
		}
		send(t, c, b, "2")
		if _, err := c.Send(ctx, b.Address(), "3"); !limitedBy(err, protocol.QuotaSends) {
			t.Fatalf("third send: %v", err)
		}
		// The key's one use is spent.
		if _, err := c.Adopt(ctx, key); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a spent key: %v", err)
		}
		// Leaving gives a back the server's limits; sends in the account
		// counted for nothing.
		if err := a.Leave(ctx); err != nil || e.accountOf(a) != "" {
			t.Fatalf("leave: %v, account %q", err, e.accountOf(a))
		}
		if err := a.Leave(ctx); err != nil {
			t.Fatalf("leave again: %v", err)
		}
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 5000)); codeOf(err) != protocol.CodeTooLarge || !strings.Contains(err.Error(), "4096") {
			t.Fatalf("after leaving, over the cap: %v", err)
		}
		send(t, a, b, "4")
		send(t, a, b, "5")
		if _, err := a.Send(ctx, b.Address(), "6"); !limitedBy(err, protocol.QuotaSends) {
			t.Fatalf("after leaving, a third send: %v", err)
		}
	})

	t.Run("a metered account has the free limits until credit exists", func(t *testing.T) {
		e := newEnv(t, l)
		_, key := accountEnv(t, e, false, 1)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		adopt(t, a, key)
		send(t, a, b, "1")
		send(t, a, b, "2")
		if _, err := a.Send(ctx, b.Address(), "3"); !limitedBy(err, protocol.QuotaSends) {
			t.Fatalf("third send: %v", err)
		}
	})

	t.Run("keys that are refused", func(t *testing.T) {
		e := newEnv(t, l)
		acc, key := accountEnv(t, e, true, 2)
		other, _ := accountEnv(t, e, true, 1)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		unstored, _, _ := NewAdoptKey(acc.ID)
		raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, adoptPrefix))
		moved := adoptPrefix + base64.RawURLEncoding.EncodeToString(append([]byte(other.ID), raw[len(acc.ID):]...)) // its secret, naming another account
		expiring := e.adoptKey(t, acc.ID, 1, time.Minute)
		e.clock.Add(2 * time.Minute)
		for name, k := range map[string]string{
			"never stored":            unstored,
			"naming another account":  moved,
			"expired":                 expiring,
			"not a key":               "dra1_x",
			"a key's hash, not a key": adoptPrefix + base64.RawURLEncoding.EncodeToString(append([]byte(acc.ID), func() []byte { h := sha256.Sum256([]byte(key)); return h[:] }()...)),
		} {
			if _, err := a.Adopt(ctx, k); codeOf(err) != protocol.CodeAdoptKeyRefused {
				t.Errorf("%s: %v", name, err)
			}
		}
		if e.accountOf(a) != "" {
			t.Fatal("a refused key adopted the box")
		}
		// Adopting into the account the box is already in spends no use,
		// and a key that was never stored is refused there too.
		adopt(t, a, key)
		adopt(t, a, key)
		if _, err := a.Adopt(ctx, unstored); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a key never stored, naming the box's own account: %v", err)
		}
		adopt(t, b, key)
		if _, err := e.box(protocol.Classic).Adopt(ctx, key); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a third box on a two-use key: %v", err)
		}
		// The key is spent, and a box already in its account is still
		// answered 200: a retry whose answer was lost.
		if got := adopt(t, a, key); got != acc.ID {
			t.Fatalf("a retry adopted into %q", got)
		}
	})

	t.Run("moving to another account", func(t *testing.T) {
		e := newEnv(t, l)
		first, key1 := accountEnv(t, e, false, 1)
		second, key2 := accountEnv(t, e, true, 1)
		a := e.box(protocol.Classic)
		adopt(t, a, key1)
		if got := adopt(t, a, key2); got != second.ID || e.accountOf(a) != second.ID {
			t.Fatalf("moved to %q", e.accountOf(a))
		}
		if s, ok := onDynamo(e.store); ok { // the index of each account's boxes follows the box record
			s.lists(t, first.ID, a.Address(), false)
			s.lists(t, second.ID, a.Address(), true)
			if err := a.Leave(ctx); err != nil {
				t.Fatal(err)
			}
			s.lists(t, second.ID, a.Address(), false)
		}
	})

	t.Run("calls that are refused", func(t *testing.T) {
		e := newEnv(t, l)
		r := e.raw().register(30 * 24 * time.Hour)
		pass := r.pass(1)
		e.want(e.do(http.MethodPut, r.path("/account"), protocol.AdoptRequest{Key: "x"}, ""), 401, protocol.CodeUnauthorized)
		e.want(e.do(http.MethodPut, r.path("/account"), []byte(`{"key":1}`), pass), 400, protocol.CodeBadRequest)
		// No key, a null one (PROTOCOL.md §3.3) or an empty one is a member
		// missing from the request, not a key refused.
		for _, body := range []string{`{}`, `{"key":null}`, `{"key":""}`} {
			got := e.do(http.MethodPut, r.path("/account"), []byte(body), pass)
			e.want(got, 400, protocol.CodeBadRequest)
			if got.problem().Member != "key" {
				t.Errorf("%s: the refusal names %q, want the member key: %s", body, got.problem().Member, got.body)
			}
		}
		e.want(e.do(http.MethodDelete, r.path("/account"), nil, ""), 401, protocol.CodeUnauthorized)
		e.want(e.do(http.MethodDelete, r.path("/account"), nil, pass), 204, "")
		// Over the sender's own cap, a send is refused before its body is
		// read: here, before the server finds it is no age file.
		e.want(e.do(http.MethodPost, r.path("/messages"), sealedTo(1, 1, make([]byte, 16384)), pass), 413, protocol.CodeTooLarge)
	})
}

// A box revoked while it is in an account leaves it: an account lists no
// boxes, a box's membership is its record's, and the revocation deletes the
// record (purge; dromas-dev/dromas-client#434 item 1). Then the account
// routes answer 410 revoked, with the box's pass or none.
func TestARevokedBoxLeavesItsAccount(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 2)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	if got := adopt(t, a, key); got != acc.ID || e.accountOf(a) != acc.ID {
		t.Fatalf("adopted into %q, the record says %q", got, e.accountOf(a))
	}
	send(t, b, a, "waiting in A's box when it is revoked")
	pass := e.pass(a)
	e.want(e.do("PUT", revocationPath(a.Address()), record(t, a), ""), http.StatusCreated, "")
	if got := e.accountOf(a); got != "" {
		t.Fatalf("a revoked box is still in the account %q", got)
	}
	account := boxPath(a.Address()) + "/account"
	for what, p := range map[string]string{"with its pass": pass, "with no pass": ""} {
		if got := e.do(http.MethodPut, account, protocol.AdoptRequest{Key: key}, p); got.status != http.StatusGone || got.code() != protocol.CodeRevoked {
			t.Errorf("PUT …/account of a revoked box, %s: %d %s, want 410 revoked", what, got.status, got.code())
		}
		if got := e.do(http.MethodDelete, account, nil, p); got.status != http.StatusGone || got.code() != protocol.CodeRevoked {
			t.Errorf("DELETE …/account of a revoked box, %s: %d %s, want 410 revoked", what, got.status, got.code())
		}
	}
}

// Adopt and Leave write only over the record they were given.
func TestAdoptAndLeaveNameTheRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 1)
	_, id, _ := parseAdopt(key)
	a := e.box(protocol.Classic)
	old, err := e.store.Box(ctx, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	cur := cloneBox(old)
	if err := e.store.UpdateBox(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Adopt(ctx, cloneBox(old), acc.ID, id); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt over an old record: %v", err)
	}
	if err := e.store.Adopt(ctx, cur, acc.ID, id); err != nil || cur.Account != acc.ID {
		t.Fatalf("adopt: %v", err)
	}
	stale := cloneBox(cur)
	stale.Rev--
	if err := e.store.Leave(ctx, stale); !errors.Is(err, ErrStale) {
		t.Fatalf("leave over an old record: %v", err)
	}
	if err := e.store.Leave(ctx, cur); err != nil || cur.Account != "" {
		t.Fatalf("leave: %v", err)
	}
}

// staleStore loses every race to adopt or leave.
type staleStore struct{ Store }

func (staleStore) Adopt(context.Context, *Box, string, [32]byte) error { return ErrStale }
func (staleStore) Leave(context.Context, *Box) error                   { return ErrStale }

// adoptCounting counts the store's adopts: each writes the box's record.
type adoptCounting struct {
	Store
	n atomic.Int32
}

func (s *adoptCounting) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	s.n.Add(1)
	return s.Store.Adopt(ctx, b, account, key)
}

// A key that is not this server's, or is spent or expired, is refused after
// a read of its item, and never reaches the write of the box's record.
func TestARefusedKeyWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	e := newEnv(t, l)
	acc, key := accountEnv(t, e, true, 1)
	cs := &adoptCounting{Store: e.store}
	h := New(Config{Store: cs, Limits: l, Now: e.clock.Now}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { h.ServeHTTP(w, r) })
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, a, key)
	unstored, _, _ := NewAdoptKey(acc.ID)
	expiring := e.adoptKey(t, acc.ID, 1, time.Minute)
	e.clock.Add(2 * time.Minute)
	for name, k := range map[string]string{"spent": key, "never stored": unstored, "expired": expiring} {
		if _, err := b.Adopt(ctx, k); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := cs.n.Load(); n != 1 {
		t.Fatalf("%d writes of a box's record, for one adopt", n)
	}
}

func TestAdoptRaceIsAConflict(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	acc, key := accountEnv(t, e, true, 2)
	a := e.box(protocol.Classic)
	adopt(t, a, e.adoptKey(t, acc.ID, 1, time.Hour))
	stale := New(Config{Store: staleStore{e.store}, Limits: l, Now: e.clock.Now}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { stale.ServeHTTP(w, r) })
	b := e.box(protocol.Classic)
	if _, err := b.Adopt(context.Background(), key); codeOf(err) != protocol.CodeBoxChanged {
		t.Fatalf("adopt: %v", err)
	}
	if err := a.Leave(context.Background()); codeOf(err) != protocol.CodeBoxChanged {
		t.Fatalf("leave: %v", err)
	}
}

// cannedDynamo answers DynamoDB's calls in turn from its answers, the last
// one again once they run out, and counts the calls.
type cannedDynamo struct {
	n       atomic.Int32
	answers []string // a 200's body, or a 400's: an error in the SDK's JSON shape, by its "__type"
}

func (d *cannedDynamo) Do(r *http.Request) (*http.Response, error) {
	i := int(d.n.Add(1)) - 1
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	body := d.answers[min(i, len(d.answers)-1)]
	status := http.StatusOK
	if strings.Contains(body, `"__type"`) {
		status = http.StatusBadRequest
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/x-amz-json-1.0"}, "X-Amzn-Requestid": {"t"}},
		Body:   io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (d *cannedDynamo) store(logged *bytes.Buffer) *Memory {
	return NewDynamoStore(DynamoConfig{AWS: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "x", ""),
		HTTPClient: d, BaseEndpoint: aws.String("http://127.0.0.1:1")}, BoxesTable: "b", MsgsTable: "m", AccountsTable: "a", Bucket: "s", Log: log.New(logged, "", 0)})
}

// cancelled is a TransactWriteItems cancelled for these reasons, one an item.
func cancelled(reasons ...string) string {
	var codes []string
	for _, r := range reasons {
		codes = append(codes, `{"Code":"`+r+`"}`)
	}
	return `{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","Message":"Transaction cancelled, please refer cancellation reasons for specific reasons [` + strings.Join(reasons, ", ") + `]","CancellationReasons":[` + strings.Join(codes, ",") + `]}`
}

// dynamoAdopt is the test store, but with the Adopt of a store on DynamoDB.
type dynamoAdopt struct {
	Store
	d *Memory
}

func (s dynamoAdopt) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	return s.d.Adopt(ctx, b, account, key)
}

// An adopt that meets another transaction on the box's record or the key's
// item, as two adopts with one multi-use key do, is cancelled for a
// TransactionConflict, which the SDK does not retry. It applied nothing, so
// the store sends it again, by a new call, up to four calls in all; one
// that meets another every time is ErrStale, and the adopt 409 box_changed.
// A failed condition still wins, whichever item conflicted.
func TestAnAdoptThatMeetsAnotherIsSentAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 5)
	_, hash, _ := parseAdopt(key)
	a := e.box(protocol.Classic)
	conflict := cancelled("None", "TransactionConflict")
	for _, c := range []struct {
		name    string
		answers []string
		calls   int32
		want    error
	}{
		{"none", []string{`{}`}, 1, nil},
		{"one conflict", []string{conflict, `{}`}, 2, nil},
		{"three conflicts", []string{conflict, conflict, cancelled("TransactionConflict", "None"), `{}`}, 4, nil},
		{"a conflict every time", []string{conflict}, 4, ErrStale}, // the SDK's own tries for DynamoDB
		{"a key that is spent", []string{cancelled("None", "ConditionalCheckFailed")}, 1, ErrKeyRefused},
		{"a key that is spent, beside a conflict", []string{cancelled("TransactionConflict", "ConditionalCheckFailed")}, 1, ErrKeyRefused},
		{"a box that moved on", []string{conflict, cancelled("ConditionalCheckFailed", "None")}, 2, ErrStale},
	} {
		b, err := e.store.Box(ctx, a.Address())
		if err != nil {
			t.Fatal(err)
		}
		var logged bytes.Buffer
		d := &cannedDynamo{answers: c.answers}
		if err := d.store(&logged).Adopt(ctx, b, acc.ID, hash); !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if n := d.n.Load(); n != c.calls {
			t.Errorf("%s: %d calls to DynamoDB, want %d", c.name, n, c.calls)
		}
	}

	// Through the handler: a conflict that lasts is 409 box_changed, which a
	// client sends again as it is, and nothing is logged as an internal error.
	var logged bytes.Buffer
	srv := New(Config{Store: dynamoAdopt{e.store, (&cannedDynamo{answers: []string{conflict}}).store(&logged)}, Limits: relaxed(), Now: e.clock.Now, Log: log.New(&logged, "", 0)}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { srv.ServeHTTP(w, r) })
	defer e.setMiddle(nil)
	if _, err := e.box(protocol.Classic).Adopt(ctx, key); codeOf(err) != protocol.CodeBoxChanged {
		t.Errorf("an adopt that met another every time: %v, want box_changed", err)
	}
	if strings.Contains(logged.String(), "internal error") {
		t.Errorf("an adopt that met another is logged as an internal error: %s", logged.String())
	}
}

// A write of the box's record alone that meets a transaction on it is
// refused with a TransactionConflictException, which the SDK does not retry:
// the record changes if that transaction commits, so it is ErrStale, as a
// failed condition is, and a client sends it again (409 box_changed).
func TestARecordWriteThatMeetsATransactionIsStale(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a := e.box(protocol.Classic)
	b, err := e.store.Box(ctx, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	conflict := `{"__type":"com.amazonaws.dynamodb.v20120810#TransactionConflictException","message":"Transaction is ongoing for the item"}`
	for name, write := range map[string]func(*Memory) error{
		"UpdateBox": func(s *Memory) error { return s.UpdateBox(ctx, cloneBox(b)) },
		"Leave":     func(s *Memory) error { return s.Leave(ctx, cloneBox(b)) },
	} {
		var logged bytes.Buffer
		d := &cannedDynamo{answers: []string{conflict}}
		if err := write(d.store(&logged)); !errors.Is(err, ErrStale) {
			t.Errorf("%s that met a transaction: %v, want ErrStale", name, err)
		}
		if n := d.n.Load(); n != 1 {
			t.Errorf("%s: %d calls to DynamoDB, want 1", name, n)
		}
	}
}

// A change to an account reaches memory by the accounts stream: an operator
// makes a metered account unmetered by hand, then deletes it, and its box
// has the free limits again.
func TestAccountChangesReachMemory(t *testing.T) {
	t.Parallel()
	if !onAWS() {
		t.Skip("needs the AWS tables")
	}
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	s := e.store.(*Memory)
	acc, key := accountEnv(t, e, false, 1)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, a, key)
	send(t, a, b, "1")
	if _, err := a.Send(ctx, b.Address(), "2"); !limitedBy(err, protocol.QuotaSends) {
		t.Fatalf("second send: %v", err)
	}
	if _, err := s.dynamo().db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.dynamo().accts, Key: accountKey(acc.ID, skAccount),
		UpdateExpression:          aws.String("SET #u = :t, #r = :r"),
		ExpressionAttributeNames:  map[string]string{"#u": "unmetered", "#r": "rev"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}, ":r": num(2)},
	}); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("unmetered %d", i))
		return err == nil
	})
	if _, err := s.dynamo().db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.dynamo().accts, Key: accountKey(acc.ID, skAccount)}); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("gone %d", i))
		return limitedBy(err, protocol.QuotaSends)
	})
}

// until retries ok every 100 ms, for up to 10 s: the stream's delay.
func until(t *testing.T, ok func(i int) bool) {
	t.Helper()
	for i := range 100 {
		if ok(i) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the stream never brought the change")
}

// A send past the free cap's size waits for the one allowance for large
// reads; a smaller one never does, and one over the sender's own cap is
// refused at once. Only a sender whose cap is above the free one ever waits
// for it: the pass comes before the body, so a body from anyone else is never
// read that far.
func TestLargeReadsTakeTurns(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10 // bodies read at once up to 16 KiB, at most 64 KiB
	e := newEnv(t, l)
	_, key := accountEnv(t, e, true, 1)
	lifted, free, to := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, lifted, key)
	post := func(pass string, size int, wait time.Duration) (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(1, 1, nil).Encode(), bytes.NewReader(make([]byte, size)))
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	e.server.largeRead <- struct{}{} // another large send is being read
	if _, err := post(e.pass(lifted), 30000, 300*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a large send did not wait its turn: %v", err)
	}
	if code, err := post(e.pass(lifted), 500, 5*time.Second); err != nil || code != http.StatusBadRequest { // read, then not_age
		t.Fatalf("a small send waited: %d %v", code, err)
	}
	if code, err := post(e.pass(lifted), 100000, 5*time.Second); err != nil || code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the largest cap: %d %v", code, err)
	}
	if code, err := post(e.pass(free), 30000, 5*time.Second); err != nil || code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over a free sender's cap, with the allowance taken: %d %v", code, err)
	}
	if code, err := post("", 30000, 5*time.Second); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("a large send with no pass, with the allowance taken: %d %v", code, err)
	}
	<-e.server.largeRead
	if code, err := post(e.pass(lifted), 30000, 5*time.Second); err != nil || code != http.StatusBadRequest {
		t.Fatalf("a large send with the allowance free: %d %v", code, err)
	}
	if len(e.server.largeRead) != 0 {
		t.Fatal("the allowance was not given back")
	}
}

// A large body that stops coming is cut off by its deadline, and gives the
// one large read back (dromas-dev/dromas-server#7): a large send after it
// is read at once, not after the stalled one's peer gives up. The metrics
// count the cut and both reads.
func TestAStalledBodyGivesTheLargeReadBack(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10 // bodies read at once up to 16 KiB, at most 64 KiB
	l.BodyTimeout, l.BodyMinRate = 300*time.Millisecond, 1<<20
	m := NewMetrics(prometheus.NewRegistry())
	e := newEnv(t, l, func(c *Config) { c.Metrics = m })
	_, key := accountEnv(t, e, true, 1)
	lifted, to := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, lifted, key)
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := sealedTo(1, 1, nil).Encode()
	_, _ = io.WriteString(conn, "POST /v1/"+to.Address().String()+"/messages?"+query+" HTTP/1.1\r\nHost: "+addr+"\r\nAuthorization: "+e.pass(lifted)+
		"\r\nContent-Type: application/octet-stream\r\nContent-Length: 60000\r\n\r\n"+strings.Repeat("a", 30000)) // past the free size, then nothing
	time.Sleep(50 * time.Millisecond) // the stalled send holds the large read
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+query, bytes.NewReader(make([]byte, 30000)))
	req.Header.Set("Authorization", e.pass(lifted))
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("a large send behind a stalled one: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || time.Since(start) > 2*time.Second { // read, then not_age
		t.Fatalf("a large send behind a stalled one: %d after %s, want 400 at once", resp.StatusCode, time.Since(start))
	}
	if cut, taken := testutil.ToFloat64(m.cut), testutil.ToFloat64(m.largeRead.WithLabelValues("taken")); cut != 1 || taken != 2 {
		t.Fatalf("the metrics: %v bodies cut, %v large reads taken, want 1 and 2", cut, taken)
	}
}

// A send waiting for the one large read gives up after the body timeout, with
// 503 and Retry-After, and does not wait on its own client. The metrics count
// the wait that timed out.
func TestAWaitForTheLargeReadIsBounded(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10
	l.BodyTimeout = 200 * time.Millisecond
	m := NewMetrics(prometheus.NewRegistry())
	e := newEnv(t, l, func(c *Config) { c.Metrics = m })
	_, key := accountEnv(t, e, true, 1)
	lifted, to := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, lifted, key)
	e.server.largeRead <- struct{}{} // another large send is being read
	defer func() { <-e.server.largeRead }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(1, 1, nil).Encode(), bytes.NewReader(make([]byte, 30000)))
	req.Header.Set("Authorization", e.pass(lifted))
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the wait for the large read did not end: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || time.Since(start) > 2*time.Second || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("the wait for the large read: %d after %s, Retry-After %q", resp.StatusCode, time.Since(start), resp.Header.Get("Retry-After"))
	}
	if got := testutil.ToFloat64(m.largeRead.WithLabelValues("timed_out")); got != 1 {
		t.Fatalf("the metrics count %v waits that timed out, want 1", got)
	}
}
