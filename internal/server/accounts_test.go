package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// The adopt_keys table keeps an adopt key's SHA-256 and never the key, so a
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
	s, ok := onPg(e.store)
	if !ok {
		return
	}
	rows, err := rowsOf(s.pool().Query(ctx, `SELECT * FROM adopt_keys WHERE account = $1`, acc.ID))
	if err != nil || len(rows) != 1 {
		t.Fatalf("the account's adopt keys: %d rows, %v; want the one", len(rows), err)
	}
	if h, err := rows[0].hash("hash"); err != nil || h != hash {
		t.Fatalf("the key's row is at %x (%v); want its SHA-256", h, err)
	}
	names := slices.Sorted(maps.Keys(rows[0]))
	if !slices.Equal(names, []string{"account", "expires_at", "hash", "uses"}) {
		t.Fatalf("the key's row holds %v", names)
	}
}

func (e *env) accountOf(b *client.Mailbox) string {
	e.t.Helper()
	r, err := e.store.Mailbox(context.Background(), b.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Account
}

func TestAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.MaxSize, l.AccountMaxSize, l.SendsBurst = 2, 4096, 16384, 2 // the smallest message is 2,048 bytes

	t.Run("an unmetered account lifts the daily limit and the cap", func(t *testing.T) {
		e := newEnv(t, l)
		acc, key := accountEnv(t, e, true, 1)
		a, b, c := e.mailbox(), e.mailbox(), e.mailbox()
		if got := adopt(t, a, key); got != acc.ID || e.accountOf(a) != acc.ID {
			t.Fatalf("adopted into %q, the record says %q", got, e.accountOf(a))
		}
		for i := range 3 {
			send(t, a, b, strings.Repeat("x", 100*i))
		}
		send(t, a, b, strings.Repeat("x", 5000)) // over 4096
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 20000)); !tooLarge(err, 16384) {
			t.Fatalf("over the largest cap: %v", err)
		}
		// A mailbox in no account has the server's limits.
		send(t, c, b, "1")
		if _, err := c.Send(ctx, b.Address(), strings.Repeat("x", 5000)); !tooLarge(err, 4096) {
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
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 5000)); !tooLarge(err, 4096) {
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
		a, b := e.mailbox(), e.mailbox()
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
		a, b := e.mailbox(), e.mailbox()
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
			t.Fatal("a refused key adopted the mailbox")
		}
		// A key naming the account the mailbox is already in spends no use, and
		// is answered 200 whatever state it is in or whether it is still held,
		// so a retry whose answer was lost is 200 once the key has expired and
		// its row has gone (PROTOCOL.md §11.16). One naming another account is
		// still judged.
		adopt(t, a, key)
		adopt(t, a, key)
		for name, k := range map[string]string{"never stored, as a key gone is": unstored, "expired": expiring} {
			if got, err := a.Adopt(ctx, k); err != nil || got != acc.ID {
				t.Fatalf("%s, naming the mailbox's own account: %q, %v", name, got, err)
			}
		}
		if _, err := a.Adopt(ctx, moved); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a key naming another account, from a mailbox in this one: %v", err)
		}
		adopt(t, b, key)
		if _, err := e.mailbox().Adopt(ctx, key); codeOf(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a third mailbox on a two-use key: %v", err)
		}
		// The key is spent, and a mailbox already in its account is still
		// answered 200: a retry whose answer was lost.
		if got := adopt(t, a, key); got != acc.ID {
			t.Fatalf("a retry adopted into %q", got)
		}
	})

	t.Run("moving to another account", func(t *testing.T) {
		e := newEnv(t, l)
		first, key1 := accountEnv(t, e, false, 1)
		second, key2 := accountEnv(t, e, true, 1)
		a := e.mailbox()
		adopt(t, a, key1)
		if got := adopt(t, a, key2); got != second.ID || e.accountOf(a) != second.ID {
			t.Fatalf("moved to %q", e.accountOf(a))
		}
		if s, ok := onPg(e.store); ok { // the account's mailboxes are the mailbox records that name it
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
		r := e.raw().register(protocol.PrekeyLifetime)
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
		e.want(e.do(http.MethodPost, r.path("/messages"), r.sealed(1, make([]byte, 16384)), pass), 413, protocol.CodeTooLarge)
	})
}

// A mailbox revoked while it is in an account leaves it: an account lists no
// mailboxes, a mailbox's membership is its record's, and the revocation deletes the
// record (purge; dromas-dev/dromas-client#434 item 1). Then the account
// routes answer 410 revoked, with the mailbox's pass or none.
func TestARevokedMailboxLeavesItsAccount(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 2)
	a, b := e.mailbox(), e.mailbox()
	if got := adopt(t, a, key); got != acc.ID || e.accountOf(a) != acc.ID {
		t.Fatalf("adopted into %q, the record says %q", got, e.accountOf(a))
	}
	send(t, b, a, "waiting in A's mailbox when it is revoked")
	pass := e.pass(a)
	e.want(e.do("PUT", revocationPath(a.Address()), record(t, a), ""), http.StatusCreated, "")
	if got := e.accountOf(a); got != "" {
		t.Fatalf("a revoked mailbox is still in the account %q", got)
	}
	account := mailboxPath(a.Address()) + "/account"
	for what, p := range map[string]string{"with its pass": pass, "with no pass": ""} {
		if got := e.do(http.MethodPut, account, protocol.AdoptRequest{Key: key}, p); got.status != http.StatusGone || got.code() != protocol.CodeRevoked {
			t.Errorf("PUT …/account of a revoked mailbox, %s: %d %s, want 410 revoked", what, got.status, got.code())
		}
		if got := e.do(http.MethodDelete, account, nil, p); got.status != http.StatusGone || got.code() != protocol.CodeRevoked {
			t.Errorf("DELETE …/account of a revoked mailbox, %s: %d %s, want 410 revoked", what, got.status, got.code())
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
	a := e.mailbox()
	old, err := e.store.Mailbox(ctx, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	cur := cloneMailbox(old)
	if err := e.store.UpdateMailbox(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Adopt(ctx, cloneMailbox(old), acc.ID, id); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt over an old record: %v", err)
	}
	if err := e.store.Adopt(ctx, cur, acc.ID, id); err != nil || cur.Account != acc.ID {
		t.Fatalf("adopt: %v", err)
	}
	stale := cloneMailbox(cur)
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

func (staleStore) Adopt(context.Context, *Mailbox, string, [32]byte) error { return ErrStale }
func (staleStore) Leave(context.Context, *Mailbox) error                   { return ErrStale }

// adoptCounting counts the store's adopts: each writes the mailbox's record.
type adoptCounting struct {
	Store
	n atomic.Int32
}

func (s *adoptCounting) Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error {
	s.n.Add(1)
	return s.Store.Adopt(ctx, b, account, key)
}

// A key that is not this server's, or is spent or expired, is refused after
// a read of its row, and never reaches the write of the mailbox's record.
func TestARefusedKeyWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	e := newEnv(t, l)
	acc, key := accountEnv(t, e, true, 1)
	cs := &adoptCounting{Store: e.store}
	h := New(Config{Store: cs, Limits: l, Now: e.clock.Now}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { h.ServeHTTP(w, r) })
	a, b := e.mailbox(), e.mailbox()
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
		t.Fatalf("%d writes of a mailbox's record, for one adopt", n)
	}
}

func TestAdoptRaceIsAConflict(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	acc, key := accountEnv(t, e, true, 2)
	a := e.mailbox()
	adopt(t, a, e.adoptKey(t, acc.ID, 1, time.Hour))
	stale := New(Config{Store: staleStore{e.store}, Limits: l, Now: e.clock.Now}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { stale.ServeHTTP(w, r) })
	b := e.mailbox()
	if _, err := b.Adopt(context.Background(), key); codeOf(err) != protocol.CodeMailboxChanged {
		t.Fatalf("adopt: %v", err)
	}
	if err := a.Leave(context.Background()); codeOf(err) != protocol.CodeMailboxChanged {
		t.Fatalf("leave: %v", err)
	}
}

// Two adopts at once with one key of a single use: one takes it, and the
// other is refused for the key, never both taken, whatever the store.
func TestTwoAdoptsAtOnceTakeOneUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 1)
	_, hash, _ := parseAdopt(key)
	var recs [2]*Mailbox
	for i := range recs {
		b, err := e.store.Mailbox(ctx, e.mailbox().Address())
		if err != nil {
			t.Fatal(err)
		}
		recs[i] = b
	}
	var wg sync.WaitGroup
	var errs [2]error
	for i, b := range recs {
		wg.Go(func() { errs[i] = e.store.Adopt(ctx, b, acc.ID, hash) })
	}
	wg.Wait()
	took := 0
	for i, err := range errs {
		switch {
		case err == nil:
			took++
		case !errors.Is(err, ErrKeyRefused):
			t.Errorf("adopt %d: %v, want taken or ErrKeyRefused", i, err)
		}
	}
	if took != 1 {
		t.Errorf("%d adopts took a key of one use", took)
	}
	if k, err := e.store.AdoptKey(ctx, acc.ID, hash); err != nil || k.Uses != 0 {
		t.Errorf("the key after the adopts: %+v %v; want no uses left", k, err)
	}
}

// A change to an account reaches memory by the feed: an operator makes a
// metered account unmetered by hand, then deletes it, and its mailbox has
// the free limits again.
func TestAccountChangesReachMemory(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 1, 1
	e := newEnv(t, l)
	s := e.store.(*Memory)
	acc, key := accountEnv(t, e, false, 1)
	a, b := e.mailbox(), e.mailbox()
	adopt(t, a, key)
	send(t, a, b, "1")
	if _, err := a.Send(ctx, b.Address(), "2"); !limitedBy(err, protocol.QuotaSends) {
		t.Fatalf("second send: %v", err)
	}
	if _, err := s.pool().Exec(ctx, `UPDATE accounts SET unmetered = true, rev = 2 WHERE id = $1`, acc.ID); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("unmetered %d", i))
		return err == nil
	})
	if _, err := s.pool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, acc.ID); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("gone %d", i))
		return limitedBy(err, protocol.QuotaSends)
	})
}

// until retries ok every 100 ms, for up to 10 s: the feed's delay.
func until(t *testing.T, ok func(i int) bool) {
	t.Helper()
	for i := range 100 {
		if ok(i) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the feed never brought the change")
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
	lifted, free, to := e.mailbox(), e.mailbox(), e.mailbox()
	adopt(t, lifted, key)
	post := func(pass string, size int, wait time.Duration) (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(e.statement(to.Address()), nil).Encode(), bytes.NewReader(make([]byte, size)))
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
	if code, err := post(e.pass(lifted), 500, 5*time.Second); err != nil || code != http.StatusBadRequest { // read, then bad_request
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
// one large read back (dromas-dev/dromas-server#7): its answer, 408, comes
// while its peer still holds the connection, and a large send after it is
// read, with no wait for the allowance. The metrics count the cut and both
// reads. Ordered by what each step waits for, not by a clock: on a loaded
// runner a clock lets the large send go before the cut gives the allowance
// back, and lets the wait it is allowed, the body timeout too, run out first.
func TestAStalledBodyGivesTheLargeReadBack(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10 // bodies read at once up to 16 KiB, at most 64 KiB
	l.BodyTimeout, l.BodyMinRate = 300*time.Millisecond, 1<<20
	m := NewMetrics(prometheus.NewRegistry())
	e := newEnv(t, l, func(c *Config) { c.Metrics = m })
	_, key := accountEnv(t, e, true, 1)
	lifted, to := e.mailbox(), e.mailbox()
	adopt(t, lifted, key)
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := sealedTo(e.statement(to.Address()), nil).Encode()
	_, _ = io.WriteString(conn, "POST /v1/"+to.Address().String()+"/messages?"+query+" HTTP/1.1\r\nHost: "+addr+"\r\nAuthorization: "+e.pass(lifted)+
		"\r\nContent-Type: application/octet-stream\r\nContent-Length: 60000\r\n\r\n"+strings.Repeat("a", 30000)) // past the free size, then nothing
	for wait := time.Now().Add(5 * time.Second); testutil.ToFloat64(m.largeRead.WithLabelValues("taken")) != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(wait) {
			t.Fatal("the stalled send never took the large read")
		}
	}
	// The cut's answer is written once the send has returned, and so given
	// the allowance back; the peer has not closed.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	stalled, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the stalled send was not cut: %v", err)
	}
	_ = stalled.Body.Close()
	if stalled.StatusCode != http.StatusRequestTimeout || len(e.server.largeRead) != 0 {
		t.Fatalf("the stalled send: %d, with %d large reads held, want 408 and none", stalled.StatusCode, len(e.server.largeRead))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+query, bytes.NewReader(make([]byte, 30000)))
	req.Header.Set("Authorization", e.pass(lifted))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("a large send after a stalled one: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest { // read, then bad_request
		t.Fatalf("a large send after a stalled one: %d, want 400", resp.StatusCode)
	}
	cut, taken, waited := testutil.ToFloat64(m.cut), testutil.ToFloat64(m.largeRead.WithLabelValues("taken")), testutil.ToFloat64(m.largeRead.WithLabelValues("timed_out"))
	if cut != 1 || taken != 2 || waited != 0 {
		t.Fatalf("the metrics: %v bodies cut, %v large reads taken, %v waits timed out, want 1, 2 and 0", cut, taken, waited)
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
	lifted, to := e.mailbox(), e.mailbox()
	adopt(t, lifted, key)
	e.server.largeRead <- struct{}{} // another large send is being read
	defer func() { <-e.server.largeRead }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(e.statement(to.Address()), nil).Encode(), bytes.NewReader(make([]byte, 30000)))
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
