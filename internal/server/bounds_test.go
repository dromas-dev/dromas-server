package server

// The bound of every call the store's backend makes, and of each read a
// send's shared call makes apart from its request
// (dromas-dev/dromas-server#91).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newRecord is a registered mailbox's record, from the suite's store.
func newRecord(t *testing.T) *Mailbox {
	t.Helper()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	b, err := e.store.Mailbox(t.Context(), r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// silentDatabase is a listener that takes every connection and answers
// nothing on it, as a database gone silent does: its address, and what
// closes it and its connections.
func silentDatabase(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

// silentBackend is the PostgreSQL backend on a database that never
// answers, its bodies in a directory.
func silentBackend(t *testing.T) *pgBackend {
	t.Helper()
	addr, closeDB := silentDatabase(t)
	url := "postgres://dromas@" + addr + "/dromas?sslmode=disable"
	pc, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := pgconn.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	rc.RuntimeParams["replication"] = "database"
	t.Cleanup(pool.Close)
	t.Cleanup(closeDB) // first, so the pool's dials end and its Close returns
	return &pgBackend{pool: pool, replication: rc, schema: "public", publication: "dromas_public", bodies: &dirBodies{t.TempDir()}, now: time.Now}
}

// silentS3 is bodies in a bucket of an S3 that answers nothing, or, where
// stall is set, answers a read's status, its headers and two bytes of the
// three it says the body has, and then nothing.
func silentS3(t *testing.T, stall bool) s3Bodies {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stall {
			w.Header().Set("Content-Length", "3")
			_, _ = w.Write([]byte("ab"))
			w.(http.Flusher).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		// Never an answer, even as the test ends: a handler that returned
		// would answer 200 with no body, which the SDK reads as a success.
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDFAKE", "fake", ""), BaseEndpoint: aws.String(srv.URL)}
	return s3Bodies{newS3(cfg, func(o *s3.Options) { o.UsePathStyle = true }), "bodies"}
}

// Every call the PostgreSQL backend makes ends at its bound, on a context
// its caller handed it with no deadline and no end, against a database and
// an S3 that never answer: every method of the Backend, held to the
// interface's methods, the sweep's, and each call to the bodies in S3
// (dromas-dev/dromas-server#91). The bound is in one place for each client
// (bounded, and bound for S3), not at each call
// (dromas-dev/dromas-client#411 item 4); Start's, which waits for the feed's
// slot, is feedStartWithin. Where a call comes after another, the first is
// answered: a send's body is written, and a read's status and the first of
// its bytes come, before the call held.
func TestEveryCallOfTheBackendEndsAtItsBound(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	mailbox := newRecord(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	msg := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	methods := map[string]func(context.Context, Backend) error{
		"ReadAddress": func(ctx context.Context, b Backend) error { _, _, err := b.ReadAddress(ctx, mailbox.Addr); return err },
		"ReadLive":    func(ctx context.Context, b Backend) error { _, err := b.ReadLive(ctx, mailbox.Addr); return err },
		"List": func(ctx context.Context, b Backend) error {
			_, err := b.List(ctx, mailbox.Addr, nil, 10, false)
			return err
		},
		"Message": func(ctx context.Context, b Backend) error {
			_, _, err := b.Message(ctx, mailbox.Addr, msg.ID, 0)
			return err
		},
		"Dedupe":        func(ctx context.Context, b Backend) error { _, err := b.Dedupe(ctx, mailbox.Addr, msg.ID); return err },
		"Account":       func(ctx context.Context, b Backend) error { _, err := b.Account(ctx, "acct"); return err },
		"AdoptKey":      func(ctx context.Context, b Backend) error { _, err := b.AdoptKey(ctx, "acct", [32]byte{1}); return err },
		"CreateMailbox": func(ctx context.Context, b Backend) error { return b.CreateMailbox(ctx, cloneMailbox(mailbox)) },
		"UpdateMailbox": func(ctx context.Context, b Backend) error { return b.UpdateMailbox(ctx, cloneMailbox(mailbox)) },
		"DeleteMailbox": func(ctx context.Context, b Backend) error { return b.DeleteMailbox(ctx, mailbox.Addr) },
		"Revoke": func(ctx context.Context, b Backend) error {
			_, err := b.Revoke(ctx, mailbox.Addr, &Revocations{Identity: mailbox.Identity, Address: []byte("r")}, ExpectAnything)
			return err
		},
		"Adopt": func(ctx context.Context, b Backend) error {
			return b.Adopt(ctx, cloneMailbox(mailbox), "acct", [32]byte{1})
		},
		"Leave":         func(ctx context.Context, b Backend) error { return b.Leave(ctx, cloneMailbox(mailbox)) },
		"CreateAccount": func(ctx context.Context, b Backend) error { return b.CreateAccount(ctx, &Account{ID: "acct"}) },
		"PutAdoptKey": func(ctx context.Context, b Backend) error {
			return b.PutAdoptKey(ctx, &AdoptKey{Account: "acct", Hash: [32]byte{1}, Uses: 1, Expires: now.Add(time.Hour)})
		},
		"PutMessage": func(ctx context.Context, b Backend) error { return b.PutMessage(ctx, mailbox.Addr, msg, []byte("abc")) },
		"Retire":     func(ctx context.Context, b Backend) error { _, err := b.Retire(ctx, mailbox.Addr, msg.ID); return err },
		"DeleteMessage": func(ctx context.Context, b Backend) error {
			_, err := b.DeleteMessage(ctx, mailbox.Addr, msg.ID)
			return err
		},
		"DeleteAll": func(ctx context.Context, b Backend) error {
			return b.DeleteAll(ctx, mailbox.Addr, func([32]byte, time.Time) {})
		},
		"Start": func(ctx context.Context, b Backend) error { return b.Start(ctx, func(Change) {}) },
	}
	bt := reflect.TypeFor[Backend]()
	for i := range bt.NumMethod() {
		if name := bt.Method(i).Name; methods[name] == nil && name != "Ready" { // Ready makes no call
			t.Errorf("the Backend's %s has no case here", name)
		}
	}
	type call struct {
		name  string
		bound time.Duration
		run   func(context.Context) error
	}
	var calls []call
	for _, name := range slices.Sorted(maps.Keys(methods)) {
		bound := storeTimeout
		if name == "Start" {
			bound = feedStartWithin
		}
		b := silentBackend(t)
		calls = append(calls, call{name, bound, func(ctx context.Context) error { return methods[name](ctx, b) }})
	}
	sweep := silentBackend(t)
	put, get, del, stalled := silentS3(t, false), silentS3(t, false), silentS3(t, false), silentS3(t, true)
	calls = append(calls,
		call{"the sweep's batch", storeTimeout, func(ctx context.Context) error { return sweep.sweepTable(ctx, "messages") }},
		call{"a body's write to S3", storeTimeout, func(ctx context.Context) error { return put.Put(ctx, "k", []byte("abc")) }},
		call{"a body's read from S3", storeTimeout, func(ctx context.Context) error { _, err := get.Get(ctx, "k", 0, 3); return err }},
		call{"a body's bytes from S3", storeTimeout, func(ctx context.Context) error { _, err := stalled.Get(ctx, "k", 0, 3); return err }},
		call{"bodies' delete from S3", storeTimeout, func(ctx context.Context) error { return del.Delete(ctx, "k") }},
	)
	// Every call at once, then each judged by its end, waited for until its
	// bound and 3 s after they began.
	type result struct {
		err  error
		took time.Duration
	}
	began := time.Now()
	ended := make([]chan result, len(calls))
	for i, c := range calls {
		ended[i] = make(chan result, 1)
		go func() {
			start := time.Now()
			err := c.run(context.WithoutCancel(t.Context()))
			ended[i] <- result{err, time.Since(start)}
		}()
	}
	for i, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			wait := time.NewTimer(time.Until(began.Add(c.bound + 3*time.Second)))
			defer wait.Stop()
			var r result
			ok := false
			select { // a call that has ended is judged by its end, however long the calls judged before it waited
			case r = <-ended[i]:
				ok = true
			default:
				select {
				case r = <-ended[i]:
					ok = true
				case <-wait.C:
				}
			}
			switch {
			case !ok:
				t.Errorf("still waiting after %v and 3 s: a call that is never answered is not bounded by %v", c.bound, c.bound)
			case !errors.Is(r.err, context.DeadlineExceeded):
				t.Errorf("ended after %v by %v, not by its bound", r.took.Round(100*time.Millisecond), r.err)
			default:
				t.Logf("ended after %v: %v", r.took.Round(100*time.Millisecond), r.err)
			}
		})
	}
}

// A body S3 answers with is read after its call returns, within the call's
// bound, which ends when the body is closed (bound;
// dromas-dev/dromas-client#453 item 2): once Close returns, the bound's
// context has ended, and not before.
func TestABodysBoundEndsWhenItIsClosed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), storeTimeout)
	defer cancel()
	body := cancelOnClose{io.NopCloser(strings.NewReader("abc")), cancel}
	if _, err := io.ReadAll(body); err != nil || ctx.Err() != nil {
		t.Fatalf("the body's read: %v; its bound before it is closed: %v", err, ctx.Err())
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Error("the body is closed, and its bound has not ended")
	}
}

// hangingDedupe holds the dedupe read of one id until its context ends or
// the test lets it go, as a read on a connection that went silent does (a
// call to the database ends with its context, and by default with nothing
// else).
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

func (s *hangingDedupe) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
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
	return s.Store.Dedupe(ctx, mailbox, id)
}

func (s *hangingDedupe) Known(a protocol.Address) (*Mailbox, bool) {
	if a == s.probe {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s *hangingDedupe) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.probe {
		s.lookupDeadline.Store(deadlineOf(ctx))
	}
	return s.Store.Mailbox(ctx, a)
}

// postBytes posts ciphertext ct to url, which names its statement, with pass,
// through c: its status, or 0 when the client gave up.
func postBytes(c *http.Client, url string, ct []byte, pass string) int {
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(ct))
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
	url := e.srv.URL + to.path("/messages?") + to.sealed(1, nil).Encode()
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
// lets it go, as a read on a connection that went silent does.
type holdDedupe struct {
	Store
	hold    atomic.Bool
	entered chan struct{}
	let     chan struct{}
	ended   atomic.Bool
}

func (s *holdDedupe) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	if s.hold.CompareAndSwap(true, false) {
		close(s.entered)
		select {
		case <-ctx.Done():
			s.ended.Store(true)
			return nil, ctx.Err()
		case <-s.let:
		}
	}
	return s.Store.Dedupe(ctx, mailbox, id)
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
	lifted, to := e.mailbox(), e.mailbox()
	adopt(t, lifted, key)
	id, err := age.GenerateHybridIdentity()
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
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/v1/"+to.Address().String()+"/messages?"+sealedTo(e.statement(to.Address()), nil).Encode(), bytes.NewReader(body))
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

func (s *readDeadlines) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	if mailbox == s.to {
		s.note("Dedupe", ctx)
	}
	return s.Store.Dedupe(ctx, mailbox, id)
}

func (s *readDeadlines) Count(ctx context.Context, mailbox protocol.Address) (int, error) {
	if mailbox == s.to {
		s.note("Count", ctx)
	}
	return s.Store.Count(ctx, mailbox)
}

func (s *readDeadlines) Account(ctx context.Context, id string) (*Account, error) {
	if id == s.account {
		s.note("Account", ctx)
	}
	return s.Store.Account(ctx, id)
}

func (s *readDeadlines) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.to {
		s.note("Mailbox", ctx)
	}
	return s.Store.Mailbox(ctx, a)
}

// Each read a send's shared call makes runs apart from the request that
// leads it, and is handed a context bounded by storeTimeout, so the bound
// holds on any store: the dedupe, the mailbox cap's reads, the
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
	rec, err := e.store.Mailbox(ctx, to.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Adopt(ctx, rec, acc.ID, hash); err != nil {
		t.Fatal(err)
	}
	s.to, s.account = to.id.Address(), acc.ID
	e.want(e.sendTo(to, 1, from, 1), http.StatusCreated, "")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, read := range []string{"Dedupe", "Count", "Account", "Mailbox"} {
		d, ok := s.seen[read]
		t.Logf("%s: deadline %v (-1: none)", read, d)
		if !ok || d <= 0 || d > storeTimeout {
			t.Errorf("the send's %s read, made apart from its request, is handed deadline %v (made %v); want at most %v", read, d, ok, storeTimeout)
		}
	}
}
