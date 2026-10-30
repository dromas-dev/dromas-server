package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Posts of the same ciphertext in flight at once are one call, from any
// sender (dromas-dev/dromas-server#76): the second waits for the first and
// is answered 200 with its receipt, never refused by a quota the first one
// spent (PROTOCOL.md §11.5), for the sends a day, the mailbox cap and the mailbox's
// new messages alike. A post handed the refusal of another sender's is made
// again, as its own.
func TestPostsOfTheSameBytesInFlightAreOneCall(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		set  func(*Limits)
	}{
		{"sends a day", func(l *Limits) { l.SendsPerDay = 2 }},
		{"the mailbox cap", func(l *Limits) { l.MailboxCap = 2 }},
		{"the mailbox's new messages", func(l *Limits) { l.ReceiveBurst, l.ReceiveRefill = 2, time.Hour }},
	} {
		l := relaxed()
		l.MailboxCap = 0
		c.set(&l)
		e := newEnv(t, l, func(cfg *Config) { cfg.Store = slowPut{cfg.Store, 40 * time.Millisecond} })
		for i := range 5 {
			to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.sendTo(to, 1, 1, from, 1), http.StatusCreated, "") // one of each budget spent
			// The second post is from the same sender, and on odd trials
			// from another.
			second := from
			if i%2 == 1 {
				second = e.raw().register(protocol.MaxPrekeyLifetime)
			}
			ct := sealFor(t, to, 1)
			var r1, r2 reply
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); r1 = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), from.pass(1)) }()
			time.Sleep(5 * time.Millisecond)
			go func() { defer wg.Done(); r2 = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), second.pass(1)) }()
			wg.Wait()
			if got := fmt.Sprint(r1.status, " ", r2.status); got != "201 200" && got != "200 201" {
				t.Errorf("%s, trial %d: the same bytes posted twice at once answered %s %s, %s %s; want 201 and 200, whichever won", c.name, i, got, r1.code(), r2.code(), r2.body)
			}
		}
	}

	e := newEnv(t, relaxed(), func(cfg *Config) { cfg.Store = slowPut{cfg.Store, 40 * time.Millisecond} })
	to, a, b := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	ct := sealFor(t, to, 1)
	var ra, rb reply
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ra = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), a.pass(1)) }()
	time.Sleep(5 * time.Millisecond)
	go func() { defer wg.Done(); rb = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), b.pass(1)) }()
	wg.Wait()
	if got := fmt.Sprint(ra.status, " ", rb.status); got != "201 200" && got != "200 201" {
		t.Errorf("the same bytes from two senders at once answered %s; want 201 and 200, whichever won", got)
	}

	// A sender at its sends a day and one with sends left post the same
	// bytes at once: the second is never handed the first one's refusal.
	// The first leads, held at its dedupe until the second's begins, and
	// reads before it (leadDedupe), so the second comes while the first is
	// in flight, and is stored after the first has read.
	l := relaxed()
	l.SendsPerDay = 1
	lead := &armedDedupe{leadDedupe: &leadDedupe{wait: time.Second, entered: make(chan struct{}), second: make(chan struct{}), read: make(chan struct{})}}
	e = newEnv(t, l, func(cfg *Config) { lead.Store, cfg.Store = cfg.Store, lead })
	to, spent, fresh := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.sendTo(to, 1, 1, spent, 1), http.StatusCreated, "")
	lead.on.Store(true)
	ct = sealFor(t, to, 1)
	led := make(chan reply, 1)
	go func() { led <- e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), spent.pass(1)) }()
	select {
	case <-lead.entered:
	case r := <-led:
		t.Fatalf("the post at its limit was answered before its dedupe: %d %s", r.status, r.code())
	}
	rb = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), fresh.pass(1))
	ra = <-led
	if ra.status != http.StatusTooManyRequests || rb.status != http.StatusCreated {
		t.Errorf("a sender at its limit and one with sends left posting the same bytes at once: %d %s and %d %s; want 429 and 201", ra.status, ra.code(), rb.status, rb.code())
	}
}

// revokedBetween revokes mailbox a, once, just before the first read of its
// record once set: in a send, the read after its pass's check.
type revokedBetween struct {
	Store
	a    protocol.Address
	rv   *Revocations
	done atomic.Bool
}

func (s *revokedBetween) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.a && s.done.CompareAndSwap(false, true) {
		if err := s.Store.Revoke(ctx, a, s.rv, ExpectAnything); err != nil {
			return nil, err
		}
	}
	return s.Store.Mailbox(ctx, a)
}

// A sender revoked between its pass's check and the send's read of its
// record is refused there, as its pass's check would have refused it
// (sender), and its message is not taken.
func TestASenderRevokedDuringItsSendIsRefused(t *testing.T) {
	t.Parallel()
	s := &revokedBetween{}
	e := newEnv(t, relaxed(), func(c *Config) { s.Store, c.Store = c.Store, s })
	to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	sig, err := protocol.SignRevocation(from.signer, from.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	s.a, s.rv = from.id.Address(), &Revocations{Identity: from.id.Document(), Address: sig}
	e.want(e.sendTo(to, 1, 1, from, 1), http.StatusForbidden, protocol.CodeSenderRevoked)
	if n, _ := e.store.Count(context.Background(), to.id.Address()); n != 0 {
		t.Errorf("the mailbox took %d messages from a sender revoked during its send", n)
	}
}

// heldDeletes holds every delete of a mailbox's messages until released, counting
// them.
type heldDeletes struct {
	Store
	started, release chan struct{}
	once             sync.Once
	n                atomic.Int64
}

func (s *heldDeletes) DeleteMessages(ctx context.Context, a protocol.Address) error {
	s.n.Add(1)
	s.once.Do(func() { close(s.started) })
	<-s.release
	return s.Store.DeleteMessages(ctx, a)
}

// Revocations sent for a revoked mailbox while its delete is in flight start no
// delete of their own (dromas-dev/dromas-server#29): they wait for the
// one in flight and are answered 410, and the revoking PUT is answered with
// its delete's result.
func TestPUTsDuringARevocationsDeleteStartNoOther(t *testing.T) {
	t.Parallel()
	hs := &heldDeletes{started: make(chan struct{}), release: make(chan struct{})}
	e := newEnv(t, relaxed(), func(c *Config) { hs.Store, c.Store = c.Store, hs })
	a, b := e.mailbox(), e.mailbox()
	send(t, b, a, "waiting in A's mailbox when it is revoked")
	rec := record(t, a)
	path := revocationPath(a.Address())
	junk := protocol.Revocations{Identity: rec.Identity, Revocation: []byte("not a signature")}

	owner := make(chan reply, 1)
	go func() { owner <- e.do("PUT", path, rec, "") }()
	<-hs.started // the owner's delete is under way, and memory still shows the messages
	const k = 8
	codes := make(chan string, k)
	for range k {
		go func() {
			r := e.do("PUT", path, junk, "")
			codes <- fmt.Sprint(r.status, " ", r.code())
		}()
	}
	time.Sleep(300 * time.Millisecond) // for the PUTs to reach a delete of their own, if they would
	close(hs.release)
	for range k {
		if got := <-codes; got != "410 revoked" {
			t.Errorf("a PUT during the delete: %s", got)
		}
	}
	e.want(<-owner, http.StatusCreated, "")
	if n := hs.n.Load(); n != 1 {
		t.Errorf("%d PUTs during one delete drew %d deletes of the mailbox's messages; want 1", k, n)
	}
}

// On DynamoDB: a write of an id whose message was acked is a new message, whatever
// a dedupe read before it found: the ack deleted the item, so the write's
// condition passes, and its item and its body are stored and served.
func TestAPutAfterAnAckIsStored(t *testing.T) {
	t.Parallel()
	e, s := dynamoEnv(t)
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	body := []byte("acked, then posted again")
	id := idOf(t, send(t, a, b, string(body)))
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	e.clock.Add(time.Second)
	now := e.clock.Now().UTC().Truncate(time.Millisecond)
	h := &Header{ID: id, Size: len("the same id again"), ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	orig, err := s.PutMessage(ctx, b.Address(), h, []byte("the same id again"))
	if err != nil || orig != nil {
		t.Fatalf("the write after the ack: %v, %v; want it stored", orig, err)
	}
	if !s.listed(t, b.Address(), id) || !s.bodyExists(t, b.Address(), id) {
		t.Fatal("the write after the ack is not listed, or its body not kept")
	}
	if got, body, err := s.Message(ctx, b.Address(), id, 0); err != nil || !got.ReceivedAt.Equal(now) || string(body) != "the same id again" {
		t.Fatalf("fetch: %+v %q %v; want the new message", got, body, err)
	}
}

// slowRead makes a read of address x take a while.
type slowRead struct {
	Store
	x protocol.Address
}

func (s slowRead) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.x {
		time.Sleep(300 * time.Millisecond)
	}
	return s.Store.Mailbox(ctx, a)
}

// A lookup that waits on another's read of the same address, whose caller
// was refused before reading, makes its own read: it is never handed the
// refusal of another caller's address (lookup).
func TestALookupIsNeverRefusedForAnotherCallersMisses(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute = 1
	var x, y protocol.Address
	x[0], y[0] = 9, 10
	e := newEnv(t, l, func(c *Config) { c.Store, c.TrustedProxies = slowRead{c.Store, x}, loopback })
	from := func(ip string, a protocol.Address) chan int {
		got := make(chan int, 1)
		go func() {
			req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/"+a.String(), nil)
			req.Header.Set("X-Forwarded-For", ip)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				got <- 0
				return
			}
			_ = resp.Body.Close()
			got <- resp.StatusCode
		}()
		return got
	}
	first := from("192.0.2.1", x) // holds the caller's one miss while its read is slow
	time.Sleep(50 * time.Millisecond)
	refused := from("192.0.2.1", y) // waits for that miss to settle, then is refused
	time.Sleep(50 * time.Millisecond)
	other := from("192.0.2.2", y) // joins that read of y
	if got := <-first; got != http.StatusNotFound {
		t.Fatalf("the first lookup: %d", got)
	}
	if got := <-refused; got != http.StatusTooManyRequests {
		t.Fatalf("the lookup past its address's misses: %d; the test wants it refused", got)
	}
	if got := <-other; got != http.StatusNotFound {
		t.Errorf("a lookup from another address, joined to a read whose caller was refused: %d, want 404", got)
	}
}

// alwaysRead holds nothing in memory, so every lookup reads, and holds each
// read until two have begun.
type alwaysRead struct {
	Store
	begun chan struct{}
}

func (s alwaysRead) Known(protocol.Address) (*Mailbox, bool) { return nil, false }

func (s alwaysRead) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	s.begun <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	return s.Store.Mailbox(ctx, a)
}

// Lookups that share a read each get a copy of their own of the record, since
// a caller may change the one it has (a renewal does).
func TestLookupsThatShareAReadGetCopiesOfTheirOwn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	s := New(Config{Store: alwaysRead{e.store, make(chan struct{}, 2)}, Limits: relaxed(), Now: e.clock.Now})
	req := httptest.NewRequest(http.MethodGet, b.path(""), nil)
	var got [2]*Mailbox
	var wg sync.WaitGroup
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if got[i], err = s.lookup(req, b.id.Address()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got[0] == nil || got[0] == got[1] {
		t.Errorf("two lookups that shared a read got %p and %p; want two copies", got[0], got[1])
	}
}

// rawAnswer is one call's answer, or the error that ended it.
type rawAnswer struct {
	status int
	code   protocol.Code
	err    error
}

func (a rawAnswer) String() string {
	if a.err != nil {
		return "error"
	}
	return fmt.Sprint(a.status, " ", a.code)
}

// plainCall makes one call, for goroutines: it never stops the test, and a call
// cut off (a panic in its handler) is an answer with err set.
func plainCall(method, url string, body []byte, ctype, pass string) rawAnswer {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if pass != "" {
		req.Header.Set("Authorization", pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rawAnswer{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var p protocol.Problem
	_ = json.Unmarshal(b, &p)
	return rawAnswer{status: resp.StatusCode, code: p.Code}
}

// rawPost is a post of ct to mailbox to, naming the serials given, with pass.
func rawPost(e *env, to *raw, ct []byte, serial, under uint64, pass string) func() rawAnswer {
	q := protocol.SendQuery{PrekeySerial: serial, CertificateSerial: under}
	url := e.srv.URL + to.path("/messages") + "?" + q.Encode()
	return func() rawAnswer { return plainCall(http.MethodPost, url, ct, protocol.CiphertextContentType, pass) }
}

// allAtOnce runs each call on a goroutine of its own, all released at once,
// and returns their answers in order.
func allAtOnce(calls ...func() rawAnswer) []rawAnswer {
	start := make(chan struct{})
	out := make([]rawAnswer, len(calls))
	var wg sync.WaitGroup
	for i, c := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = c()
		}()
	}
	close(start)
	wg.Wait()
	return out
}

// tallyOf counts the answers by status and code.
func tallyOf(as []rawAnswer) string {
	n := map[string]int{}
	for _, a := range as {
		n[a.String()]++
	}
	var ks []string
	for k, v := range n {
		ks = append(ks, fmt.Sprintf("%dx %s", v, k))
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

// leadDedupe holds the first dedupe read until a second begins, or until wait
// has passed, and the second until the first has read: a post that leads its
// flight reads first, and one that comes while it is in flight, if it makes
// a flight of its own, reads after it.
type leadDedupe struct {
	Store
	wait                  time.Duration
	n                     atomic.Int32
	entered, second, read chan struct{}
}

func (s *leadDedupe) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	switch s.n.Add(1) {
	case 1:
		close(s.entered)
		select {
		case <-s.second:
		case <-time.After(s.wait):
		}
		defer close(s.read)
	case 2:
		close(s.second)
		<-s.read
	}
	return s.Store.Dedupe(ctx, mailbox, id)
}

// armedDedupe is leadDedupe once on: every dedupe read before is the
// store's own.
type armedDedupe struct {
	*leadDedupe
	on atomic.Bool
}

func (s *armedDedupe) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	if !s.on.Load() {
		return s.Store.Dedupe(ctx, mailbox, id)
	}
	return s.leadDedupe.Dedupe(ctx, mailbox, id)
}

// Posts of the same bytes from one sender naming other serials are posts of
// their own: the single flight's key holds the query (send). A post naming a
// stale serial, which leads, is refused stale_prekey; one naming the current
// serials, which comes while it is in flight, is stored, never handed the
// stale one's refusal (dromas-dev/dromas-server#92).
func TestAStaleSerialIsAPostOfItsOwn(t *testing.T) {
	t.Parallel()
	s := &leadDedupe{wait: time.Second, entered: make(chan struct{}), second: make(chan struct{}), read: make(chan struct{})}
	e := newEnv(t, relaxed(), func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
	to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	ct := sealFor(t, to, 1)
	pass := from.pass(1)
	stale, cur := rawPost(e, to, ct, 2, 1, pass), rawPost(e, to, ct, 1, 1, pass)
	led := make(chan rawAnswer, 1)
	go func() { led <- stale() }()
	select {
	case <-s.entered: // the stale post leads its flight, held at its dedupe
	case a := <-led:
		t.Fatalf("the stale post was answered before its dedupe: %s", a)
	}
	got := cur()
	if first := <-led; first.code != protocol.CodeStalePrekey || got.status != http.StatusCreated {
		t.Errorf("the same bytes naming a stale and the current serials at once: %s and %s; want 409 stale_prekey and 201", first, got)
	}
}

// panicOnce panics once it is armed, after a gate, in a post's write, a
// purge's delete or a lookup's read of address x.
type panicOnce struct {
	Store
	x              protocol.Address
	let            chan struct{}
	put, del, read atomic.Bool
	entered        chan string
}

func (s *panicOnce) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	if s.put.CompareAndSwap(true, false) {
		s.entered <- "put"
		<-s.let
		panic("panicOnce: a panic in a post's write")
	}
	return s.Store.PutMessage(ctx, mailbox, h, body)
}

func (s *panicOnce) DeleteMessages(ctx context.Context, a protocol.Address) error {
	if s.del.CompareAndSwap(true, false) {
		s.entered <- "delete"
		<-s.let
		panic("panicOnce: a panic in a purge")
	}
	return s.Store.DeleteMessages(ctx, a)
}

func (s *panicOnce) Known(a protocol.Address) (*Mailbox, bool) {
	if a == s.x {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s *panicOnce) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.x && s.read.CompareAndSwap(true, false) {
		s.entered <- "read"
		<-s.let
		panic("panicOnce: a panic in a lookup's read")
	}
	return s.Store.Mailbox(ctx, a)
}

// A panic in the shared function of each single flight, the posts', the
// lookups' and the purges', with callers waiting on it, ends none but those
// calls: each caller's handler panics, which net/http reports and recovers,
// the process goes on, and the next call of the same key is made afresh.
// singleflight's DoChan would end the process on that panic, and Do hands it
// to every caller (dromas-dev/dromas-server#92).
func TestAPanicInEachSingleFlightEndsOnlyItsCalls(t *testing.T) {
	t.Parallel()
	const n = 8
	e := newEnv(t, relaxed())
	p := &panicOnce{Store: e.store, entered: make(chan string, 3)}
	srv := httptest.NewUnstartedServer(apitest.Handler(t, New(Config{Store: p, Limits: relaxed(), Now: e.clock.Now}).Handler()))
	var panics lockedBuffer
	srv.Config.ErrorLog = log.New(&panics, "", 0)
	srv.Start()
	t.Cleanup(srv.Close)
	api := &env{t: t, clock: e.clock, srv: srv, store: p}
	to, from := api.raw().register(protocol.MaxPrekeyLifetime), api.raw().register(protocol.MaxPrekeyLifetime)
	victim := api.raw().register(protocol.MaxPrekeyLifetime)
	p.x = victim.id.Address()

	run := func(name string, arm *atomic.Bool, call func() rawAnswer) {
		t.Helper()
		before := strings.Count(panics.String(), "http: panic serving")
		p.let = make(chan struct{})
		arm.Store(true)
		calls := make([]func() rawAnswer, n)
		for i := range calls {
			calls[i] = call
		}
		go func() { <-p.entered; time.Sleep(300 * time.Millisecond); close(p.let) }()
		got := allAtOnce(calls...)
		time.Sleep(50 * time.Millisecond) // net/http logs a panic before it closes the connection
		after := strings.Count(panics.String(), "http: panic serving")
		t.Logf("%s: %s; %d panics reported", name, tallyOf(got), after-before)
		if after-before != n {
			t.Errorf("%s: %d of %d callers' handlers panicked", name, after-before, n)
		}
		if again := call(); again.err != nil || again.status >= 500 {
			t.Errorf("%s: the next call after the panic: %v %s", name, again.err, again)
		}
	}

	post := rawPost(api, to, sealFor(t, to, 1), 1, 1, api.passFor(from.work[1], from.id.Address(), api.name()))
	run("posts", &p.put, post)
	run("lookups", &p.read, func() rawAnswer { return plainCall(http.MethodGet, srv.URL+victim.path(""), nil, "", "") })

	mailbox := api.raw().register(protocol.MaxPrekeyLifetime)
	api.want(api.sendTo(mailbox, 1, 1, from, 1), http.StatusCreated, "")
	sig, err := protocol.SignRevocation(mailbox.signer, mailbox.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := json.Marshal(protocol.Revocations{Identity: mailbox.id.Document(), Revocation: sig})
	if err := p.Store.Revoke(context.Background(), mailbox.id.Address(), &Revocations{Identity: mailbox.id.Document(), Address: sig}, ExpectAnything); err != nil {
		t.Fatal(err)
	}
	run("purges", &p.del, func() rawAnswer {
		return plainCall(http.MethodPut, srv.URL+mailbox.path("/revocations"), rec, "application/json", "")
	})
	if n, _ := p.Store.Count(context.Background(), mailbox.id.Address()); n != 0 {
		t.Errorf("after the purge's panic and the next PUT: %d messages left", n)
	}
}

// changedBetween changes sender a, once, just before the first read of its
// record once set: in a send, the read after its pass's check.
type changedBetween struct {
	Store
	a      protocol.Address
	change func(ctx context.Context) error
	done   atomic.Bool
}

func (s *changedBetween) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.a && s.change != nil && s.done.CompareAndSwap(false, true) {
		if err := s.change(ctx); err != nil {
			return nil, err
		}
	}
	return s.Store.Mailbox(ctx, a)
}

// A sender revoked, its current certificate revoked, or forgotten between its
// pass's check and the send's read of its record is refused as its pass's
// check would refuse it, and nothing is stored (send; dromas-dev/dromas-server#92).
func TestASenderChangedBetweenItsPassAndItsRecordIsRefused(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		status int
		code   protocol.Code
		change func(s *changedBetween, from *raw) func(context.Context) error
	}{
		{"revoked", http.StatusForbidden, protocol.CodeSenderRevoked, func(s *changedBetween, from *raw) func(context.Context) error {
			return func(ctx context.Context) error {
				sig, err := protocol.SignRevocation(from.signer, from.id.Address())
				if err != nil {
					return err
				}
				return s.Store.Revoke(ctx, from.id.Address(), &Revocations{Identity: from.id.Document(), Address: sig}, ExpectAnything)
			}
		}},
		{"its current certificate revoked", http.StatusUnauthorized, protocol.CodeCertificateRevoked, func(s *changedBetween, from *raw) func(context.Context) error {
			return func(ctx context.Context) error {
				rc := from.certs(1)
				return s.Store.Revoke(ctx, from.id.Address(), &Revocations{Identity: from.id.Document(), Certs: rc.RevokedCertificates, CertsSig: rc.RevokedCertificatesSignature, Through: 1}, ExpectAnything)
			}
		}},
		{"forgotten", http.StatusForbidden, protocol.CodeUnknownSender, func(s *changedBetween, from *raw) func(context.Context) error {
			return func(ctx context.Context) error { return s.Store.DeleteMailbox(ctx, from.id.Address()) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &changedBetween{}
			e := newEnv(t, relaxed(), func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			pass := from.pass(1)
			s.a, s.change = from.id.Address(), c.change(s, from)
			r := e.do("POST", to.path("/messages"), sealedTo(1, 1, sealFor(t, to, 1)), pass)
			n, _ := e.store.Count(context.Background(), to.id.Address())
			if !s.done.Load() || r.status != c.status || r.code() != c.code || n != 0 {
				t.Errorf("a sender %s between its pass's check and its record's read: %d %s, %d stored (changed %v); want %d %s and none",
					c.name, r.status, r.code(), n, s.done.Load(), c.status, c.code)
			}
		})
	}
}

// cannedAWS answers S3's PutObject and DeleteObject, and DynamoDB's PutItem
// with a failed condition carrying item, and records each call.
type cannedAWS struct {
	mu    sync.Mutex
	calls []string
	item  string // the ConditionalCheckFailedException's Item, as JSON
}

func (c *cannedAWS) Do(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	target := r.Header.Get("X-Amz-Target")
	c.mu.Lock()
	c.calls = append(c.calls, strings.TrimSpace(r.Method+" "+target+" "+r.URL.Path))
	c.mu.Unlock()
	status, body, ctype := http.StatusOK, "", "application/xml"
	switch {
	case strings.HasSuffix(target, ".PutItem"):
		status, ctype = http.StatusBadRequest, "application/x-amz-json-1.0"
		body = `{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed","Item":` + c.item + `}`
	case target != "":
		return nil, fmt.Errorf("cannedAWS: no answer for %s", target)
	case r.Method == http.MethodDelete:
		status = http.StatusNoContent
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {ctype}, "X-Amzn-Requestid": {"t"}, "Etag": {`"e"`}},
		Body:   io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// The DynamoDB backend's PutMessage, in process against canned answers: a
// duplicate whose PutItem finds the id's item live answers with its header,
// and deletes no body: the one it put is that message's, the same bytes
// (dromas-dev/dromas-server#16, #92).
func TestADuplicatesWriteDeletesNoBody(t *testing.T) {
	t.Parallel()
	var mailbox protocol.Address
	mailbox[0] = 1
	body := []byte("the same bytes")
	id := [32]byte{3}
	now := time.Now().UTC().Truncate(time.Millisecond)
	recv := ms(now) - 1000
	b64 := base64.StdEncoding.EncodeToString
	it := fmt.Sprintf(`{"box":{"B":%q},"id":{"B":%q},"size":{"N":"%d"},"received_at":{"N":"%d"},"expires_at":{"N":"%d"},"live":{"B":%q}}`,
		b64(mailbox[:]), b64(id[:]), len(body), recv, ttlSeconds(recv+ttlMs), b64(liveKey(recv, id)))
	fake := &cannedAWS{item: it}
	var logged bytes.Buffer
	s := NewDynamoStore(DynamoConfig{AWS: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "x", ""),
		HTTPClient: fake, BaseEndpoint: aws.String("http://127.0.0.1:1")}, MailboxesTable: "b", MessagesTable: "m", AccountsTable: "a", Bucket: "s", Log: log.New(&logged, "", 0)})
	h := &Header{ID: id, Size: len(body), ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	orig, err := s.PutMessage(context.Background(), mailbox, h, body)
	fake.mu.Lock()
	calls := append([]string(nil), fake.calls...)
	fake.mu.Unlock()
	t.Logf("calls %q; logged %q", calls, logged.String())
	if err != nil || orig == nil || orig.ID != id || ms(orig.ReceivedAt) != recv {
		t.Fatalf("a duplicate's write: %+v, %v; want the original's header", orig, err)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Errorf("a duplicate that found the item live deleted %s", call)
		}
	}
}
