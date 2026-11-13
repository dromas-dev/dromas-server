package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/dromas-dev/dromas-client/protocol"
)

// testValkey is a client of the Valkey DROMAS_TEST_VALKEY names
// (valkey://host:port), as serve makes one (OpenValkey); a test that needs
// one skips without it.
func testValkey(t *testing.T) valkey.Client {
	t.Helper()
	url := os.Getenv("DROMAS_TEST_VALKEY")
	if url == "" {
		t.Skip("needs Valkey: DROMAS_TEST_VALKEY")
	}
	c, err := OpenValkey(url, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if err := c.Do(t.Context(), c.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("DROMAS_TEST_VALKEY: %v", err)
	}
	return c
}

// A Valkey user's password is taken apart from the URL, which names the
// user; a wrong one refuses the client at once, since the store answered;
// and a password in the URL and another apart is refused.
func TestValkeysPasswordIsGivenApartFromItsURL(t *testing.T) {
	t.Parallel()
	c := testValkey(t)
	user, password := "test-"+randomKey(t), randomKey(t)
	if err := c.Do(t.Context(), c.B().Arbitrary("ACL", "SETUSER", user, "on", ">"+password, "~*", "+@all").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Do(context.Background(), c.B().Arbitrary("ACL", "DELUSER", user).Build()).Error() })
	base := os.Getenv("DROMAS_TEST_VALKEY")
	at := strings.Replace(base, "://", "://"+user+"@", 1)

	good, err := OpenValkey(at, password)
	if err != nil {
		t.Fatalf("the user's password: %v", err)
	}
	defer good.Close()
	if err := good.Do(t.Context(), good.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("a call with the user's password: %v", err)
	}
	if _, err := OpenValkey(at, password+"x"); err == nil {
		t.Fatal("a wrong password was taken")
	}
	if _, err := OpenValkey(strings.Replace(base, "://", "://"+user+":"+password+"@", 1), password); err == nil {
		t.Fatal("a password in the URL and another apart were taken")
	}
}

// randomKey is a key no other test uses, so tests share one store.
func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sharedSet is a bucket set of n, one back each interval, on the shared
// store, under a name of its own: a process's sends a day.
func sharedSet(c valkey.Client, name string, n int, every time.Duration) *buckets {
	bs := newBuckets(name, n, every)
	bs.shared = newSharedBuckets(c, name, nil, nil)
	return bs
}

// Two processes' buckets on one shared store are one bucket: a token one
// takes, the other cannot; one given back, the other can take; each reports
// the store's bucket; and a clear by one fills it for both.
func TestBucketsOnASharedStoreAreOneAcrossProcesses(t *testing.T) {
	t.Parallel()
	c := testValkey(t)
	name, key := "test-"+randomKey(t), randomKey(t)
	at := time.Now().Truncate(time.Second)
	now := func() time.Time { return at }
	a, b := sharedSet(c, name, 2, time.Hour), sharedSet(c, name, 2, time.Hour)
	ctx := t.Context()

	for i := range 2 {
		r, ok, _ := a.reserve(ctx, key, now)
		if !ok {
			t.Fatalf("take %d of 2 refused", i+1)
		}
		r.keep()
	}
	if _, ok, wait := b.reserve(ctx, key, now); ok || wait != time.Hour {
		t.Fatalf("the other process took a third of 2: ok %v, wait %s; want refused for an hour", ok, wait)
	}
	if left, untilFull, n, _ := b.report(key, at); left != 0 || untilFull != 2*time.Hour || n != 2 {
		t.Fatalf("the other process reports %d left, full in %s, of %d; want 0, 2h, 2", left, untilFull, n)
	}
	if len(a.full) != 0 || len(b.full) != 0 {
		t.Fatalf("the processes' own counts hold %d and %d keys while the store answers, want none", len(a.full), len(b.full))
	}

	at = at.Add(time.Hour)
	r, ok, _ := b.reserve(ctx, key, now)
	if !ok {
		t.Fatal("the token back after an hour was refused")
	}
	if _, ok, _ := a.reserve(ctx, key, now); ok {
		t.Fatal("a token was taken twice")
	}
	r.release(at)
	r, ok, _ = a.reserve(ctx, key, now)
	if !ok {
		t.Fatal("a token given back by one process was refused by the other")
	}
	r.keep()

	if !b.clear(key, at) {
		t.Fatal("a clear found nothing held")
	}
	if left, _, _, _ := a.report(key, at); left != 2 {
		t.Fatalf("after a clear, %d left, want 2", left)
	}
}

// A send's sends a day are the shared store's: a token another process
// spent is refused here, and the send's Dromas-RateLimit reports the store's
// bucket.
func TestASendSpendsTheSendersBudgetInTheSharedStore(t *testing.T) {
	t.Parallel()
	c := testValkey(t)
	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 2, 2
	e := newEnv(t, l, func(cfg *Config) { cfg.Valkey = c })
	a, b := e.mailbox(), e.mailbox()
	to := "/v1/" + b.Address().String() + "/messages"

	other := sharedSet(c, string(protocol.QuotaSends), 2, day/2)
	r, ok, _ := other.reserve(t.Context(), a.Address().String(), e.clock.Now)
	if !ok {
		t.Fatal("the other process's take refused")
	}
	r.keep()
	got := e.do("POST", to, e.sealTo(b), e.pass(a))
	e.want(got, http.StatusCreated, "")
	rl := protocol.ParseRateLimit(got.header.Values(protocol.RateLimitField))
	if s := rl[protocol.QuotaSends]; s.Left != 0 || s.Cap != 2 {
		t.Fatalf("Dromas-RateLimit %v, want sends left 0 of 2", rl)
	}
	e.limited(e.do("POST", to, e.sealTo(b), e.pass(a)), protocol.QuotaSends)
}

// A shared store that does not answer in time, or at all, is a process
// counting by itself: the send is taken within the store's wait, its count
// is the process's own, and a second failure does not fill it again.
func TestASlowOrDownSharedStoreIsCountedByTheProcess(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { // accepts and never answers: a store that is slow
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := closed.Addr().String()
	_ = closed.Close() // nothing listens: a store that is down

	for _, c := range []struct{ what, addr string }{{"slow", ln.Addr().String()}, {"down", down}} {
		t.Run(c.what, func(t *testing.T) {
			t.Parallel()
			v, err := OpenValkey("valkey://"+c.addr, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			l := relaxed()
			l.SendsPerDay, l.SendsBurst = 1, 1
			e := newEnv(t, l, func(cfg *Config) { cfg.Valkey = v })
			a, b := e.mailbox(), e.mailbox()
			to := "/v1/" + b.Address().String() + "/messages"

			start := time.Now()
			e.want(e.do("POST", to, e.sealTo(b), e.pass(a)), http.StatusCreated, "")
			if took := time.Since(start); took > time.Second {
				t.Fatalf("a send with the store %s took %s", c.what, took)
			}
			e.limited(e.do("POST", to, e.sealTo(b), e.pass(a)), protocol.QuotaSends)
			// Past the retry, the store fails again: the process's count
			// stands.
			e.clock.Add(sharedRetry)
			e.limited(e.do("POST", to, e.sealTo(b), e.pass(a)), protocol.QuotaSends)
		})
	}
}
