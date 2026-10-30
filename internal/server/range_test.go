package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// rangeStore is the test store, keeping what each read of a message's body
// asked for and got: where it began, and how many bytes came.
type rangeStore struct {
	Store
	mu    sync.Mutex
	reads [][2]int64
}

func (s *rangeStore) Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, body, err := s.Store.Message(ctx, mailbox, id, from)
	s.mu.Lock()
	s.reads = append(s.reads, [2]int64{from, int64(len(body))})
	s.mu.Unlock()
	return h, body, err
}

// last is the last read of a body: where it began and how many bytes came.
func (s *rangeStore) last() [2]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads[len(s.reads)-1]
}

// ranged is a server on e's store, wrapped to keep each read of a body,
// with limits l.
func ranged(t *testing.T, e *env, l Limits) (*env, *rangeStore) {
	t.Helper()
	rs := &rangeStore{Store: e.store}
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: rs, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	return &env{t: t, clock: e.clock, srv: srv}, rs
}

// A fetch that was cut resumes by range (PROTOCOL.md §11.12): Range: bytes=N-,
// N inside the ciphertext, is answered 206 with the bytes from N on and a
// Content-Range that says so, read from the store from N, and every other
// Range, an If-Range beside one included, with the whole body, 200, read
// whole. No answer is 416.
func TestAFetchResumesByRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	e2, rs := ranged(t, e, relaxed())
	tok := e2.pass(b)
	path := "/v1/" + b.Address().String() + "/messages/" + send(t, a, b, "read in two parts").ID
	r := e2.do(http.MethodGet, path, nil, tok)
	e2.want(r, http.StatusOK, "")
	whole := r.body
	size := int64(len(whole))
	if got := rs.last(); got != [2]int64{0, size} {
		t.Fatalf("a fetch with no range read %v of the body", got)
	}
	for _, from := range []int64{size / 2, 1, size - 1, 0} {
		r := e2.doWith(http.MethodGet, path, nil, tok, "Range", protocol.RangeAsk(from))
		e2.want(r, http.StatusPartialContent, "")
		if got := r.header.Get("Content-Range"); got != protocol.ContentRange(from, size) {
			t.Errorf("bytes=%d-: Content-Range %q, want %q", from, got, protocol.ContentRange(from, size))
		}
		if !bytes.Equal(r.body, whole[from:]) || r.header.Get("Content-Length") != strconv.FormatInt(size-from, 10) {
			t.Errorf("bytes=%d-: %d bytes, Content-Length %s; want the %d from there on", from, len(r.body), r.header.Get("Content-Length"), size-from)
		}
		if got := rs.last(); got != [2]int64{from, size - from} {
			t.Errorf("bytes=%d-: the store read %v, want from %d, %d bytes", from, got, from, size-from)
		}
	}
	// The unit is read in any ASCII case (RFC 9110 §5.6.2, §14.1).
	if r := e2.doWith(http.MethodGet, path, nil, tok, "Range", "BYTES=5-"); r.status != http.StatusPartialContent {
		t.Errorf("BYTES=5-: %d, want 206", r.status)
	}
	for _, hdr := range [][]string{
		{"Range", "bytes=1-" + strconv.FormatInt(size-1, 10)},
		{"Range", "bytes=-5"},
		{"Range", "bytes=0-,5-"},
		{"Range", protocol.RangeAsk(size)},
		{"Range", protocol.RangeAsk(size + 5)},
		{"Range", "bytes=99999999999999999999999-"},
		{"Range", "items=5-"},
		// A unit is a token, ASCII: U+017F is no s, though Unicode folds it
		// to one (dromas-dev/dromas-client#405).
		{"Range", "byte\u017f=5-"},
		{"Range", "bytes=5-", "If-Range", `"x"`},
		{"Range", "bytes=5-", "If-Range", "Sun, 18 Oct 2026 00:00:00 GMT"},
		{"Range", "bytes=5-", "Range", "bytes=6-"},
	} {
		r := e2.doWith(http.MethodGet, path, nil, tok, hdr...)
		e2.want(r, http.StatusOK, "")
		if !bytes.Equal(r.body, whole) || r.header.Get("Content-Range") != "" {
			t.Errorf("%q: %d bytes, Content-Range %q; want the whole body", hdr, len(r.body), r.header.Get("Content-Range"))
		}
		if got := rs.last(); got[1] != size {
			t.Errorf("%q: the store read %v, want the whole body", hdr, got)
		}
	}
}

// A ranged fetch is counted as any fetch is (PROTOCOL.md §11.12): a fetch of a
// message fetched before, ranged or not, takes from the mailbox's allowance of
// repeats, and past it is 429 refetch_spent.
func TestARangedFetchIsCountedAsAnyFetch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	l := relaxed()
	l.PollBurst, l.PollRefill = 1, time.Minute
	e2, _ := ranged(t, e, l)
	tok := e2.pass(b)
	path := "/v1/" + b.Address().String() + "/messages/" + send(t, a, b, "cut, then resumed").ID
	e2.want(e2.do(http.MethodGet, path, nil, tok), http.StatusOK, "")
	e2.want(e2.doWith(http.MethodGet, path, nil, tok, "Range", protocol.RangeAsk(10)), http.StatusPartialContent, "")
	e2.want(e2.doWith(http.MethodGet, path, nil, tok, "Range", protocol.RangeAsk(20)), http.StatusTooManyRequests, protocol.CodeRefetchSpent)
}
