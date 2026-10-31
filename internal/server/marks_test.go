package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A first page carries an ETag, the first 16 bytes of the SHA-256 of its
// body, and a poll that sends it back is 304 while the page is unchanged
// (PROTOCOL.md §11.11). The tag is the page's own: every process computes it
// alike, with no key, and an empty mailbox's is the same on every server. A tag
// of the page before, the "<count>-<version>" form among them, is not
// the page's. Weak comparison: W/ is read past, and * names any page. A page
// after the first carries none, so no tag names it, and only * makes it 304
// (dromas-dev/dromas-server#86). Every answer carries the poll interval
// in Retry-After, a 304's too.
func TestAFirstPageIsNotModifiedWhileUnchanged(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(query, ifNoneMatch string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages")+query, nil)
		req.Header.Set("Authorization", to.pass(1))
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if got := resp.Header.Get("Retry-After"); got != strconv.Itoa(l.PollAfter) {
			t.Errorf("If-None-Match %q: %d with Retry-After %q, want %d", ifNoneMatch, resp.StatusCode, got, l.PollAfter)
		}
		return resp, body
	}
	const emptyPage = `{"count":0,"messages":[],"next_cursor":null}` + "\n"
	sum := sha256.Sum256([]byte(emptyPage))
	emptyTag := `"` + hex.EncodeToString(sum[:16]) + `"`
	resp, body := poll("", "")
	if resp.StatusCode != http.StatusOK || string(body) != emptyPage || resp.Header.Get("ETag") != emptyTag {
		t.Fatalf("an empty mailbox: %d %q, ETag %q, want 200 %q with the page's hash, %s", resp.StatusCode, body, resp.Header.Get("ETag"), emptyPage, emptyTag)
	}
	for _, tag := range []string{emptyTag, "W/" + emptyTag, `"other", ` + emptyTag, "*"} {
		if resp, body := poll("", tag); resp.StatusCode != http.StatusNotModified || len(body) != 0 || resp.Header.Get("ETag") != emptyTag {
			t.Errorf("an empty mailbox, If-None-Match %q: %d %q, ETag %q, want 304 with no body", tag, resp.StatusCode, body, resp.Header.Get("ETag"))
		}
	}
	// A comma and a "*" are a tag's own characters (RFC 9110 §8.8.3): a tag
	// that holds them is one tag, and so is "*" among tags no page's.
	planted := []string{`",*,"`, `"x,*,y"`, `W/"a,W/*,b"`, emptyTag[:len(emptyTag)-1] + `,x"`, emptyTag + `, *`, emptyTag + ` junk`}
	for _, tag := range append([]string{`"0-0000000000000000"`, `"` + strings.Repeat("0", 32) + `"`, emptyTag[1 : len(emptyTag)-1]}, planted...) {
		if resp, _ := poll("", tag); resp.StatusCode != http.StatusOK {
			t.Errorf("an empty mailbox, If-None-Match %q: %d, want 200", tag, resp.StatusCode)
		}
	}
	const n = 3
	for range n {
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		e.want(e.do(http.MethodPost, to.path("/messages"), to.sealed(1, ct.Bytes()), from.pass(1)), http.StatusCreated, "")
	}
	resp, body = poll("", emptyTag)
	var list protocol.MessageList
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || list.Count != n || len(list.Messages) != n {
		t.Fatalf("a mailbox holding %d, sent the empty mailbox's tag: %d %s, want 200 with the messages", n, resp.StatusCode, body)
	}
	held := resp.Header.Get("ETag")
	if sum := sha256.Sum256(body); held != `"`+hex.EncodeToString(sum[:16])+`"` || held == emptyTag {
		t.Fatalf("a mailbox holding %d: ETag %q, want its page's hash", n, held)
	}
	if resp, _ := poll("", held); resp.StatusCode != http.StatusNotModified {
		t.Errorf("a mailbox holding %d, sent its own page's tag: %d, want 304", n, resp.StatusCode)
	}
	// A cursor after every message: a poll, answered with an empty page that
	// is not the first, so untagged, and 304 only to *, which names any page.
	last := formatCursor(Header{ReceivedAt: e.clock.Now().Add(time.Hour)})
	for tag, status := range map[string]int{"": http.StatusOK, "*": http.StatusNotModified, held: http.StatusOK} {
		if resp, _ := poll("?cursor="+last, tag); resp.StatusCode != status || resp.Header.Get("ETag") != "" {
			t.Errorf("a page after the first, If-None-Match %q: %d, ETag %q, want %d and none", tag, resp.StatusCode, resp.Header.Get("ETag"), status)
		}
	}
}

// A poll's If-Match is evaluated first, as RFC 9110 §13.1.1 and §13.2.2 have
// an origin server evaluate one, and compared strongly: a false one is 412
// precondition_failed, before If-None-Match is read, and a page after the
// first, which carries no tag, matches none but "*"
// (dromas-dev/dromas-server#71). It comes after the poll's count, as
// If-None-Match does: a mailbox past its poll rate is refused 429 whatever it
// sends.
func TestAPollsIfMatchIsEvaluatedFirst(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MailboxCap = 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	var ct bytes.Buffer
	w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	e.want(e.do(http.MethodPost, to.path("/messages"), to.sealed(1, ct.Bytes()), from.pass(1)), http.StatusCreated, "")
	poll := func(e *env, query string, headers ...string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages")+query, nil)
		req.Header.Set("Authorization", to.pass(1))
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var p protocol.Problem
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &p)
		return resp.StatusCode, string(p.Code)
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages"), nil)
	req.Header.Set("Authorization", to.pass(1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	tag := resp.Header.Get("ETag")
	last := formatCursor(Header{ReceivedAt: e.clock.Now().Add(time.Hour)})
	for _, c := range []struct {
		query   string
		headers []string
		status  int
	}{
		{"", []string{"If-Match", tag}, http.StatusOK},
		{"", []string{"If-Match", "*"}, http.StatusOK},
		{"", []string{"If-Match", `"other", ` + tag}, http.StatusOK},
		{"", []string{"If-Match", `"other"`}, http.StatusPreconditionFailed},
		{"", []string{"If-Match", "W/" + tag}, http.StatusPreconditionFailed},
		{"", []string{"If-Match", "junk"}, http.StatusPreconditionFailed},
		{"", []string{"If-Match", tag, "If-None-Match", tag}, http.StatusNotModified},
		{"", []string{"If-Match", `"other"`, "If-None-Match", tag}, http.StatusPreconditionFailed},
		{"?cursor=" + last, []string{"If-Match", tag}, http.StatusPreconditionFailed},
		{"?cursor=" + last, []string{"If-Match", "*"}, http.StatusOK},
	} {
		status, code := poll(e, c.query, c.headers...)
		if status != c.status || status == http.StatusPreconditionFailed && code != string(protocol.CodePreconditionFailed) {
			t.Errorf("%s %q: %d %s, want %d", c.query, c.headers, status, code, c.status)
		}
	}
	l.PollBurst, l.PollRefill = 1, time.Hour
	past := newEnv(t, l)
	to = past.raw().register(protocol.MaxPrekeyLifetime)
	if status, _ := poll(past, ""); status != http.StatusOK {
		t.Fatalf("the one poll: %d", status)
	}
	if status, code := poll(past, "", "If-Match", `"other"`); status != http.StatusTooManyRequests {
		t.Errorf("past the poll rate, with a false If-Match: %d %s, want 429", status, code)
	}
}

// A 304 is a poll: it takes from the poll rate, and a mailbox that polls faster is
// refused 429, never answered 304, whatever it sends (PROTOCOL.md §11.11).
func TestA304IsAPoll(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill = 2, time.Hour
	e := newEnv(t, l)
	to := e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(tag string) reply {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages"), nil)
		req.Header.Set("Authorization", to.pass(1))
		if tag != "" {
			req.Header.Set("If-None-Match", tag)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return reply{status: resp.StatusCode, header: resp.Header, body: b}
	}
	first := poll("")
	tag := first.header.Get("ETag")
	if first.status != http.StatusOK || tag == "" {
		t.Fatalf("the first poll: %d, ETag %q", first.status, tag)
	}
	if r := poll(tag); r.status != http.StatusNotModified {
		t.Fatalf("the second poll, inside the rate: %d, want 304", r.status)
	}
	if r := poll(tag); r.status != http.StatusTooManyRequests || r.code() != protocol.CodeRateLimited || r.header.Get("Retry-After") == "" {
		t.Fatalf("a poll past the rate, with the page's tag: %d %s, want 429 rate_limited with Retry-After", r.status, r.body)
	}
}

// An id that shares a held message's first 8 bytes is not that message: its
// fetch and its ack are 404 from memory, and touch no storage.
func TestAnIDThatSharesAPrefixIsNotHeld(t *testing.T) {
	t.Parallel()
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "held")
	e2, cs := counted(t, e, l)
	pass := e2.pass(b)
	list := listOf(t, e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass))
	if len(list.Messages) != 1 {
		t.Fatalf("listed %d", len(list.Messages))
	}
	real, _ := hex.DecodeString(list.Messages[0].ID)
	forged := append([]byte{}, real[:8]...)
	tail := make([]byte, 24)
	_, _ = rand.Read(tail)
	forged = append(forged, tail...)
	path := "/v1/" + b.Address().String() + "/messages/" + hex.EncodeToString(forged)
	before := cs.calls.Load()
	for range 5 {
		e2.want(e2.do(http.MethodDelete, path, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
		e2.want(e2.do(http.MethodGet, path, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
	}
	if n := cs.calls.Load(); n != before {
		t.Fatalf("%d storage calls for an id that only shares a held message's prefix", n-before)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("the held message: delivered %d", len(res.Delivered))
	}
}

// tagFront stands between a mailbox and the server. While plant is set, it gives a
// 200 to a first-page poll the tag plant in place of the page's own; after,
// it records each first-page poll's status.
type tagFront struct {
	mu     sync.Mutex
	plant  string
	status []int
	asked  []string // each poll's If-None-Match
}

func (f *tagFront) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/messages") || r.URL.RawQuery != "" {
		next.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	maps.Copy(w.Header(), rec.Header())
	f.mu.Lock()
	f.asked = append(f.asked, r.Header.Get("If-None-Match"))
	if f.plant != "" && rec.Code == http.StatusOK {
		w.Header().Set("ETag", f.plant)
	} else {
		f.status = append(f.status, rec.Code)
	}
	f.mu.Unlock()
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (f *tagFront) honest() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plant = ""
}

// A tag a hostile server hands an empty mailbox once is one tag to this server,
// whatever commas and "*" it holds: the mailbox's polls are answered in full while
// it keeps that tag, and the messages sent after are delivered
// (dromas-dev/dromas-client#149).
func TestAPlantedTagHidesNoMessageAtAnHonestServer(t *testing.T) {
	t.Parallel()
	for _, plant := range []string{`",*,"`, `"x,*,y"`, `W/"a,W/*,b"`} {
		e := newEnv(t, relaxed())
		a, b := e.mailbox(), e.mailbox()
		f := &tagFront{plant: plant}
		e.setMiddle(f.serve)
		receive(t, b) // the one hostile answer: the mailbox is empty, and only the tag is the front's
		f.honest()
		send(t, a, b, "one")
		send(t, a, b, "two")
		got := 0
		for range 4 {
			e.clock.Add(2 * time.Minute)
			got += len(receive(t, b).Delivered)
		}
		n, _ := e.store.Count(context.Background(), b.Address())
		if len(f.asked) < 2 || f.asked[1] != plant {
			t.Fatalf("the poll after the planted tag sent %q, want the planted %s", f.asked, plant)
		}
		if got != 2 || f.status[0] != http.StatusOK || n != 0 {
			t.Errorf("with %s kept: polls answered %v, delivered %d of 2, the server holds %d", plant, f.status, got, n)
		}
	}
}

// Nor is that message lost to the renewals the mailbox makes meanwhile, which retire
// the prekey it was sealed to.
func TestAMessageHiddenByAPlantedTagIsNotLost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	f := &tagFront{plant: `",*,"`}
	e.setMiddle(f.serve)
	receive(t, b)
	f.honest()
	send(t, a, b, "sealed to the prekey current now")
	got := 0
	for range 3 { // a day apart: each drain renews, and drops retired prekeys
		e.clock.Add(25 * time.Hour)
		got += len(receive(t, b).Delivered)
	}
	if got != 1 {
		t.Errorf("polls answered %v, delivered %d of 1", f.status, got)
	}
}
