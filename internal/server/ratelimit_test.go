package server

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// sendsReported is the sends a send's answer r reports, failing where it
// carries no Dromas-RateLimit whose sends member a client can read.
func sendsReported(t *testing.T, r reply) protocol.Budget {
	t.Helper()
	b, ok := protocol.ParseRateLimit(r.header.Values(protocol.RateLimitField))[protocol.QuotaSends]
	if !ok {
		t.Fatalf("%d with Dromas-RateLimit %q, want a sends member", r.status, r.header.Values(protocol.RateLimitField))
	}
	return b
}

// A send's 201 reports the sender's sends after the call as PROTOCOL.md
// §11.5 has it: what is left, the bucket's size, its refill a day and the
// whole seconds until it is full, rounded up; a token comes back each
// interval; a duplicate's 200 reports the same and spends nothing.
func TestASendsAnswerReportsTheSendersSends(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 50, 60
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	every := day / time.Duration(l.SendsPerDay)
	post := func(ct []byte) reply {
		t.Helper()
		return e.do("POST", to.path("/messages"), to.sealed(1, ct), from.pass(1))
	}
	ct := ciphertextTo(t, to)
	first := post(ct)
	e.want(first, http.StatusCreated, "")
	want := protocol.Budget{Left: 59, Cap: 60, Refill: 50, Window: protocol.DefaultWindow, Full: int64(every / time.Second)}
	if got := sendsReported(t, first); got != want {
		t.Fatalf("the first send reports %+v, want %+v", got, want)
	}
	if got := first.header.Get(protocol.RateLimitField); got != "sends=59;c=60;q=50;f=1728" {
		t.Fatalf("the field is %q, want sends=59;c=60;q=50;f=1728", got)
	}
	again := post(ct)
	e.want(again, http.StatusOK, "")
	if got := sendsReported(t, again); got != want {
		t.Fatalf("a duplicate reports %+v, want %+v, nothing spent", got, want)
	}
	e.clock.Add(time.Second)
	second := post(ciphertextTo(t, to))
	e.want(second, http.StatusCreated, "")
	want.Left, want.Full = 58, int64(2*every/time.Second)-1
	if got := sendsReported(t, second); got != want {
		t.Fatalf("a second send a second later reports %+v, want %+v", got, want)
	}
	e.clock.Add(every)
	third := post(ciphertextTo(t, to))
	e.want(third, http.StatusCreated, "")
	if got := sendsReported(t, third); got.Left != 58 {
		t.Fatalf("a send an interval later reports %+v, want 58 left: one came back", got)
	}
}

// A sender whose sends are not limited gets no Dromas-RateLimit, and no
// answer but a send's ever carries it: not a lookup, a list, a fetch or a
// refusal (PROTOCOL.md §11.5).
func TestOnlyALimitedSendsAnswerReportsSends(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	r := e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1))
	e.want(r, http.StatusCreated, "")
	if v := r.header.Values(protocol.RateLimitField); len(v) > 0 {
		t.Fatalf("a send with no sends a day reports %q", v)
	}

	l := relaxed()
	l.SendsPerDay, l.SendsBurst = 1, 1
	e = newEnv(t, l)
	from, to = e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1)), http.StatusCreated, "")
	for _, c := range []struct {
		what string
		r    reply
	}{
		{"a refused send", e.do("POST", to.path("/messages"), to.sealed(1, ciphertextTo(t, to)), from.pass(1))},
		{"a lookup", e.do("GET", to.path(""), nil, "")},
		{"a list", e.do("GET", to.path("/messages"), nil, to.pass(1))},
		{"the sender's list", e.do("GET", from.path("/messages"), nil, from.pass(1))},
	} {
		if v := c.r.header.Values(protocol.RateLimitField); len(v) > 0 {
			t.Errorf("%s (%d) reports %q", c.what, c.r.status, v)
		}
	}
}

// A lookup's 200 carries a weak ETag, the same gzipped or not; a lookup whose
// If-None-Match names it, weakly or strongly, is 304 with the tag, Vary and
// no content; another tag, or none, is the 200; the tag changes with the
// answer, at a renewal (PROTOCOL.md §11.8).
func TestALookupCarriesAWeakTagAndIs304ToIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	url := e.srv.URL + b.path("")
	plain, body := rawCall(t, http.MethodGet, url)
	tag := plain.Header.Get("ETag")
	if plain.StatusCode != http.StatusOK || len(tag) < 4 || tag[:3] != `W/"` {
		t.Fatalf("a lookup: %d with ETag %q, want 200 with a weak tag", plain.StatusCode, tag)
	}
	if zipped, _ := rawCall(t, http.MethodGet, url, "Accept-Encoding", "gzip"); zipped.Header.Get("Content-Encoding") != "gzip" || zipped.Header.Get("ETag") != tag {
		t.Fatalf("a gzipped lookup: %q with ETag %q, want gzip with %q", zipped.Header.Get("Content-Encoding"), zipped.Header.Get("ETag"), tag)
	}
	for _, inm := range []string{tag, tag[2:], `"other", ` + tag} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			resp, got := rawCall(t, method, url, "If-None-Match", inm)
			if resp.StatusCode != http.StatusNotModified || resp.Header.Get("ETag") != tag || !varies(resp) || len(got) != 0 {
				t.Errorf("%s with If-None-Match %q: %d, ETag %q, Vary %q, %d bytes; want 304 with %q and no content", method, inm, resp.StatusCode, resp.Header.Get("ETag"), resp.Header.Values("Vary"), len(got), tag)
			}
		}
	}
	if resp, got := rawCall(t, http.MethodGet, url, "If-None-Match", `W/"other"`); resp.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatalf("a lookup naming another tag: %d, want the 200", resp.StatusCode)
	}
	b.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", b.path("/prekey"), b.upload(2), b.pass(2)), http.StatusOK, "")
	resp, _ := rawCall(t, http.MethodGet, url, "If-None-Match", tag)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") == tag || resp.Header.Get("ETag") == "" {
		t.Fatalf("a lookup after a renewal naming the old tag: %d with ETag %q, want 200 with a new tag", resp.StatusCode, resp.Header.Get("ETag"))
	}
	gone := e.raw()
	if resp, _ := rawCall(t, http.MethodGet, e.srv.URL+gone.path(""), "If-None-Match", "*"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a lookup of no mailbox with If-None-Match *: %d, want 404", resp.StatusCode)
	}
}
