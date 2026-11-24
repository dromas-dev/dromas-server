package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Every answer under /v1/ but a 304, a refusal among them, carries the
// headers that tell a browser it is no page (apiHeaders); a 304, a list's or
// a mailbox's read's, carries none of them.
func TestEveryAPIAnswerTellsABrowserItIsNoPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	to := e.raw().register(protocol.MaxPrekeyLifetime)
	list := e.do("GET", to.path("/messages"), nil, to.pass(1))
	read := e.do("GET", to.path(""), nil, "")
	answers := map[string]reply{
		"a mailbox's read":    read,
		"a list":              list,
		"a list with no pass": e.do("GET", to.path("/messages"), nil, ""),
		"not an address":      e.do("GET", "/v1/x_nope", nil, ""),
		"no route":            e.do("GET", "/v1/nope", nil, ""),
	}
	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	}
	for name, r := range answers {
		for h, v := range want {
			if got := r.header.Get(h); got != v {
				t.Errorf("%s (%d): %s is %q, want %q", name, r.status, h, got, v)
			}
		}
	}
	notModified := map[string]reply{
		"a list's 304":           e.doWith("GET", to.path("/messages"), nil, to.pass(1), "If-None-Match", list.header.Get("ETag")),
		"a mailbox's read's 304": e.doWith("GET", to.path(""), nil, "", "If-None-Match", "*"),
	}
	for name, r := range notModified {
		e.want(r, http.StatusNotModified, "")
		for _, f := range apiHeaderFields {
			if got := r.header.Values(f[0]); len(got) > 0 {
				t.Errorf("%s: carries %s %q", name, f[0], got)
			}
		}
		if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Date") == "" {
			t.Errorf("%s: lacks what RFC 9110 §15.4.5 has a 304 carry: %v", name, r.header)
		}
	}
}

// The link page's policy allows its one style element by its hash, and
// nothing inline else.
func TestTheLinkPagesPolicyNamesItsStyleByItsHash(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.do("GET", "/to/"+"d_"+strings.Repeat("ab", 32), nil, "")
	e.want(r, http.StatusOK, "")
	csp := r.header.Get("Content-Security-Policy")
	_, rest, _ := strings.Cut(string(r.body), "<style>")
	style, _, ok := strings.Cut(rest, "</style>")
	sum := sha256.Sum256([]byte(style))
	if !ok || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatalf("the page's policy %q does not name its served style by its hash", csp)
	}
	if r.header.Get("Cross-Origin-Opener-Policy") != "same-origin" || r.header.Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatalf("the page's cross-origin policies: %v", r.header)
	}
}

// No answer is compressed, however the request takes gzip, and none says it
// varies by Accept-Encoding (PROTOCOL.md §15.8): not a mailbox's read, with
// its own length, nor a list, though one of three messages is long enough
// to gain from it, a fetch, an error, an owner's read or the link page.
func TestNoAnswerIsCompressed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to := e.mailbox(), e.mailbox()
	r := send(t, from, to, strings.Repeat("the same words again ", 200))
	send(t, from, to, "a second")
	send(t, from, to, "a third, so that the list is long enough to compress")
	pass := e.pass(to)
	none := make([]byte, 32)
	_, _ = rand.Read(none)
	base := e.srv.URL + "/v1/" + to.Address().String()
	for _, c := range []struct {
		path, pass string
		status     int
	}{
		{"", "", http.StatusOK},
		{"/messages", pass, http.StatusOK},
		{"/messages/" + r.ID, pass, http.StatusOK},
		{"/acl", pass, http.StatusOK},
		{"/revocation", "", http.StatusNotFound},
		{"/messages", "", http.StatusUnauthorized},
	} {
		resp, got := rawCall(t, http.MethodGet, base+c.path, "Accept-Encoding", "gzip", "Authorization", c.pass)
		if resp.StatusCode != c.status || resp.Header.Get("Content-Encoding") != "" || varies(resp) {
			t.Errorf("%q: %d in %q, Vary %q, want %d as it is: %.80q", c.path, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"), c.status, got)
		}
		if c.path == "" && resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) {
			t.Errorf("a mailbox's read: Content-Length %q of %d bytes", resp.Header.Get("Content-Length"), len(got))
		}
	}
	for _, path := range []string{"/v1/" + hex.EncodeToString(none), protocol.LinkPath + to.Address().String()} {
		resp, got := rawCall(t, http.MethodGet, e.srv.URL+path, "Accept-Encoding", "gzip")
		if resp.Header.Get("Content-Encoding") != "" || varies(resp) {
			t.Errorf("%s: %d in %q, Vary %q, want it as it is: %.80q", path, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"), got)
		}
	}
}
