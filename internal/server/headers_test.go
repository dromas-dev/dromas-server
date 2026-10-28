package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Every answer under /v1/, a refusal and a 304 among them, carries the
// headers that tell a browser it is no page (apiHeaders).
func TestEveryAPIAnswerTellsABrowserItIsNoPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	to := e.raw().register(protocol.MaxPrekeyLifetime)
	list := e.do("GET", to.path("/messages"), nil, to.pass(1))
	answers := map[string]reply{
		"a box's read":        e.do("GET", to.path(""), nil, ""),
		"a list":              list,
		"a list's 304":        e.doWith("GET", to.path("/messages"), nil, to.pass(1), "If-None-Match", list.header.Get("ETag")),
		"a list with no pass": e.do("GET", to.path("/messages"), nil, ""),
		"not an address":      e.do("GET", "/v1/nope", nil, ""),
	}
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Opener-Policy":   "same-origin",
	}
	for name, r := range answers {
		for h, v := range want {
			if got := r.header.Get(h); got != v {
				t.Errorf("%s (%d): %s is %q, want %q", name, r.status, h, got, v)
			}
		}
	}
}

// The link page's policy allows its one style element by its hash, and
// nothing inline else.
func TestTheLinkPagesPolicyNamesItsStyleByItsHash(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.do("GET", "/to/"+strings.Repeat("ab", 32), nil, "")
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
