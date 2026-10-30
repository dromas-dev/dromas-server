package server

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	htmltemplate "html/template"
	"net/http"
	"strings"

	"github.com/dromas-dev/dromas-client/protocol"
)

// The one page of this server's own outside /v1/: the page a mailbox's link
// opens (PROTOCOL.md §4.3). It needs no store, so it is served while the
// API still answers 503. A site's pages, when there is one, are a
// deployment's (site.go).

// pageMaxAge bounds how long a cache and clients keep the page after a
// deploy changes it.
const pageMaxAge = "public, max-age=300"

//go:embed to.html
var toHTML string

// linkCSP is the link page's policy: nothing but its one style element,
// named by its hash (CSP Level 3 §8.2), so no inline style or script an
// injection could add would run, no base, form or frame.
var linkCSP = func() string {
	_, rest, _ := strings.Cut(toHTML, "<style>")
	style, _, ok := strings.Cut(rest, "</style>")
	if !ok {
		panic("to.html has no style element")
	}
	sum := sha256.Sum256([]byte(style))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

// linkPage serves the page a mailbox's link opens, <server>/to/<address>: what
// dromas is, for whoever was handed the link. It is fixed text, the
// address and the link itself, never text a mailbox supplied, for any 64
// lowercase hex characters, the form clients take; it reads no store, so it
// answers before the API is ready. The link is a send capability: the page
// keeps it out of Referer headers and search engines.
func (s *Server) linkPage() http.Handler {
	t := htmltemplate.Must(htmltemplate.New("to.html").Option("missingkey=error").Parse(toHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := protocol.ParseAddress(r.PathValue("addr"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// The page exists for every address and carries no tag
		// (precondition); a 304 carries how long a cache may keep it (RFC
		// 9110 §15.4.5). Its call was counted at the gate.
		if err := precondition(r, targetState{exists: true, hint: hintConditions, also: []string{"Cache-Control", pageMaxAge}}); err != nil {
			writeConditions(w, err)
			return
		}
		var b bytes.Buffer
		if err := t.Execute(&b, struct{ Addr, Link string }{a.String(), s.linkBase(r) + protocol.LinkPath + a.String()}); err != nil {
			http.Error(w, "the page did not render", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex")
		h.Set("Content-Security-Policy", linkCSP)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", pageMaxAge)
		h.Set("X-Content-Type-Options", "nosniff")
		w.Write(b.Bytes()) //nolint:errcheck,gosec // the client went away
	})
}

// linkBase is this server as a mailbox's link names it: by the scheme the caller
// reached it by, and by the name the caller called it by when that is one of
// its own (serverName), as a client's base URL names it; called by any other
// name, by the first of its own. So each server's page names that server,
// and never one a request made up.
func (s *Server) linkBase(r *http.Request) string {
	name, ours := s.serverName(r)
	if !ours {
		name = s.names[0] // with no names configured, every name is ours
	}
	return s.scheme(r) + "://" + name
}

// scheme is the scheme the caller reached this server by: https over TLS to
// this server, or what a trusted proxy says in X-Forwarded-Proto, which TLS
// ending in front sets to the scheme its client used, overwriting a client's
// own; otherwise http. From any other peer the header is ignored, as
// X-Forwarded-For is.
func (s *Server) scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if s.fromProxy(r) {
		first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
		if p := protocol.LowerASCII(strings.TrimSpace(first)); p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}
