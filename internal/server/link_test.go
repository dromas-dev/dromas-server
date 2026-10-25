package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
)

// With no site, outside /v1/ the server has the link page and nothing else.
func TestNoPagesButTheLinkPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Ready: func() bool { return false }}).Handler()))
	defer srv.Close()
	for _, p := range []string{"/", "/llms.txt", "/docs/", "/docs", "/index.html", "/to.html", "/nope"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/v1/" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("the API while not ready: %d", resp.StatusCode)
	}
}

// A box's link opens a page for any 64 lowercase hex characters, the form
// clients take, while the API is still 503: fixed text, the address and the
// link, kept out of Referer headers and search engines. Anything else is
// 404. A server with no names of its own (the dev server's) names itself as
// the request does.
func TestLinkPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Ready: func() bool { return false }}).Handler()))
	defer srv.Close()
	get := func(method, path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	a := strings.Repeat("0a", 32)
	resp, body := get(http.MethodGet, "/to/"+a)
	h := resp.Header
	if resp.StatusCode != http.StatusOK || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Cache-Control") != pageMaxAge ||
		h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Robots-Tag") != "noindex" || !strings.HasPrefix(h.Get("Content-Security-Policy"), "default-src 'none';") {
		t.Fatalf("GET /to/<address>: %d %v", resp.StatusCode, h)
	}
	for _, want := range []string{"<code>" + a + "</code>", "echo hello | dromas send " + srv.URL + "/to/" + a + "</code>", `<meta property="og:url" content="` + srv.URL + "/to/" + a + `">`, `<meta name="robots" content="noindex">`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "{{") {
		t.Error("the page has template text left in it")
	}
	if resp, body := get(http.MethodHead, "/to/"+a); resp.StatusCode != http.StatusOK || body != "" {
		t.Errorf("HEAD: %d %q", resp.StatusCode, body)
	}
	// A shared link picks up a query, and the page is the same page.
	if resp, got := get(http.MethodGet, "/to/"+a+"?utm_source=chat&x=1"); resp.StatusCode != http.StatusOK || got != body {
		t.Errorf("GET /to/<address> with a query: %d, the same page %v", resp.StatusCode, got == body)
	}
	if resp, _ := get(http.MethodPost, "/to/"+a); resp.StatusCode == http.StatusOK {
		t.Error("POST: 200")
	}
	for _, p := range []string{"/to/" + strings.ToUpper(a), "/to/" + a[:63], "/to/" + a + "0", "/to/" + a + "/", "/to/", "/to/%3Cscript%3E" + a[13:]} {
		if resp, body := get(http.MethodGet, p); resp.StatusCode != http.StatusNotFound || strings.Contains(body, "dromas send") {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
}

// The page names the server that serves it, never one server for all: by
// the name the request calls it by when that is one of its own, and else by
// the first of them, and by the scheme the caller reached it by, which a
// trusted proxy in front says in X-Forwarded-Proto and nobody else can.
func TestTheLinkPageNamesItsOwnServer(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		proxies []netip.Prefix
		host    string
		proto   string
		want    string
	}{
		{"its own name, through TLS in front", loopback, "mail.example", "https", "https://mail.example"},
		{"its other name, with a port", loopback, "mail.example:8443", "https", "https://mail.example:8443"},
		{"the default port left out, in any case", loopback, "MAIL.example:443", "HTTPS", "https://mail.example"},
		{"plain http in front", loopback, "mail.example", "http", "http://mail.example"},
		{"a scheme that is neither", loopback, "mail.example", "gopher", "http://mail.example"},
		{"the first of a list", loopback, "mail.example", "https, http", "https://mail.example"},
		{"a name not its own", loopback, "evil.example", "https", "https://mail.example"},
		{"no proxy is trusted", nil, "mail.example", "https", "http://mail.example"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Limits: relaxed(),
				Names: []string{"mail.example", "mail.example:8443"}, TrustedProxies: c.proxies}).Handler()))
			defer srv.Close()
			a := strings.Repeat("0a", 32)
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/to/"+a, nil)
			req.Host = c.host
			req.Header.Set("X-Forwarded-Proto", c.proto)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			link := c.want + "/to/" + a
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "<code>echo hello | dromas send "+link+"</code>") ||
				!strings.Contains(string(b), `<meta property="og:url" content="`+link+`">`) {
				t.Errorf("the page does not name %s:\n%s", link, b)
			}
		})
	}
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// The page's command is the client README's: the echo box's link renders to
// a line of the README, at the address the client code carries, on a server
// called dromas.dev through TLS in front of it.
func TestLinkPageCommandIsInTheClientREADME(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Names: []string{"dromas.dev"}, TrustedProxies: loopback}).Handler()))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/to/"+client.EchoAddress, nil)
	req.Host = "dromas.dev"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	readme, err := os.ReadFile("../../../dromas-client/README.md")
	if err != nil {
		t.Fatal(err)
	}
	line := "echo hello | dromas send https://dromas.dev/to/" + client.EchoAddress
	if !strings.Contains(string(b), "<code>"+line+"</code>") || !strings.Contains(string(readme), "\n"+line+"\n") {
		t.Errorf("the page and the README do not both give %q", line)
	}
}
