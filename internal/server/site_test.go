package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// siteFiles is a site a backend serves: the front page, a page at a path of
// its own, and an index in a directory.
var siteFiles = map[string]string{
	"index.html":      "<!doctype html><title>front</title>",
	"llms.txt":        "what an agent reads first\n",
	"docs/index.html": "<!doctype html><title>docs</title>",
}

func writeSite(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// siteBackend is a deployment's web server, serving files as a static file
// server does, and its URL.
func siteBackend(t *testing.T, files map[string]string) *url.URL {
	t.Helper()
	return backendOf(t, http.FileServer(http.Dir(writeSite(t, files))))
}

// backendOf serves h as a site's web server, and returns its URL.
func backendOf(t *testing.T, h http.Handler) *url.URL {
	t.Helper()
	b := httptest.NewServer(h)
	t.Cleanup(b.Close)
	u, err := SiteBackend(b.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// siteServer is a server with the site above, and ready as given: the API
// answers 503 until it is.
func siteServer(t *testing.T, l Limits, ready bool) *httptest.Server {
	t.Helper()
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, SiteBackend: siteBackend(t, siteFiles), Ready: func() bool { return ready }})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, method, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	return request(t, srv, method, path, nil, hdr...)
}

// request sends one request with the headers named, Host among them, and
// follows no redirect.
func request(t *testing.T, srv *httptest.Server, method, path string, body io.Reader, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// seen is what a site's web server was asked: a request's method, its
// target as written, its Host, its headers and its body.
type seen struct {
	method, target, host, body string
	header                     http.Header
}

// recorder is a site's web server that answers every request 299, with a
// header and a body of its own, and keeps what it was asked.
type recorder struct {
	mu   sync.Mutex
	asks []seen
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rec.mu.Lock()
	rec.asks = append(rec.asks, seen{r.Method, r.RequestURI, r.Host, string(b), r.Header.Clone()})
	rec.mu.Unlock()
	w.Header().Set("X-Site", "its own")
	w.WriteHeader(299)
	_, _ = io.WriteString(w, "the site's answer to "+r.RequestURI)
}

func (rec *recorder) taken() []seen {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]seen(nil), rec.asks...)
}

// Every request outside /v1/ and /to/ is its site's: passed to the backend
// with its method, its target as written, its body and the Host the client
// asked for, and answered with the backend's status, headers and body, a 404
// among them. Under /v1/ and /to/ nothing is: the API, the link page and
// the router answer there, 404 and 405 among them, and the router sends /v1
// and /to to them.
func TestEveryOtherRequestIsTheSites(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), SiteBackend: backendOf(t, rec)}).Handler())
	t.Cleanup(srv.Close)
	for _, c := range []struct{ method, target, body string }{
		{"GET", "/", ""},
		{"GET", "/docs/?a=1&b=%20", ""},
		{"GET", "/a%2Fb/c%3Fd", ""},
		{"GET", "/nope", ""},
		{"HEAD", "/llms.txt", ""},
		{"POST", "/pay/checkout", `{"plan":"one"}`},
		{"PUT", "/tools", "x"},
		{"DELETE", "/v1x", ""},
	} {
		before := len(rec.taken())
		resp, body := request(t, srv, c.method, c.target, strings.NewReader(c.body), "Host", "dromas.example")
		want := "the site's answer to " + c.target
		if c.method == http.MethodHead {
			want = ""
		}
		if resp.StatusCode != 299 || resp.Header.Get("X-Site") != "its own" || body != want {
			t.Errorf("%s %s: %d %q, headers %v; want the site's 299", c.method, c.target, resp.StatusCode, body, resp.Header)
		}
		asks := rec.taken()
		if len(asks) != before+1 {
			t.Fatalf("%s %s: the site was asked %d times", c.method, c.target, len(asks)-before)
		}
		if a := asks[before]; a.method != c.method || a.target != c.target || a.host != "dromas.example" || a.body != c.body {
			t.Errorf("%s %s: the site was asked %s %s for %q with %q", c.method, c.target, a.method, a.target, a.host, a.body)
		}
	}
	before := len(rec.taken())
	addr := strings.Repeat("a", 64)
	for _, c := range []struct {
		method, target string
		status         int
		code           protocol.Code
	}{
		{"GET", "/v1/" + strings.Repeat("0", 64), http.StatusNotFound, protocol.CodeNoSuchMailbox},
		{"GET", "/v1", http.StatusTemporaryRedirect, ""},
		{"PUT", "/to", http.StatusTemporaryRedirect, ""},
		{"GET", "/v1/nope", http.StatusBadRequest, protocol.CodeBadAddress},
		{"POST", "/v1/", http.StatusNotFound, ""},
		{"GET", protocol.LinkPath + addr, http.StatusOK, ""},
		{"POST", protocol.LinkPath + addr, http.StatusMethodNotAllowed, ""},
		{"GET", protocol.LinkPath, http.StatusNotFound, ""},
		{"GET", protocol.LinkPath + addr + "/more", http.StatusNotFound, ""},
	} {
		resp, body := request(t, srv, c.method, c.target, nil)
		if resp.StatusCode != c.status || resp.Header.Get("X-Site") != "" || !strings.Contains(body, string(c.code)) {
			t.Errorf("%s %s: %d %q, want the server's own %d", c.method, c.target, resp.StatusCode, body, c.status)
		}
	}
	if n := len(rec.taken()) - before; n != 0 {
		t.Errorf("the site was asked %d requests under /v1/ and /to/", n)
	}
}

// The site is told who the client is as the limits read it: X-Forwarded-For
// is the CF-Connecting-IP of a trusted proxy, else the peer, and
// X-Forwarded-Proto a trusted proxy's, else this connection's. What any
// other peer says of the client, in those headers or in Forwarded, is not
// passed on.
func TestTheSiteIsToldTheClientTheLimitsSee(t *testing.T) {
	t.Parallel()
	claims := []string{"CF-Connecting-IP", "203.0.113.9", "X-Forwarded-For", "198.51.100.1", "X-Forwarded-Proto", "https", "Forwarded", "for=192.0.2.1", "Host", "dromas.example"}
	for _, c := range []struct {
		name          string
		proxies       []netip.Prefix
		client, proto string
	}{
		{"from a trusted proxy", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, "203.0.113.9", "https"},
		{"from any other peer", nil, "127.0.0.1", "http"},
	} {
		rec := &recorder{}
		srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), TrustedProxies: c.proxies, SiteBackend: backendOf(t, rec)}).Handler())
		get(t, srv, http.MethodGet, "/", claims...)
		srv.Close()
		asks := rec.taken()
		if len(asks) != 1 {
			t.Fatalf("%s: the site was asked %d times", c.name, len(asks))
		}
		h := asks[0].header
		if h.Get("X-Forwarded-For") != c.client || len(h.Values("X-Forwarded-For")) != 1 || h.Get("X-Forwarded-Proto") != c.proto ||
			h.Get("X-Forwarded-Host") != "dromas.example" || h.Get("Forwarded") != "" {
			t.Errorf("%s: the site was told %v", c.name, h)
		}
	}
}

// A page of the site spends its caller's flood budget, which is for floods
// alone (dromas-dev/dromas-server#58): thirty views of three pages each, a
// 404 among them, from one address at once, are each answered under the
// default limits, while the API is not ready; a flood is refused.
func TestASitePageSpendsOnlyAFloodBudget(t *testing.T) {
	t.Parallel()
	srv := siteServer(t, DefaultLimits(), false)
	if resp, _ := get(t, srv, http.MethodGet, "/v1/"+strings.Repeat("0", 64)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the API before it is ready: %d, want 503", resp.StatusCode)
	}
	for i := range 30 {
		for path, want := range map[string]int{"/": http.StatusOK, "/llms.txt": http.StatusOK, "/nope": http.StatusNotFound} {
			if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode != want {
				t.Fatalf("request %d of %s, with the default limits and the API not ready: %d, want %d", i+1, path, resp.StatusCode, want)
			}
		}
	}
	for range 1000 {
		if resp, _ := get(t, srv, http.MethodGet, "/llms.txt"); resp.StatusCode == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("a thousand pages at once from one address are all answered")
}

// A site's web server that does not answer is a 502.
func TestASiteThatDoesNotAnswerIsABadGateway(t *testing.T) {
	t.Parallel()
	gone := httptest.NewServer(http.NotFoundHandler())
	u, err := SiteBackend(gone.URL)
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), SiteBackend: u}).Handler())
	t.Cleanup(srv.Close)
	if resp, _ := get(t, srv, http.MethodGet, "/"); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("a site that does not answer: %d, want 502", resp.StatusCode)
	}
}

// With no site, every path outside /v1/ and the link page is 404.
func TestNoSiteIsNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed()}).Handler())
	t.Cleanup(srv.Close)
	for _, path := range []string{"/", "/llms.txt"} {
		if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s with no site: %d, want 404", path, resp.StatusCode)
		}
	}
}

// A site's web server is named by http or https and a host alone.
func TestASiteBackendIsASchemeAndAHost(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"http://site:8080":     "http://site:8080",
		"https://site.example": "https://site.example",
		"http://site/":         "http://site",
		"http://[::1]:80":      "http://[::1]:80",
	} {
		if u, err := SiteBackend(raw); err != nil || u.String() != want {
			t.Errorf("%q: %v, %v; want %s", raw, u, err, want)
		}
	}
	for _, raw := range []string{"", "site:8080", "ftp://site", "http://", "http://site/path", "http://site?q", "http://site/?", "http://site#f", "http://u:p@site", "/site", "http:site"} {
		if u, err := SiteBackend(raw); err == nil {
			t.Errorf("%q: taken as %s", raw, u)
		}
	}
}
