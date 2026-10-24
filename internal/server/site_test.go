package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// siteFiles is a site as a renderer writes one: the front page, a page at a
// path of its own, an index of another type in a directory, and three icons.
var siteFiles = map[string]string{
	"index.html":           "<!doctype html><title>front</title>",
	"llms.txt":             "what an agent reads first\n",
	"docs/index.md":        "# docs\n",
	"favicon.ico":          "\x00\x00\x01\x00ico",
	"favicon.svg":          "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
	"apple-touch-icon.png": "\x89PNG\r\n\x1a\npng",
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

// siteServer is a server with the site above, and ready as given: the API
// answers 503 until it is.
func siteServer(t *testing.T, l Limits, ready bool) *httptest.Server {
	t.Helper()
	site, err := LoadSite(writeSite(t, siteFiles))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, Site: site, Ready: func() bool { return ready }})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, method, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
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

// rawGet sends one request line as written, with nothing cleaned or
// followed, and returns the status, the Location and the body.
func rawGet(t *testing.T, srv *httptest.Server, target string) (int, string, string) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET "+target+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

// Each page answers at its own path and nowhere else, with the type of its
// extension, a cache of five minutes, nosniff, its hash as a strong ETag and
// a Last-Modified; an index answers at its directory's path, which the path
// without the slash redirects to. The API and the link page are never the
// site's.
func TestTheSiteServesEachPageAtItsPath(t *testing.T) {
	t.Parallel()
	srv := siteServer(t, relaxed(), true)
	for path, want := range map[string]struct{ file, ctype string }{
		"/":                     {"index.html", "text/html; charset=utf-8"},
		"/llms.txt":             {"llms.txt", "text/plain; charset=utf-8"},
		"/docs/":                {"docs/index.md", "text/plain; charset=utf-8"},
		"/favicon.ico":          {"favicon.ico", "image/x-icon"},
		"/favicon.svg":          {"favicon.svg", "image/svg+xml"},
		"/apple-touch-icon.png": {"apple-touch-icon.png", "image/png"},
	} {
		resp, body := get(t, srv, http.MethodGet, path)
		sum := sha256.Sum256([]byte(siteFiles[want.file]))
		h := resp.Header
		if resp.StatusCode != http.StatusOK || body != siteFiles[want.file] || h.Get("Content-Type") != want.ctype ||
			h.Get("Cache-Control") != pageMaxAge || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("ETag") != `"`+hex.EncodeToString(sum[:16])+`"` || h.Get("Last-Modified") == "" {
			t.Errorf("%s: %d %q, headers %v", path, resp.StatusCode, body, h)
		}
	}
	if resp, _ := get(t, srv, http.MethodGet, "/docs"); resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/docs/" {
		t.Errorf("/docs: %d to %q, want 301 to /docs/", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, path := range []string{"/index.html", "/docs/index.md", "/nope", "/docs/nope", "/llms.txt/", "/to/"} {
		if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.StatusCode)
		}
	}
	if resp, body := get(t, srv, http.MethodGet, "/v1/"+strings.Repeat("0", 64)); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, string(protocol.CodeNoSuchMailbox)) {
		t.Errorf("the API's read of a box: %d %s, want its own 404", resp.StatusCode, body)
	}
	if resp, body := get(t, srv, http.MethodGet, protocol.LinkPath+strings.Repeat("a", 64)); resp.StatusCode != http.StatusOK || !strings.Contains(body, strings.Repeat("a", 64)) {
		t.Errorf("the link page: %d", resp.StatusCode)
	}
}

// A page is answered as a static file is: 304 to its ETag or a date not
// before its own, a HEAD with no body, and a range.
func TestASitePageAnswersConditionally(t *testing.T) {
	t.Parallel()
	srv := siteServer(t, relaxed(), true)
	first, _ := get(t, srv, http.MethodGet, "/llms.txt")
	if resp, body := get(t, srv, http.MethodGet, "/llms.txt", "If-None-Match", first.Header.Get("ETag")); resp.StatusCode != http.StatusNotModified || body != "" {
		t.Errorf("If-None-Match its ETag: %d %q, want 304", resp.StatusCode, body)
	}
	if resp, _ := get(t, srv, http.MethodGet, "/llms.txt", "If-Modified-Since", first.Header.Get("Last-Modified")); resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-Modified-Since its date: %d, want 304", resp.StatusCode)
	}
	if resp, body := get(t, srv, http.MethodHead, "/llms.txt"); resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Content-Length") != "26" {
		t.Errorf("HEAD: %d %q, length %q", resp.StatusCode, body, resp.Header.Get("Content-Length"))
	}
	if resp, body := get(t, srv, http.MethodGet, "/llms.txt", "Range", "bytes=0-3"); resp.StatusCode != http.StatusPartialContent || body != "what" {
		t.Errorf("a range: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get(t, srv, http.MethodPost, "/llms.txt"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", resp.StatusCode)
	}
}

// A page of the site spends its caller's flood budget, which is for floods
// alone (IronGall-dev/irongall-server#58): thirty views of three pages each,
// a 404 among them, from one address at once, are each answered under the
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

// A directory's path without its slash redirects to its index, escaped, as
// Location is a URI reference, and with the request's query
// (IronGall-dev/irongall-server#44): each lands on its page.
func TestADirectorysRedirectNamesItsPath(t *testing.T) {
	t.Parallel()
	site, err := LoadSite(writeSite(t, map[string]string{
		"p%41/index.html": "PCT", "q?x/index.html": "Q", "h#x/index.html": "HASH", "s p/index.html": "SPACE", "docs/index.md": "docs",
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Site: site}).Handler())
	t.Cleanup(srv.Close)
	for path, want := range map[string]struct{ loc, body string }{
		"/p%2541":   {"/p%2541/", "PCT"},
		"/q%3Fx":    {"/q%3Fx/", "Q"},
		"/h%23x":    {"/h%23x/", "HASH"},
		"/s%20p":    {"/s%20p/", "SPACE"},
		"/docs?a=1": {"/docs/?a=1", "docs"},
	} {
		st, loc, _ := rawGet(t, srv, path)
		if st != http.StatusMovedPermanently || loc != want.loc {
			t.Errorf("%s: %d to %q, want 301 to %q", path, st, loc, want.loc)
			continue
		}
		u, _ := url.Parse(srv.URL + path)
		ref, err := u.Parse(loc) // as a client resolves Location
		if err != nil {
			t.Fatal(err)
		}
		if st, _, body := rawGet(t, srv, ref.RequestURI()); st != http.StatusOK || body != want.body {
			t.Errorf("%s, then %s: %d %q, want 200 %q", path, ref.RequestURI(), st, body, want.body)
		}
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

// A site is what its renderer wrote: a file of a type it holds none of, a
// second index in one directory, a link, or a file under v1/ or to/, which it
// could never serve at its path (IronGall-dev/irongall-server#43), is refused
// at start.
func TestASiteOfAnythingElseIsRefused(t *testing.T) {
	t.Parallel()
	for name, files := range map[string]map[string]string{
		"a type it holds none of": {"index.html": "x", "notes.pdf": "x"},
		"a file with no type":     {"index.html": "x", "README": "x"},
		"two indexes":             {"docs/index.md": "x", "docs/index.html": "x"},
		"a file under v1/":        {"index.html": "x", "v1/hidden.html": "x"},
		"an index under v1/":      {"v1/index.md": "x"},
		"an index under to/":      {"to/index.html": "x"},
		"a file under to/":        {"to/one.html": "x"},
		"a file deeper in to/":    {"to/a/b.html": "x"},
	} {
		if _, err := LoadSite(writeSite(t, files)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	dir := writeSite(t, map[string]string{"index.html": "x"})
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "llms.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSite(dir); err == nil {
		t.Error("a link: loaded")
	}
}

// A site's root may be a link to its directory, as a web server's root may
// (IronGall-dev/irongall-server#45); a link inside it is still refused
// (above), and a root that is no directory is refused as one.
func TestASitesRootMayBeALink(t *testing.T) {
	t.Parallel()
	dir := writeSite(t, siteFiles)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	site, err := LoadSite(link)
	if err != nil {
		t.Fatalf("a link to a directory: %v", err)
	}
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Site: site}).Handler())
	t.Cleanup(srv.Close)
	if resp, body := get(t, srv, http.MethodGet, "/llms.txt"); resp.StatusCode != http.StatusOK || body != siteFiles["llms.txt"] {
		t.Errorf("a page of the linked site: %d %q", resp.StatusCode, body)
	}
	if _, err := LoadSite(filepath.Join(dir, "index.html")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file as the root: %v", err)
	}
}
