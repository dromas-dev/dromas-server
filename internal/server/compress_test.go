package server

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// rawCall calls url with exactly the headers given, each one whose value is
// not empty: no Accept-Encoding is added, and nothing is decompressed, as
// Go's transport otherwise does.
func rawCall(t *testing.T, method, url string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	tr := &http.Transport{DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	req, _ := http.NewRequest(method, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] != "" {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	return out
}

func varies(resp *http.Response) bool {
	for _, v := range resp.Header.Values("Vary") {
		for f := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "Accept-Encoding") {
				return true
			}
		}
	}
	return false
}

// A request takes gzip by naming it, or x-gzip, with a weight above zero, or
// by "*" when it does not name it (RFC 9110 §12.5.3, §12.4.2).
func TestWhatTakesGzip(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fields []string
		want   bool
	}{
		{nil, false},
		{[]string{""}, false},
		{[]string{"gzip"}, true},
		{[]string{"GZip"}, true},
		{[]string{"x-gzip"}, true},
		{[]string{"br, gzip"}, true},
		{[]string{"br", "gzip"}, true},
		{[]string{"gzip;q=0.5"}, true},
		{[]string{"gzip ; Q=0.001"}, true},
		{[]string{"*"}, true},
		{[]string{"br"}, false},
		{[]string{"identity"}, false},
		{[]string{"gzip;q=0"}, false},
		{[]string{"gzip; q=0.000"}, false},
		{[]string{"gzip;q=nope"}, false},
		{[]string{"gzip;level=1"}, false},
		{[]string{"*;q=0"}, false},
		{[]string{"*, gzip;q=0"}, false},
		{[]string{"gzip;q=0, *"}, false},
		{[]string{"gzip, *;q=0"}, true},
		{[]string{"gzipped"}, false},
	} {
		if got := acceptsGzip(c.fields); got != c.want {
			t.Errorf("Accept-Encoding %q: %v, want %v", c.fields, got, c.want)
		}
	}
}

// A box's read is gzipped to a request that takes gzip, with its own length,
// and is the JSON it is otherwise; to any other it is the JSON. Both say
// they vary by Accept-Encoding.
func TestABoxsReadIsGzippedWhenTaken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	url := e.srv.URL + b.path("")
	resp, plain := rawCall(t, http.MethodGet, url)
	var box protocol.BoxResponse
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" || protocol.Unmarshal(plain, &box) != nil {
		t.Fatalf("no Accept-Encoding: %d in %q: %s", resp.StatusCode, resp.Header.Get("Content-Encoding"), plain)
	}
	if !varies(resp) || resp.Header.Get("Content-Length") != strconv.Itoa(len(plain)) {
		t.Errorf("no Accept-Encoding: Vary %q, Content-Length %q, want Accept-Encoding and %d", resp.Header.Values("Vary"), resp.Header.Get("Content-Length"), len(plain))
	}
	for _, ae := range []string{"gzip", "br, gzip", "x-gzip", "*", "gzip;q=0.1"} {
		resp, got := rawCall(t, http.MethodGet, url, "Accept-Encoding", ae)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding %q: %d in %q, want 200 in gzip", ae, resp.StatusCode, resp.Header.Get("Content-Encoding"))
			continue
		}
		if !varies(resp) || resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) || len(got) >= len(plain) {
			t.Errorf("Accept-Encoding %q: Vary %q, Content-Length %q of %d bytes, against %d plain", ae, resp.Header.Values("Vary"), resp.Header.Get("Content-Length"), len(got), len(plain))
		}
		if !bytes.Equal(gunzip(t, got), plain) {
			t.Errorf("Accept-Encoding %q: the gzip is not the read", ae)
		}
	}
	for _, ae := range []string{"identity", "br", "gzip;q=0", "*;q=0", "*, gzip;q=0"} {
		resp, got := rawCall(t, http.MethodGet, url, "Accept-Encoding", ae)
		if resp.Header.Get("Content-Encoding") != "" || !bytes.Equal(got, plain) || !varies(resp) {
			t.Errorf("Accept-Encoding %q: %d in %q, Vary %q, want the read as JSON", ae, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"))
		}
	}
}

// No other answer is gzipped, however the request takes it: not a list,
// though one of three messages is long enough to gain from it, nor a fetch,
// an error, an owner's read or the link page.
func TestNoOtherAnswerIsGzipped(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to := e.box(protocol.Classic), e.box(protocol.Classic)
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
		{"/messages", pass, http.StatusOK},
		{"/messages/" + r.ID, pass, http.StatusOK},
		{"/acl", pass, http.StatusOK},
		{"/revocations", "", http.StatusNotFound},
		{"/messages", "", http.StatusUnauthorized},
	} {
		resp, got := rawCall(t, http.MethodGet, base+c.path, "Accept-Encoding", "gzip", "Authorization", c.pass)
		if resp.StatusCode != c.status || resp.Header.Get("Content-Encoding") != "" || varies(resp) {
			t.Errorf("%s: %d in %q, Vary %q, want %d as it is: %.80q", c.path, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"), c.status, got)
		}
	}
	for _, path := range []string{"/v1/" + hex.EncodeToString(none), protocol.LinkPath + to.Address().String()} {
		resp, got := rawCall(t, http.MethodGet, e.srv.URL+path, "Accept-Encoding", "gzip")
		if resp.Header.Get("Content-Encoding") != "" || varies(resp) {
			t.Errorf("%s: %d in %q, Vary %q, want it as it is: %.80q", path, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"), got)
		}
	}
}

// A site's text page that gzip makes smaller is gzipped once, and answered
// so to a request that takes gzip: bytes with an ETag of their own, which a
// 304 and a range answer to. An image, and a page gzip would make larger, are
// answered as they are, and say nothing of Accept-Encoding.
func TestASitesTextIsGzippedOnce(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("what an agent reads first\n", 40)
	site, err := LoadSite(writeSite(t, map[string]string{
		"llms.txt":             text,
		"index.html":           "<!doctype html><title>front</title>",
		"apple-touch-icon.png": "\x89PNG\r\n\x1a\n" + strings.Repeat("png", 200),
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Site: site}).Handler())
	t.Cleanup(srv.Close)

	resp, plain := rawCall(t, http.MethodGet, srv.URL+"/llms.txt")
	if string(plain) != text || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("ETag") != entityTag([]byte(text)) || !varies(resp) {
		t.Fatalf("no Accept-Encoding: %d in %q, ETag %q, Vary %q", resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Get("ETag"), resp.Header.Values("Vary"))
	}
	resp, gz := rawCall(t, http.MethodGet, srv.URL+"/llms.txt", "Accept-Encoding", "gzip")
	tag := resp.Header.Get("ETag")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" || !varies(resp) || tag != entityTag(gz) || tag == entityTag([]byte(text)) {
		t.Fatalf("gzip: %d in %q, ETag %q, Vary %q", resp.StatusCode, resp.Header.Get("Content-Encoding"), tag, resp.Header.Values("Vary"))
	}
	if string(gunzip(t, gz)) != text || len(gz) >= len(text) || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("gzip: %d bytes of %s, not the page", len(gz), resp.Header.Get("Content-Type"))
	}
	if resp, got := rawCall(t, http.MethodGet, srv.URL+"/llms.txt", "Accept-Encoding", "gzip", "If-None-Match", tag); resp.StatusCode != http.StatusNotModified || len(got) != 0 || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("gzip, its own tag: %d in %q, want 304", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	if resp, _ := rawCall(t, http.MethodGet, srv.URL+"/llms.txt", "If-None-Match", tag); resp.StatusCode != http.StatusOK {
		t.Errorf("no Accept-Encoding, the gzip's tag: %d, want 200", resp.StatusCode)
	}
	if resp, got := rawCall(t, http.MethodGet, srv.URL+"/llms.txt", "Accept-Encoding", "gzip", "Range", "bytes=0-9"); resp.StatusCode != http.StatusPartialContent || !bytes.Equal(got, gz[:10]) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("gzip, a range: %d in %q, %q, want 206 of the gzip's first 10 bytes", resp.StatusCode, resp.Header.Get("Content-Encoding"), got)
	}
	if resp, got := rawCall(t, http.MethodGet, srv.URL+"/llms.txt", "Accept-Encoding", "gzip;q=0"); string(got) != text || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("gzip;q=0: %d in %q, want the page as it is", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	for _, path := range []string{"/", "/apple-touch-icon.png"} {
		if resp, _ := rawCall(t, http.MethodGet, srv.URL+path, "Accept-Encoding", "gzip"); resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" || varies(resp) {
			t.Errorf("%s: %d in %q, Vary %q, want it as it is", path, resp.StatusCode, resp.Header.Get("Content-Encoding"), resp.Header.Values("Vary"))
		}
	}
}
