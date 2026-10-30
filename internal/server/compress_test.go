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

	"github.com/dromas-dev/dromas-client/protocol"
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

// A mailbox's read is gzipped to a request that takes gzip, with its own length,
// and is the JSON it is otherwise; to any other it is the JSON. Both say
// they vary by Accept-Encoding.
func TestAMailboxsReadIsGzippedWhenTaken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	url := e.srv.URL + b.path("")
	resp, plain := rawCall(t, http.MethodGet, url)
	var mailbox protocol.MailboxResponse
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" || protocol.Unmarshal(plain, &mailbox) != nil {
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
	from, to := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
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

// A site's answer is its web server's, as that server sent it: the server
// compresses none of it, whatever the request takes, and a gzip the site
// made itself comes back as it was made.
func TestASitesAnswerIsCompressedOnlyByTheSite(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("what an agent reads first\n", 40)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := io.WriteString(zw, text); err != nil || zw.Close() != nil {
		t.Fatal(err)
	}
	backend := backendOf(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gz" {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
			return
		}
		_, _ = io.WriteString(w, text)
	}))
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), SiteBackend: backend}).Handler())
	t.Cleanup(srv.Close)
	if resp, got := rawCall(t, http.MethodGet, srv.URL+"/plain", "Accept-Encoding", "gzip"); resp.Header.Get("Content-Encoding") != "" || string(got) != text || varies(resp) {
		t.Errorf("the site's plain answer, to a request that takes gzip: %q, %d bytes, Vary %q", resp.Header.Get("Content-Encoding"), len(got), resp.Header.Values("Vary"))
	}
	if resp, got := rawCall(t, http.MethodGet, srv.URL+"/gz", "Accept-Encoding", "gzip"); resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(got, gz.Bytes()) {
		t.Errorf("the site's own gzip: %q, %d bytes, want its %d", resp.Header.Get("Content-Encoding"), len(got), gz.Len())
	}
}
