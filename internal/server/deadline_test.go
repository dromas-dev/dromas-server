package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Every answer is paced, so no connection outlives the deadline its peer
// sets by not sending or not reading (LIMITS.md, a body's and a response's
// time; dromas-dev/dromas-server#28, #31, #75, #77). These run through
// HTTPServer, the server dromas-server serves the API with, on a port of their
// own, since net/http's own reading and writing is what they hold.

// pacedLimits are limits with every body and answer paced at a second, and
// a megabyte a second more for each second, so a test's slow peer is cut
// at a second.
func pacedLimits() Limits {
	l := relaxed()
	l.BodyTimeout, l.BodyMinRate = time.Second, 1<<20
	return l
}

// served serves s's handler as dromas-server does, and returns its address and
// how many of its connections have closed.
func served(t *testing.T, s *Server, l Limits) (string, *atomic.Int64) {
	t.Helper()
	closed := new(atomic.Int64)
	srv := HTTPServer("", s.Handler(), l, time.Minute)
	srv.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			closed.Add(1)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), closed
}

// servedSmall is served, with each connection's send buffer at its
// smallest, so an answer of more than a few KiB waits on its peer: what
// the write deadline holds is then what a test sees, not what the kernel's
// buffers took.
func servedSmall(t *testing.T, s *Server, l Limits) (string, *atomic.Int64) {
	t.Helper()
	closed := new(atomic.Int64)
	srv := HTTPServer("", s.Handler(), l, time.Minute)
	srv.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			_ = c.(*net.TCPConn).SetWriteBuffer(4096)
		}
		if st == http.StateClosed || st == http.StateHijacked {
			closed.Add(1)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), closed
}

// closesWithin reports whether the server ends conn within d, whatever it
// writes first, and what it wrote.
func closesWithin(conn net.Conn, d time.Duration) (bool, string) {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	got, err := io.ReadAll(conn)
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout(), string(got)
}

// A body that stops after its head is cut off at the read deadline, behind
// any answer: one a handler gives after it reads, and every one written
// before the body is read, whose body the server drains first (#77). Cut
// off where a handler reads it, the answer is 408 request_timeout (RFC 9110
// §15.5.9); behind an answer written first, the drain is cut and that
// answer goes out after it (#82), then the connection ends. Either way the
// cut is counted once, in the one place every cut is
// (dromas-dev/dromas-client#413 item 3).
func TestABodyThatStopsIsCutBehindEveryAnswer(t *testing.T) {
	t.Parallel()
	nobody := "d_" + strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		limits  func(*Limits)
		ready   bool
		spend   bool // spend the address's one call first
		head    string
		status  string // the answer's status
		limited bool
	}{
		{"read by its handler", nil, true, false, "PUT /v1/" + nobody + " HTTP/1.1", "408", false},
		{"the gate's refusal", func(l *Limits) { l.RequestBurst, l.RequestRefill = 1, time.Hour }, true, true, "POST /v1/" + nobody + "/messages HTTP/1.1", "429", true},
		{"unrouted's refusal", func(l *Limits) { l.RequestBurst, l.RequestRefill = 1, time.Hour }, true, true, "POST /nothing HTTP/1.1", "429", true},
		{"the router's 404", nil, true, false, "POST /v1/" + nobody + "/nothing/here HTTP/1.1", "404", false},
		{"the link page's 405", nil, true, false, "POST " + protocol.LinkPath + nobody + " HTTP/1.1", "405", false},
		{"OPTIONS *", nil, true, false, "OPTIONS * HTTP/1.1", "400", false},
		{"a server not ready", nil, false, false, "PUT /v1/" + nobody + " HTTP/1.1", "503", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := pacedLimits()
			if c.limits != nil {
				c.limits(&l)
			}
			ready := c.ready
			reg := prometheus.NewRegistry()
			s := New(Config{Store: NewMemStore(time.Now), Limits: l, Ready: func() bool { return ready }, Metrics: NewMetrics(reg)})
			addr, _ := served(t, s, l)
			if c.spend {
				resp, err := http.Get("http://" + addr + protocol.LinkPath + nobody)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := io.WriteString(conn, c.head+"\r\nHost: "+addr+"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			ok, got := closesWithin(conn, 5*time.Second)
			if !ok {
				t.Fatalf("a body that stopped after its head: the connection was held past %v", time.Since(start).Round(time.Millisecond))
			}
			if !strings.HasPrefix(got, "HTTP/1.1 "+c.status+" ") {
				t.Errorf("answered %.40q, want %s", got, c.status)
			}
			if c.status == "408" && !strings.Contains(got, `"code":"request_timeout"`) {
				t.Errorf("a 408 that is not request_timeout: %q", got)
			}
			if d := counts(t, reg, "dromas_server_limit_requests_total")["decision=denied,limit=requests,subject=ip"]; c.limited && d != 1 {
				t.Errorf("refused for the flood budget %v times, want 1", d)
			}
			if cut := counts(t, reg, "dromas_server_bodies_cut_total")[""]; cut != 1 {
				t.Errorf("a body cut off at its deadline: dromas_server_bodies_cut_total %v, want 1", cut)
			}
			t.Logf("cut after %v", time.Since(start).Round(10*time.Millisecond))
		})
	}
}

// A chunked body cut off at its deadline where a handler reads it is 408
// request_timeout, and counted as cut, wherever it stops: in a chunk's data,
// after its last chunk's line, or inside its trailer (#83), where net/http's
// error for the trailer is not the deadline's.
func TestAChunkedBodyCutInItsTrailerIs408(t *testing.T) {
	t.Parallel()
	nobody := "d_" + strings.Repeat("ab", 32)
	head := "PUT /v1/" + nobody + " HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
	for _, c := range []struct{ name, req string }{
		{"stops in a chunk's data (control)", head + "a\r\n{\"x"},
		{"stops after the last chunk's line", head + "2\r\n{}\r\n0\r\n"},
		{"stops inside a trailer", head + "2\r\n{}\r\n0\r\nX-T: 1\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := pacedLimits()
			reg := prometheus.NewRegistry()
			s := New(Config{Store: NewMemStore(time.Now), Limits: l, Metrics: NewMetrics(reg)})
			addr, _ := served(t, s, l)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := io.WriteString(conn, c.req); err != nil {
				t.Fatal(err)
			}
			if _, got := closesWithin(conn, 5*time.Second); !strings.HasPrefix(got, "HTTP/1.1 408 ") || !strings.Contains(got, `"code":"request_timeout"`) {
				t.Errorf("a body cut off at its deadline where its handler reads it: %.200q, want 408 request_timeout", got)
			}
			if cut := counts(t, reg, "dromas_server_bodies_cut_total")[""]; cut != 1 {
				t.Errorf("dromas_server_bodies_cut_total %v, want 1", cut)
			}
		})
	}
}

// A body that keeps coming above --body-min-rate, behind an answer written
// before it is read, gets that answer (#82): the server drains the body
// through the paced body, before the answer's first byte goes out, and no
// byte of the drain moves the read deadline, so the drain is cut at
// --body-timeout from the head, counted as every cut is
// (dromas-dev/dromas-client#413 item 3), and the answer goes out after
// it. Each body is 3,000 bytes at 2,000 a second, where a handler's reads
// would give it a second and three more; the control is a body its handler
// reads, answered after the whole of it.
func TestAnAnswerWrittenFirstOutlivesTheDrainOfItsBody(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	nobody := "d_" + strings.Repeat("ab", 32)
	cases := []struct {
		name   string
		limits func(*Limits)
		spend  bool // spend the address's one call first
		line   string
		status string
	}{
		{"read by its handler (control)", nil, false, "PUT /v1/" + nobody, "400"},
		{"the router's 404", nil, false, "POST /v1/" + nobody + "/nothing/here", "404"},
		{"a request no route answers", nil, false, "POST /nothing", "404"},
		{"the link page's 405", nil, false, "POST " + protocol.LinkPath + nobody, "405"},
		{"the gate's refusal", func(l *Limits) { l.RequestBurst, l.RequestRefill = 1, time.Hour }, true, "POST /v1/" + nobody + "/messages", "429"},
		{"a send refused for its pass (no pass)", nil, false, "POST /v1/" + nobody + "/messages", "401"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := relaxed()
			l.BodyTimeout, l.BodyMinRate = time.Second, 1000
			if c.limits != nil {
				c.limits(&l)
			}
			reg := prometheus.NewRegistry()
			s := New(Config{Store: NewMemStore(time.Now), Limits: l, Metrics: NewMetrics(reg)})
			addr, _ := served(t, s, l)
			if c.spend {
				resp, err := http.Get("http://" + addr + protocol.LinkPath + nobody)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			status, at, sent, last := trickle(t, addr, c.line+" HTTP/1.1\r\nHost: "+addr+"\r\nContent-Type: application/json\r\n", 3000, 2000)
			t.Logf("%q at %v, with %d of 3000 bytes sent, the last at %v", status, at.Round(10*time.Millisecond), sent, last.Round(10*time.Millisecond))
			if !strings.HasPrefix(status, "HTTP/1.1 "+c.status+" ") {
				t.Errorf("a body moving at twice --body-min-rate: answered %q, want %s", status, c.status)
			}
			cut := counts(t, reg, "dromas_server_bodies_cut_total")[""]
			switch control := c.name == "read by its handler (control)"; {
			case control && (sent != 3000 || at < last || cut != 0):
				t.Errorf("a body its handler reads: answered at %v with %d of 3000 bytes sent, the last at %v, %v cut; want the answer after the whole body, none cut", at.Round(10*time.Millisecond), sent, last.Round(10*time.Millisecond), cut)
			case !control && (at > last || cut != 1):
				t.Errorf("behind an answer written first: answered at %v, the body's last bytes at %v, %v cut; want the drain cut at --body-timeout, before the body's end, and counted once", at.Round(10*time.Millisecond), last.Round(10*time.Millisecond), cut)
			}
		})
	}
}

// An answer larger than net/http's buffer, written before a body that stops
// is read, goes out whole once the drain of the body is cut, and the cut is
// counted once (dromas-dev/dromas-client#437 item 1): every other test's
// answer fits the buffer, which net/http writes only as the handler
// returns, after the drain there. This one is a fetch of a 32 KiB message,
// with a body of 1,000 bytes that stops after one. Control: with no drain
// before the first write (pacedWriter.Write), net/http drains the body
// itself inside that write, to the read deadline, and the write's deadline
// has passed when it ends: nothing is answered.
func TestALargeAnswerWrittenFirstGoesOutAfterTheDrainOfItsBody(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[1].Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(make([]byte, 32<<10))
	_ = w.Close()
	e.want(e.do(http.MethodPost, to.path("/messages"), to.sealed(1, ct.Bytes()), from.pass(1)), http.StatusCreated, "")
	id := sha256.Sum256(ct.Bytes())
	l := pacedLimits()
	reg := prometheus.NewRegistry()
	s := New(Config{Store: e.store, Limits: l, Metrics: NewMetrics(reg), Now: e.clock.Now})
	addr, _ := served(t, s, l)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	pass := e.passFor(to.by[1], to.id.Address(), addr)
	if _, err := io.WriteString(conn, "GET "+to.path("/messages/"+hex.EncodeToString(id[:]))+" HTTP/1.1\r\nHost: "+addr+"\r\nAuthorization: "+pass+"\r\nContent-Length: 1000\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	ok, got := closesWithin(conn, 5*time.Second)
	if !ok {
		t.Fatal("the connection was held past 5 s")
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(got)), nil)
	if err != nil {
		t.Fatalf("no answer: %v: %.80q", err, got)
	}
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || err != nil || !bytes.Equal(body, ct.Bytes()) {
		t.Errorf("answered %s with %d of the message's %d bytes (%v), want 200 and all of them", resp.Status, len(body), ct.Len(), err)
	}
	if cut := counts(t, reg, "dromas_server_bodies_cut_total")[""]; cut != 1 {
		t.Errorf("dromas_server_bodies_cut_total %v, want 1", cut)
	}
}

// trickle sends head and then size bytes of body at rate bytes a second, in
// 100-byte pieces, reading the answer as it comes, as a client that reads
// while it writes does. It returns the answer's status line ("" for none),
// when it came, how much of the body went before the server stopped taking
// it, and when its last piece began to go.
func trickle(t *testing.T, addr, head string, size, rate int) (status string, at time.Duration, sent int, last time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, head+fmt.Sprintf("Content-Length: %d\r\n\r\n", size)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err == nil {
			status, at = resp.Proto+" "+resp.Status, time.Since(start)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	for sent < size {
		n := min(100, size-sent)
		last = time.Since(start)
		if _, err := conn.Write([]byte(strings.Repeat(" ", n))); err != nil {
			break
		}
		sent += n
		time.Sleep(time.Duration(n) * time.Second / time.Duration(rate))
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("the connection was held 5 s past the body's end")
	}
	return status, at, sent, last
}

// A body the server would not drain is not read at all behind an answer
// written first, as net/http reads none of it (go1.27's
// chunkWriter.writeHeader): one whose request asks to close the connection,
// one that waits for 100 Continue, which is never sent, and one whose
// Content-Length leaves more than net/http's bound. Each is answered at
// once, long before its deadline, with no cut, and the connection is
// closed (dromas-dev/dromas-client#413 item 3).
func TestABodyTheServerWouldNotDrainIsNotRead(t *testing.T) {
	t.Parallel()
	nobody := "d_" + strings.Repeat("ab", 32)
	for _, c := range []struct{ name, head, body string }{
		{"its request asks to close", "Connection: close\r\nContent-Length: 1000\r\n", "{"},
		{"it waits for 100 Continue", "Expect: 100-continue\r\nContent-Length: 1000\r\n", ""},
		{"its Content-Length leaves more than net/http's bound", fmt.Sprintf("Content-Length: %d\r\n", drainBound+1), "{"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := relaxed()
			l.BodyTimeout, l.BodyMinRate = 4*time.Second, 1<<20
			reg := prometheus.NewRegistry()
			s := New(Config{Store: NewMemStore(time.Now), Limits: l, Metrics: NewMetrics(reg)})
			addr, _ := served(t, s, l)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := io.WriteString(conn, "POST /v1/"+nobody+"/nothing/here HTTP/1.1\r\nHost: "+addr+"\r\n"+c.head+"\r\n"+c.body); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			ok, got := closesWithin(conn, 2*time.Second)
			t.Logf("closed %v after %v: %.40q", ok, time.Since(start).Round(10*time.Millisecond), got)
			if !ok || !strings.HasPrefix(got, "HTTP/1.1 404 ") {
				t.Errorf("a body the server would not drain: %.60q, closed %v; want 404 at once, then the connection closed", got, ok)
			}
			if cut := counts(t, reg, "dromas_server_bodies_cut_total")[""]; cut != 0 {
				t.Errorf("dromas_server_bodies_cut_total %v, want 0: nothing was read to cut", cut)
			}
		})
	}
}

// A body that keeps coming past net/http's bound, behind an answer written
// first, is drained to that bound and no further: the answer goes out
// while the body is still coming, and the connection is closed, as net/http
// closes one it will not drain (dromas-dev/dromas-client#413 item 3).
// The body is chunked, so nothing says how long it is, and comes at four
// times the bound a second for two seconds.
func TestADrainStopsAtNetHTTPsBound(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.BodyTimeout, l.BodyMinRate = time.Second, 1024
	s := New(Config{Store: NewMemStore(time.Now), Limits: l})
	addr, _ := served(t, s, l)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "POST /nothing HTTP/1.1\r\nHost: "+addr+"\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	stopped := make(chan time.Duration, 1)
	go func() {
		piece := fmt.Sprintf("%x\r\n%s\r\n", drainBound/16, strings.Repeat(" ", drainBound/16))
		for i := 0; i < 128 && time.Since(start) < 4*time.Second; i++ {
			if _, err := io.WriteString(conn, piece); err != nil {
				break
			}
			time.Sleep(time.Second / 64)
		}
		stopped <- time.Since(start)
	}()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Since(start)
	_ = resp.Body.Close()
	end := <-stopped
	t.Logf("%s at %v; the body stopped going at %v", resp.Status, at.Round(10*time.Millisecond), end.Round(10*time.Millisecond))
	if resp.StatusCode != http.StatusNotFound || !resp.Close {
		t.Errorf("answered %s, closing %v; want 404 and the connection closed", resp.Status, resp.Close)
	}
	if at > time.Second {
		t.Errorf("answered at %v, past the second the bound takes to come: the drain went past it", at.Round(10*time.Millisecond))
	}
}

// An answer its peer never reads is cut off at the write deadline, every
// kind: a page outside the API, the router's own, one with no body, and a
// site's page larger than every buffer between (#31). The peer asks again
// and again on one connection and reads nothing, with a small receive
// buffer.
func TestAnAnswerNeverReadIsCut(t *testing.T) {
	t.Parallel()
	big := make([]byte, 8<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	site := siteBackend(t, map[string]string{"index.html": "<!doctype html><title>front</title>", "big.png": string(big)})
	l := pacedLimits()
	e := newEnv(t, l, func(c *Config) { c.SiteBackend = site })
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)
	tag := e.do("GET", r.path("/messages"), nil, pass).header.Get("ETag")
	nobody := "d_" + strings.Repeat("ab", 32)
	cases := []struct {
		name, req string
		once      bool
	}{
		{"the link page", "GET " + protocol.LinkPath + nobody + " HTTP/1.1\r\nHost: %s\r\n\r\n", false},
		{"the router's 404", "GET /nothing/here.html HTTP/1.1\r\nHost: %s\r\n\r\n", false},
		{"a 304, with no body", "GET " + r.path("/messages") + " HTTP/1.1\r\nHost: %s\r\nAuthorization: " + pass + "\r\nIf-None-Match: " + tag + "\r\n\r\n", false},
		{"a site's large page", "GET /big.png HTTP/1.1\r\nHost: %s\r\n\r\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, closed := served(t, e.server, l)
			req := strings.ReplaceAll(c.req, "%s", e.name())
			d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
				return rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024) })
			}}
			conn, err := d.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			go func() { // ask, and never read
				for {
					if _, err := io.WriteString(conn, req); err != nil || c.once {
						return
					}
				}
			}()
			deadline := time.Now().Add(6 * time.Second)
			for closed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if closed.Load() == 0 {
				t.Errorf("a peer that never reads holds the connection past every deadline")
			}
		})
	}
}

// An honest slow reader of a large page is not cut: each write moves the
// deadline on, so a peer that keeps reading gets the whole page however
// long it takes, as a body that keeps coming does. Each write has a clock of
// its own, from when it began (pacedWriter): this reader takes the page at a
// third of --body-min-rate, and the page waits on it, so a clock for the
// whole answer would cut it.
func TestASlowReaderIsNotCut(t *testing.T) {
	t.Parallel()
	page := make([]byte, 1<<20)
	if _, err := rand.Read(page); err != nil {
		t.Fatal(err)
	}
	site := siteBackend(t, map[string]string{"index.html": "<!doctype html><title>front</title>", "big.png": string(page)})
	l := pacedLimits()
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, SiteBackend: site})
	addr, _ := servedSmall(t, s, l)
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
	}}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET /big.png HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	start, got := time.Now(), 0
	buf := make([]byte, 64<<10)
	for {
		n, err := io.ReadFull(resp.Body, buf)
		got += n
		if err != nil {
			break
		}
		time.Sleep(200 * time.Millisecond) // 320 KiB a second: three seconds for the page
	}
	if got != len(page) {
		t.Errorf("a slow reader got %d of %d bytes in %v", got, len(page), time.Since(start).Round(time.Millisecond))
	}
}

// slowStore is a store whose DeleteMessages takes hold, and whose reads of
// a mailbox read their context first, as the DynamoDB backend's calls do.
type slowStore struct {
	Store
	hold time.Duration
}

func (s slowStore) DeleteMessages(ctx context.Context, a protocol.Address) error {
	select {
	case <-time.After(s.hold):
		return s.Store.DeleteMessages(ctx, a)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s slowStore) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.Store.Mailbox(ctx, a)
}

// A body's read deadline ends with the body: a handler that runs past it
// once the body is read is not cut, and the next request on the connection
// is answered as on a new one (#28). The read that ends a body is where
// net/http begins its own read of the connection, for the next request,
// and a deadline set there would cancel every request still to come on it.
func TestAPacedBodysDeadlineEndsWithTheBody(t *testing.T) {
	t.Parallel()
	l := pacedLimits()
	e := newEnv(t, l, func(c *Config) { c.Store = slowStore{Store: c.Store, hold: 3 * time.Second} })
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := served(t, e.server, l)
	one := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}} // one kept-alive connection
	do := func(method, path, body string) int {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://"+addr+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = e.name()
		resp, err := one.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	nobody := "/v1/" + "d_" + strings.Repeat("ab", 32)
	if got := do("GET", nobody, ""); got != http.StatusNotFound {
		t.Fatalf("before: %d", got)
	}
	j, err := json.Marshal(protocol.Revocations{Identity: r.id.Document(), Revocation: rev})
	if err != nil {
		t.Fatal(err)
	}
	if got := do("PUT", r.path("/revocations"), string(j)); got != http.StatusCreated {
		t.Errorf("a revocation whose delete takes past the body's deadline: %d, want 201", got)
	}
	for range 2 {
		if got := do("GET", nobody, ""); got != http.StatusNotFound {
			t.Errorf("after, on the same connection: %d, want 404", got)
		}
	}
}

// OPTIONS * reaches the server's handler, and is counted as a request no
// route answers (#75), where net/http would answer it 200 itself, its body
// read, before any handler or count: from an address with one call, the
// first is the router's 400, and the second is refused for the flood
// budget.
func TestOptionsStarIsCounted(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	s := New(Config{Store: NewMemStore(time.Now), Limits: l})
	addr, _ := served(t, s, l)
	for _, want := range []string{"400", "429"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		ok, got := closesWithin(conn, 5*time.Second)
		_ = conn.Close()
		if !ok || !strings.HasPrefix(got, "HTTP/1.1 "+want+" ") {
			t.Errorf("OPTIONS *: %.40q, want %s", got, want)
		}
	}
}

// A write is credited only for the bytes it has already written, in pieces
// of at most --body-min-rate, as a read is (dromas-dev/dromas-client#413
// item 2): each piece goes out under the deadline the pieces before it
// earned, from --body-timeout after the write began, so a peer that takes
// none of an answer is cut at --body-timeout and what the buffers between
// took, whatever the answer's size would earn.
func TestAWriteIsCreditedOnlyForTheBytesItHasWritten(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.BodyTimeout, l.BodyMinRate = time.Second, 1000
	s := New(Config{Store: NewMemStore(time.Now), Limits: l})
	answer := make([]byte, 40*l.BodyMinRate+1)
	h := s.paced(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(answer) }))
	w := &deadlines{header: http.Header{}}
	before := time.Now()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	after := time.Now()
	if len(w.writes) == 0 {
		t.Fatal("nothing written")
	}
	first, written := w.writes[0].deadline, 0
	if first.Before(before.Add(l.BodyTimeout)) || first.After(after.Add(l.BodyTimeout)) {
		t.Errorf("the first piece's deadline is %v past the write, want --body-timeout, %v", first.Sub(before).Round(time.Millisecond), l.BodyTimeout)
	}
	for i, p := range w.writes {
		if p.n > l.BodyMinRate {
			t.Errorf("piece %d is %d bytes, more than --body-min-rate, %d", i, p.n, l.BodyMinRate)
		}
		if want := first.Add(time.Duration(written/l.BodyMinRate) * time.Second); !p.deadline.Equal(want) {
			t.Errorf("piece %d, after %d bytes: its deadline is %v past the first's, want %v", i, written, p.deadline.Sub(first), want.Sub(first))
		}
		written += p.n
	}
	if written != len(answer) {
		t.Errorf("%d of %d bytes written", written, len(answer))
	}
}

// deadlines is a ResponseWriter that keeps each write's length and the write
// deadline set before it, which a connection would hold that write to.
type deadlines struct {
	header   http.Header
	deadline time.Time
	writes   []struct {
		n        int
		deadline time.Time
	}
}

func (d *deadlines) Header() http.Header { return d.header }
func (d *deadlines) WriteHeader(int)     {}
func (d *deadlines) Write(b []byte) (int, error) {
	d.writes = append(d.writes, struct {
		n        int
		deadline time.Time
	}{len(b), d.deadline})
	return len(b), nil
}
func (d *deadlines) SetWriteDeadline(t time.Time) error { d.deadline = t; return nil }
func (d *deadlines) SetReadDeadline(time.Time) error    { return nil }

// A peer that takes none of a fetch holds the connection --body-timeout and
// what the buffers between took, never what the ciphertext's size would
// earn (dromas-dev/dromas-client#413 item 2): the fetch writes the whole
// ciphertext in one write, which was credited for all of it before any of
// it moved. At this --body-min-rate the ciphertext would earn a minute.
func TestAFetchNeverReadIsCutWhateverItsSize(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	if runtime.GOOS == "darwin" {
		t.Skip("macOS loopback buffers far past a small SO_RCVBUF, so the paced writer is never held: CI runs it on Linux")
	}
	l := relaxed()
	l.BodyTimeout, l.BodyMinRate, l.MaxSize = time.Second, 8<<10, 1<<20
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	body := strings.Repeat("a message that is never read. ", 17000) // its ciphertext is larger
	if len(body) < 60*l.BodyMinRate {
		t.Fatalf("a message of %d bytes earns less than a minute", len(body))
	}
	m := send(t, a, b, body)
	pass := e.pass(b)
	addr, closed := servedSmall(t, e.server, l)
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024) })
	}}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET /v1/"+b.Address().String()+"/messages/"+m.ID+" HTTP/1.1\r\nHost: "+e.name()+"\r\nAuthorization: "+pass+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for closed.Load() == 0 && time.Since(start) < 8*time.Second {
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("a message of %d bytes: closed by the server %v, after %v", len(body), closed.Load() != 0, time.Since(start).Round(10*time.Millisecond))
	if closed.Load() == 0 {
		t.Errorf("a fetch never read, of more than %d bytes at --body-min-rate %d: the connection is held past 8 s", len(body), l.BodyMinRate)
	}
}
