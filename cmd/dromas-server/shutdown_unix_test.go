//go:build unix

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5"
)

// dev is serve --dev's arguments.
func dev(string) []string { return []string{"--dev"} }

// heldRegistration opens a connection to p and sends a registration's head,
// with Expect: 100-continue and a body of two bytes, and reads the 100
// Continue net/http sends as the handler first reads the body: the request
// is then in its handler, waiting for its body, which the caller sends.
func heldRegistration(t *testing.T, p *serveProcess) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	a := protocol.AddressOf([]byte("held")).String()
	if _, err := fmt.Fprintf(c, "PUT /v1/%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n", a, p.addr); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil || resp.StatusCode != http.StatusContinue {
		t.Fatalf("the registration's head: %v, %v; want 100 Continue", resp, err)
	}
	return c, r
}

// A signal lets every request in flight finish, however long it takes, and
// serve then returns nil: Shutdown has no bound of dromas-server's own,
// since the supervisor's kill bounds it (Caddy's grace period is eternal by
// default). Here a registration whose body ends 6 s after a SIGTERM is
// answered, and the process exits 0. Control: a bound of 5 s exits 1 before
// the answer.
func TestASignalWaitsForEveryRequestInFlight(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	p := startServe(t, nil, dev)
	p.ready(t, 10*time.Second)
	c, r := heldRegistration(t, p)
	if _, err := io.WriteString(c, "{"); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	select {
	case <-p.exited:
		t.Fatalf("serve exited %v with a request in flight", p.cmd.ProcessState)
	default:
	}
	if _, err := io.WriteString(c, "}"); err != nil {
		t.Fatalf("the rest of the body: %v", err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("the request in flight at the signal was not answered: %v", err)
	}
	_ = resp.Body.Close()
	if st := p.exit(t, 10*time.Second); st.ExitCode() != 0 {
		t.Fatalf("serve exited %v once the request was answered; want 0", st)
	}
}

// A second signal ends the process at once, while the first waits for the
// requests in flight (Go's ExampleNotifyContext stops the signal context at
// its Done; Caddy's second SIGINT forces its exit). Control: a signal
// context held through Shutdown takes the second SIGINT, and the process
// waits on the request.
func TestASecondSignalEndsTheProcessAtOnce(t *testing.T) {
	t.Parallel()
	p := startServe(t, nil, dev)
	p.ready(t, 10*time.Second)
	heldRegistration(t, p)
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	// The listener closes as Shutdown begins, once the first is taken.
	for start := time.Now(); p.listening(); time.Sleep(20 * time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatal("serve still listens 5 s after a SIGINT")
		}
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	st := p.exit(t, 2*time.Second)
	if ws, ok := st.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Fatalf("serve ended %v on a second SIGINT; want ended by it", st)
	}
}

func onPostgres() bool { return os.Getenv("DROMAS_TEST_POSTGRES") != "" }

// migrated is the database libpq's environment names, migrated once, as
// test/interop.sh migrates it before its serve runs there.
var migrated = sync.OnceValue(func() error { return migrate(nil) })

// startServeOnPostgres is serve on the database libpq's environment names,
// its bodies in a directory of the test's own, ready, and the
// application_name its connections carry, its feed's walsender's among
// them, so that one is this process's alone.
func startServeOnPostgres(t *testing.T) (*serveProcess, string) {
	t.Helper()
	if err := migrated(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	app := "dromas_test_" + hex.EncodeToString(b)
	data := t.TempDir()
	p := startServe(t, []string{"PGAPPNAME=" + app}, func(addr string) []string {
		return []string{"--data-dir", data, "--names", addr}
	})
	p.ready(t, 90*time.Second) // the feed's first sync, which waits on the walsender's keepalive
	return p, app
}

// holdingSend is a transport that holds a send's last byte until release is
// closed, once the server has asked for its body (Expect: 100-continue), and
// closes held as it does: the send is then in its handler, reading its body.
type holdingSend struct {
	base          http.RoundTripper
	held, release chan struct{}
	once          sync.Once // held is closed once, whatever a retry sends
}

func (h *holdingSend) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/messages") || r.ContentLength < 2 {
		return h.base.RoundTrip(r)
	}
	r = r.Clone(r.Context())
	r.Header.Set("Expect", "100-continue")
	r.Body = &heldBody{ReadCloser: r.Body, left: r.ContentLength, h: h}
	return h.base.RoundTrip(r)
}

// heldBody is a body whose last byte waits for its holdingSend's release.
type heldBody struct {
	io.ReadCloser
	left   int64
	h      *holdingSend
	waited bool
}

func (b *heldBody) Read(p []byte) (int, error) {
	if !b.waited {
		if b.left == 1 {
			b.waited = true
			b.h.once.Do(func() { close(b.h.held) })
			<-b.h.release
		} else if int64(len(p)) >= b.left {
			p = p[:b.left-1]
		}
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// A request in flight at a signal is answered from the store, which ends
// only once Shutdown has answered every request, as Caddy runs its stop
// callbacks after its servers have shut down and Mattermost closes its store
// last: a send whose body is still arriving at a SIGTERM is stored, and
// serve exits 0. Control: a store whose pool closes at the signal answers it
// 503.
func TestASendInFlightAtASignalIsStored(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	p, _ := startServeOnPostgres(t)
	ctx := context.Background()
	h := &holdingSend{base: &http.Transport{ExpectContinueTimeout: time.Minute}, held: make(chan struct{}), release: make(chan struct{})}
	opts := client.Options{Base: "http://" + p.addr, HTTPClient: &http.Client{Transport: h, Timeout: 2 * time.Minute}}
	from, err := client.Init(ctx, t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	to, err := client.Init(ctx, t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() {
		_, err := from.Send(ctx, to.Address(), strings.Repeat("in flight ", 1000))
		sent <- err
	}()
	select {
	case <-h.held:
	case err := <-sent:
		t.Fatalf("the send was answered before its body was held: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the send's body was not asked for within 30 s")
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); p.listening(); time.Sleep(20 * time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatal("serve still listens 5 s after a SIGTERM")
		}
	}
	close(h.release)
	if err := <-sent; err != nil {
		t.Fatalf("the send in flight at the signal: %v; want it stored", err)
	}
	if st := p.exit(t, 30*time.Second); st.ExitCode() != 0 {
		t.Fatalf("serve exited %v after a signal; want 0", st)
	}
}

// A feed that loses its place ends serve with an error, so the process
// exits 1 and its supervisor starts it again, which rebuilds memory: here
// the feed's walsender is ended. Control: a serve that returns nil after
// Shutdown, whatever the feed, exits 0.
func TestALostFeedEndsServeWithAnError(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	p, app := startServeOnPostgres(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx) //nolint:errcheck // the test is ending
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_replication WHERE application_name = $1`, app).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ending the feed's session: %d sessions, %v; want 1", n, err)
	}
	st := p.exit(t, 30*time.Second)
	if st.ExitCode() != 1 || !strings.Contains(p.log(), "stopped: memory could not be shown current") {
		t.Fatalf("serve exited %v with its feed lost; want 1, saying memory could not be shown current", st)
	}
}
