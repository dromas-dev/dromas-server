package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveArgs, set in a test binary's environment, makes it dromas-server
// serve with these arguments, one to a line (TestMain), so a test can run a
// serve of its own and signal it, as os/exec's tests run their helper
// process. That serve exits once its stdin ends, as it does when the test
// binary that holds the pipe's other end is gone, however it went.
const serveArgs = "DROMAS_TEST_SERVE_ARGS"

func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv(serveArgs); ok {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			fmt.Fprintln(os.Stderr, "the test that ran this serve is gone")
			os.Exit(1)
		}()
		os.Args = append([]string{"dromas-server", "serve"}, strings.Split(args, "\n")...)
		main() // log.Fatal, exit 1, on serve's error
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// serveProcess is a dromas-server serve of the test's own, in a process.
type serveProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser // held open while the test runs
	addr   string         // its --listen
	mu     sync.Mutex
	stderr bytes.Buffer
	exited chan struct{} // closed once it has exited, cmd.ProcessState then set
}

// startServe runs serve on a free loopback port, with env added to the
// test's environment, less every DROMAS_SERVER_ variable, and the arguments
// args gives for that address after --listen, and waits within d for it to
// answer GET /v1/ 200; it is killed when the test ends. A port taken between
// its choice and serve's listen is chosen again, once.
func startServe(t *testing.T, env []string, args func(addr string) []string, d time.Duration) *serveProcess {
	t.Helper()
	for try := 1; ; try++ {
		p := launchServe(t, env, args)
		err := p.ready(d)
		if err == nil {
			return p
		}
		if try == 1 && p.gone() && strings.Contains(p.log(), "address already in use") {
			t.Logf("%s was taken before serve listened on it: another", p.addr)
			continue
		}
		t.Fatal(err)
	}
}

// launchServe runs serve as startServe says, and returns at once.
func launchServe(t *testing.T, env []string, args func(addr string) []string) *serveProcess {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &serveProcess{addr: l.Addr().String(), exited: make(chan struct{})}
	_ = l.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p.cmd = exec.Command(exe, "-test.run=^$")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, envPrefix+"_") {
			p.cmd.Env = append(p.cmd.Env, kv)
		}
	}
	p.cmd.Env = append(p.cmd.Env, env...)
	p.cmd.Env = append(p.cmd.Env, serveArgs+"="+strings.Join(append([]string{"--listen", p.addr}, args(p.addr)...), "\n"))
	p.cmd.Stderr = lockedWriter{&p.mu, &p.stderr}
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.exited) }()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.exited
		if t.Failed() {
			t.Logf("serve's log:\n%s", p.log())
		}
	})
	return p
}

// log is what the process has written to its stderr.
func (p *serveProcess) log() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stderr.String()
}

// gone reports whether the process has exited.
func (p *serveProcess) gone() bool {
	select {
	case <-p.exited:
		return true
	default:
		return false
	}
}

// ready waits for the process to answer GET /v1/ 200, within d.
func (p *serveProcess) ready(d time.Duration) error {
	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		if p.gone() {
			return fmt.Errorf("serve exited before it was ready: %v", p.cmd.ProcessState)
		}
		if resp, err := http.Get("http://" + p.addr + "/v1/"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Since(start) > d {
			return fmt.Errorf("serve is not ready after %v", d)
		}
	}
}

// exit waits for the process to exit, within d, and is its state.
func (p *serveProcess) exit(t *testing.T, d time.Duration) *os.ProcessState {
	t.Helper()
	select {
	case <-p.exited:
		return p.cmd.ProcessState
	case <-time.After(d):
		t.Fatalf("serve has not exited %v later", d)
		return nil
	}
}

// listening reports whether the process accepts a connection on --listen.
func (p *serveProcess) listening() bool {
	c, err := net.DialTimeout("tcp", p.addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// lockedWriter is a writer that takes a lock around each write.
type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
