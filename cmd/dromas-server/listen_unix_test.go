//go:build unix

package main

import (
	"net"
	"syscall"
	"testing"
)

// A connection --listen accepts sends no TCP keep-alive probes: SO_KEEPALIVE
// is off on it, read from the socket itself. A held list holds nothing but
// its goroutine and its connection, and each phase of a connection has a
// bound of its own. Control: net.Listen's own connection has it on.
func TestAnAcceptedConnectionSendsNoKeepAlive(t *testing.T) {
	t.Parallel()
	ls, err := listenAll("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ls[0].Close() //nolint:errcheck // the test is ending
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close() //nolint:errcheck // the test is ending
	if on := keepAlive(t, plain); !on {
		t.Fatal("control: net.Listen's accepted connection has SO_KEEPALIVE off")
	}
	if on := keepAlive(t, ls[0]); on {
		t.Error("a connection --listen accepted has SO_KEEPALIVE on")
	}
}

// keepAlive dials l, accepts the connection, and reports whether
// SO_KEEPALIVE is on on the accepted end.
func keepAlive(t *testing.T, l net.Listener) bool {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck // the test is ending
	a, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close() //nolint:errcheck // the test is ending
	raw, err := a.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := raw.Control(func(fd uintptr) { v, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE) }); err != nil || serr != nil {
		t.Fatalf("reading SO_KEEPALIVE: %v, %v", err, serr)
	}
	return v != 0
}
