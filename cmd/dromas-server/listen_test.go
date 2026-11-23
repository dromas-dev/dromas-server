package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-server/internal/server"
)

// --listen takes several addresses, and one server answers on every one: a
// reverse proxy in front spreads its connections across them, each one more
// range of its ephemeral ports (dromas-dev/dromas-server#124 item 6). An
// address that cannot be listened on fails the whole list, naming it, and
// leaves none of the others open; an empty list is refused.
func TestOneServerAnswersOnEveryListenAddress(t *testing.T) {
	t.Parallel()
	ls, err := listenAll("127.0.0.1:0, 127.0.0.1:0,,127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 3 {
		t.Fatalf("%d listeners, want 3", len(ls))
	}
	srv := server.HTTPServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), server.DefaultLimits(), time.Minute)
	for _, l := range ls {
		go func() { _ = srv.Serve(l) }()
	}
	defer srv.Close() //nolint:errcheck // the test is ending
	for _, l := range ls {
		resp, err := http.Get("http://" + l.Addr().String() + "/")
		if err != nil {
			t.Fatalf("%s: %v", l.Addr(), err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != "ok" {
			t.Fatalf("%s: %q", l.Addr(), b)
		}
	}

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck // the test is ending
	// The address before the one in use is free, then listened on again: a
	// listenAll that left it open fails that every time. The tests run in
	// parallel, children of serve among them, so another test's listener can
	// take the freed port first: before listenAll listens on it (its error
	// then names the freed address, not the one in use), or between listenAll
	// and the listen again. Either is a try that proves nothing, and the next
	// try takes a new port (dromas-dev/dromas-server#368).
	heldAddr := held.Addr().String()
	var left error
	checked := false
	for range 10 {
		free, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		freeAddr := free.Addr().String()
		_ = free.Close()
		_, err = listenAll(freeAddr + "," + heldAddr)
		switch named := listenedOn(err); {
		case named == freeAddr:
			continue
		case named != heldAddr:
			t.Fatalf("a list with an address in use: %v, want an error naming %s", err, heldAddr)
		}
		checked = true
		again, err := net.Listen("tcp", freeAddr)
		if left = err; err == nil {
			_ = again.Close()
			break
		}
	}
	if !checked {
		t.Fatal("another test took every freed port before listenAll listened on it")
	}
	if left != nil {
		t.Fatalf("the address before the one in use was left open: %v", left)
	}
	if _, err := listenAll(" , "); err == nil {
		t.Fatal("an empty list was taken")
	}
}

// listenedOn is the address a listen error names, or "" for none.
func listenedOn(err error) string {
	if op, ok := errors.AsType[*net.OpError](err); ok && op.Addr != nil {
		return op.Addr.String()
	}
	return ""
}
