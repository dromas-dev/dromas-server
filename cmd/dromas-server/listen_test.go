package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-server/internal/server"
)

// -listen takes several addresses, and one server answers on every one: a
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
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	_ = free.Close()
	if _, err := listenAll(freeAddr + "," + held.Addr().String()); err == nil || !strings.Contains(err.Error(), held.Addr().String()) {
		t.Fatalf("a list with an address in use: %v, want an error naming it", err)
	}
	again, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Fatalf("the address before the one in use was left open: %v", err)
	}
	_ = again.Close()
	if _, err := listenAll(" , "); err == nil {
		t.Fatal("an empty list was taken")
	}
}
