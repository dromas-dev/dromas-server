package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// headOf sends head, a request's head, to addr, and returns the status of
// its answer.
func headOf(t *testing.T, addr, head string) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck // a test's connection
	if _, err := c.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The API's server reads a request's head to --max-header-bytes and no
// further, before any handler sees it: what the longest call needs is read,
// a send with both serials at their largest, a pass as long as a pass can
// be and a server's name as long as one can be, with a client's other
// headers and those a proxy in front adds; a longer head is refused 431
// before any handler runs. With the bound off, net/http's default, the
// longer head is read.
func TestTheHeadIsReadToWhatTheLongestCallNeeds(t *testing.T) {
	serve := func(l server.Limits) (string, *int) {
		reached := new(int)
		srv := server.HTTPServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			*reached++
			w.WriteHeader(http.StatusNoContent)
		}), l, time.Minute)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		return ln.Addr().String(), reached
	}
	host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57) + ":65535"
	if err := protocol.CheckServerName(host); err != nil || len(host) != 255 {
		t.Fatalf("not a server's name: %v", err)
	}
	pass := "dromas-pass " + strings.Repeat("a", protocol.MaxPassAuthorization-len("dromas-pass "))
	serial := fmt.Sprint(protocol.MaxSerial)
	longest := "POST /v1/" + strings.Repeat("0", 64) + "/messages?prekey_serial=" + serial + "&certificate_serial=" + serial + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Authorization: " + pass + "\r\n" +
		"User-Agent: Go-http-client/1.1\r\n" +
		"Content-Type: " + protocol.CiphertextContentType + "\r\n" +
		"Content-Length: 0\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"If-None-Match: \"" + strings.Repeat("0", 64) + "\"\r\n" +
		// A proxy's: the address it took the call from, and a few of its own.
		"Cf-Connecting-Ip: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\r\n" +
		"X-Forwarded-For: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\r\n" +
		"X-Forwarded-Proto: https\r\n" +
		"Forwarded: for=\"[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]\";proto=https\r\n" +
		"Via: 1.1 " + strings.Repeat("v", 40) + "\r\n" +
		"X-Request-Id: " + strings.Repeat("r", 36) + "\r\n" +
		"Connection: close\r\n\r\n"
	l := server.DefaultLimits()
	addr, reached := serve(l)
	if got := headOf(t, addr, longest); got != http.StatusNoContent || *reached != 1 {
		t.Fatalf("the longest call, a head of %d bytes: %d, reached %d", len(longest), got, *reached)
	}
	over := "GET /v1/x HTTP/1.1\r\nHost: x\r\nX: " + strings.Repeat("a", 2*l.HeadBytes) + "\r\nConnection: close\r\n\r\n"
	if got := headOf(t, addr, over); got != http.StatusRequestHeaderFieldsTooLarge || *reached != 1 {
		t.Fatalf("a head of %d bytes: %d, reached %d", len(over), got, *reached)
	}
	l.HeadBytes = 0
	addr, reached = serve(l)
	if got := headOf(t, addr, over); got != http.StatusNoContent || *reached != 1 {
		t.Fatalf("with no bound, a head of %d bytes: %d, reached %d", len(over), got, *reached)
	}
	t.Logf("the longest call's head: %d bytes, under --max-header-bytes %d", len(longest), server.DefaultLimits().HeadBytes)
}
