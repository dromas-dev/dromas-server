package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// dromas-server serve refuses to start on a cap on a ciphertext above the
// protocol's largest (PROTOCOL.md §11.10), or on one that is not a whole number
// of its own padding blocks (§9.3), naming the flag. It refuses before it
// listens or opens any store, so each call returns at once; one that has not
// returned in a few seconds has started a server, which ends with the test.
func TestServeRefusesASizeCapTheProtocolDoesNotAllow(t *testing.T) {
	for _, flag := range []string{"-max-size", "-account-max-size"} {
		for _, c := range []struct {
			n    int
			says string
		}{
			{protocol.MaxCiphertext + 1, "over the largest ciphertext"},
			{2 * protocol.MaxCiphertext, "over the largest ciphertext"},
			{100 << 10, "not a whole number of its own padding blocks"},
			{protocol.MaxCiphertext - 1, "not a whole number of its own padding blocks"},
			{-1, "not a size"},
		} {
			done := make(chan error, 1)
			go func() { done <- serve([]string{"--dev", "-listen", "127.0.0.1:0", flag, fmt.Sprint(c.n)}) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), flag+":") || !strings.Contains(err.Error(), c.says) {
					t.Errorf("%s %d: %v, want a refusal naming the flag and saying %q", flag, c.n, err, c.says)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s %d: serve started", flag, c.n)
			}
		}
	}
}

// Control: the caps the protocol allows pass, its largest ciphertext among
// them, and so do the defaults.
func TestASizeCapOnABlockAndWithinTheLargestPasses(t *testing.T) {
	for _, n := range []int{0, protocol.PadMinBlock, 64 << 10, 10 << 20, protocol.MaxCiphertext} {
		l := server.DefaultLimits()
		l.MaxSize, l.AccountMaxSize = n, n
		if err := sizeCaps(l); err != nil {
			t.Errorf("%d: %v", n, err)
		}
	}
	if err := sizeCaps(server.DefaultLimits()); err != nil {
		t.Errorf("the defaults: %v", err)
	}
}
