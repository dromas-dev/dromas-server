package main

import (
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-server/internal/server"
)

// dromasd serve refuses to start on a budget of new mail that would let a
// box take mail faster than server.ReceiveCeiling, one turned off or one
// refilled faster, naming the flag. It refuses before it listens or opens any
// store, as for a size cap.
func TestServeRefusesNewMailPastTheCeiling(t *testing.T) {
	for _, c := range []struct{ flag, value, says string }{
		{"-receive-burst", "0", "no budget"},
		{"-receive-burst", "-1", "no budget"},
		{"-receive-refill", "0s", "shorter than"},
		{"-receive-refill", (server.ReceiveCeiling - time.Millisecond).String(), "shorter than"},
	} {
		done := make(chan error, 1)
		go func() { done <- serve([]string{"--dev", "-listen", "127.0.0.1:0", c.flag, c.value}) }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), c.flag+":") || !strings.Contains(err.Error(), c.says) {
				t.Errorf("%s %s: %v, want a refusal naming the flag and saying %q", c.flag, c.value, err, c.says)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s %s: serve started", c.flag, c.value)
		}
	}
}

// Control: a budget of one at the ceiling passes, and so do the defaults.
func TestNewMailAtTheCeilingPasses(t *testing.T) {
	l := server.DefaultLimits()
	l.ReceiveBurst, l.ReceiveRefill = 1, server.ReceiveCeiling
	if err := receiveRate(l); err != nil {
		t.Errorf("at the ceiling: %v", err)
	}
	if err := receiveRate(server.DefaultLimits()); err != nil {
		t.Errorf("the defaults: %v", err)
	}
}
