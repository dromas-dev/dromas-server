package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// dromas-server serve refuses to start on a budget of new messages that would let a
// mailbox take messages faster than server.ReceiveCeiling, one turned off or one
// refilled faster, naming the flag. It refuses before it listens or opens any
// store, as for a size cap.
func TestServeRefusesNewMessagesPastTheCeiling(t *testing.T) {
	for _, c := range []struct{ flag, value, says string }{
		{"--receive-burst", "0", "no budget"},
		{"--receive-burst", "-1", "no budget"},
		{"--receive-refill", "0s", "shorter than"},
		{"--receive-refill", (server.ReceiveCeiling - time.Millisecond).String(), "shorter than"},
	} {
		done := make(chan error, 1)
		go func() { done <- serve([]string{"--dev", "--listen", "127.0.0.1:0", c.flag, c.value}) }()
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
func TestNewMessagesAtTheCeilingPass(t *testing.T) {
	l := server.DefaultLimits()
	l.ReceiveBurst, l.ReceiveRefill = 1, server.ReceiveCeiling
	if err := receiveRate(l); err != nil {
		t.Errorf("at the ceiling: %v", err)
	}
	if err := receiveRate(server.DefaultLimits()); err != nil {
		t.Errorf("the defaults: %v", err)
	}
}

// dromas-server serve refuses to start on an ACL bound that is off or over the
// protocol's (PROTOCOL.md §11.14), naming the flag, before it listens.
func TestServeRefusesAnACLBoundOffOrOverTheProtocols(t *testing.T) {
	for _, v := range []string{"0", "-1", strconv.Itoa(protocol.MaxACLEntries + 1)} {
		done := make(chan error, 1)
		go func() { done <- serve([]string{"--dev", "--listen", "127.0.0.1:0", "--acl-entries", v}) }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "--acl-entries:") {
				t.Errorf("--acl-entries %s: %v, want a refusal naming the flag", v, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("--acl-entries %s: serve started", v)
		}
	}
}

// Control: one, the protocol's bound and the default pass.
func TestAnACLBoundInRangePasses(t *testing.T) {
	for _, n := range []int{1, protocol.MaxACLEntries, server.DefaultLimits().ACLEntries} {
		l := server.DefaultLimits()
		l.ACLEntries = n
		if err := aclEntries(l); err != nil {
			t.Errorf("%d: %v", n, err)
		}
	}
}

// dromas-server serve refuses to start on a longest certificate it takes that
// is not above the message TTL and the hour together, naming the flag, before
// it listens: a certificate no longer signs no message (PROTOCOL.md §11.18).
func TestServeRefusesAMaximumCertificateThatSignsNoMessage(t *testing.T) {
	least := protocol.TTL + protocol.MaxSkew
	for _, v := range []time.Duration{0, least, least - time.Second} {
		done := make(chan error, 1)
		go func() {
			done <- serve([]string{"--dev", "--listen", "127.0.0.1:0", "--max-certificate-lifetime", v.String()})
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "--max-certificate-lifetime:") {
				t.Errorf("--max-certificate-lifetime %v: %v, want a refusal naming the flag", v, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("--max-certificate-lifetime %v: serve started", v)
		}
	}
}

// Control: a second above the least, and the default, pass.
func TestAMaximumCertificateAboveTheTTLPasses(t *testing.T) {
	for _, d := range []time.Duration{protocol.TTL + protocol.MaxSkew + time.Second, server.DefaultLimits().MaxCertificateLifetime} {
		l := server.DefaultLimits()
		l.MaxCertificateLifetime = d
		if err := certificateLifetime(l); err != nil {
			t.Errorf("%v: %v", d, err)
		}
	}
}
