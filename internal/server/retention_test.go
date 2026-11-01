package server

import (
	"context"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A message this server still serves is one its reader takes: each post is
// dated afresh, and the server keeps a message the TTL less the hour after it
// received it, so a reader whose clock the server takes refuses none as
// stale before its expires_at (PROTOCOL.md §12.2, §13). A message mailbox_full
// held in its sender's outbox is the case the TTL's promise is for, read as
// seldom as a mailbox's prekey lets it (client.RecvWithin).
func TestAMessageIsTakenWhileTheServerServesIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	every := client.RecvWithin(protocol.PrekeyLifetime)
	t.Run("held by mailbox_full, read as seldom as its prekey lets it", func(t *testing.T) {
		const mailboxCap = 3
		l := relaxed()
		l.MailboxCap = mailboxCap
		e := newEnv(t, l)
		off := time.Duration(0)
		s, err := client.Init(ctx, t.TempDir(), e.skewed(&off))
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.Init(ctx, t.TempDir(), e.skewed(&off))
		if err != nil {
			t.Fatal(err)
		}
		landAll(t, r)
		held := 0
		for range mailboxCap + 1 {
			if _, err := s.Send(ctx, r.Address(), "a message"); codeOf(err) == protocol.CodeMailboxFull {
				held++
			}
		}
		if held != 1 {
			t.Fatalf("%d held by mailbox_full, want 1", held)
		}
		e.clock.Add(every)
		if got := len(receive(t, r).Delivered); got != mailboxCap {
			t.Fatalf("after %v: delivered %d", every, got)
		}
		sent, err := s.Flush(ctx)
		if err != nil || len(sent) != 1 {
			t.Fatalf("flush: %v, %v", sent, err)
		}
		e.clock.Add(every)
		res := receive(t, r)
		t.Logf("after %v, expires_at %s: delivered %d, refused %v", 2*every, sent[0].ExpiresAt, len(res.Delivered), res.Refused)
		if len(res.Delivered) != 1 {
			t.Error("refused while the server served it")
		}
	})
	for _, c := range []struct {
		name           string
		sender, reader time.Duration
		before         time.Duration // read this long before the receipt's expires_at
	}{
		{"sender 9m slow, reader 49m fast, read 30m before expires_at", -9 * time.Minute, 49 * time.Minute, 30 * time.Minute},
		{"sender 9m slow, reader 49m fast, read a minute before expires_at", -9 * time.Minute, 49 * time.Minute, time.Minute},
		{"sender 49m fast, reader 9m slow, read a minute before expires_at", 49 * time.Minute, -9 * time.Minute, time.Minute},
		{"control: both right", 0, 0, time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, relaxed())
			so, ro := c.sender, c.reader
			s, err := client.Init(ctx, t.TempDir(), e.skewed(&so))
			if err != nil {
				t.Fatal(err)
			}
			r, err := client.Init(ctx, t.TempDir(), e.skewed(&ro))
			if err != nil {
				t.Fatal(err)
			}
			landAll(t, r)
			sent, err := s.Send(ctx, r.Address(), "a message")
			if err != nil {
				t.Fatal(err)
			}
			received, _ := protocol.ParseTime(sent.ReceivedAt)
			expires, _ := protocol.ParseTime(sent.ExpiresAt)
			if !expires.Equal(received.Add(protocol.Retention)) {
				t.Errorf("expires_at %s, want received_at %s and the TTL less the hour", sent.ExpiresAt, sent.ReceivedAt)
			}
			e.clock.Add(expires.Sub(e.clock.Now()) - c.before)
			res := receive(t, r)
			if len(res.Delivered) != 1 {
				t.Errorf("expires_at %s, read %v before it: delivered %d, refused %v", sent.ExpiresAt, c.before, len(res.Delivered), res.Refused)
			}
		})
	}
}
