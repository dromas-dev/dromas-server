package server

import (
	"context"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A message this server still serves is one its reader takes: each post is
// dated afresh, and the server keeps mail the TTL less the hour after it
// received it, so a reader whose clock the server takes refuses none as
// stale before its expires_at (PROTOCOL.md §12.2, §13). A message pair_full
// held in its sender's outbox is the case the TTL's monthly promise is for.
func TestMailIsTakenWhileTheServerServesIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	day := 24 * time.Hour
	t.Run("held by pair_full, read every 30 days", func(t *testing.T) {
		e := newEnv(t, relaxed()) // PairCap stays at its default
		off := time.Duration(0)
		s, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		landAll(t, r)
		held := 0
		for i := 0; i <= DefaultLimits().PairCap; i++ {
			if _, err := s.Send(ctx, r.Address(), "a message"); codeOf(err) == protocol.CodePairFull {
				held++
			}
		}
		if held != 1 {
			t.Fatalf("%d held by pair_full, want 1", held)
		}
		e.clock.Add(30 * day)
		if got := len(receive(t, r).Delivered); got != DefaultLimits().PairCap {
			t.Fatalf("day 30: delivered %d", got)
		}
		sent, err := s.Flush(ctx)
		if err != nil || len(sent) != 1 {
			t.Fatalf("flush: %v, %v", sent, err)
		}
		e.clock.Add(30 * day)
		res := receive(t, r)
		t.Logf("day 60, expires_at %s: delivered %d, refused %v", sent[0].ExpiresAt, len(res.Delivered), res.Refused)
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
			s, err := client.Init(ctx, t.TempDir(), e.skewed(&so), protocol.Classic)
			if err != nil {
				t.Fatal(err)
			}
			r, err := client.Init(ctx, t.TempDir(), e.skewed(&ro), protocol.Classic)
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
