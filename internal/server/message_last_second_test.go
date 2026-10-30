package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The sender as far behind as a server takes (9m59s), the reader as far
// ahead (50m), read just before the receipt's expires_at. The server's
// clock moves by delay while the sender reads the recipient's mailbox, which a
// client does before it dates the post, so the delay is not between the
// dating and the server's receipt (client#278). What is, the seal and the
// second the dating truncates, is the room protocol.Retention leaves
// (protocol.PostTime); the request's own time is bounded by its pass.
func TestAMessageAtTheLastSecondOfItsLife(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		name           string
		sender, reader time.Duration
		delay          time.Duration // added to the server's clock while the sender reads the recipient's mailbox
		postDelay      time.Duration // added to the server's clock as the post arrives
		before         time.Duration // read this long before expires_at
	}{
		{"no delay, read 1s before", -(10*time.Minute - time.Second), 50 * time.Minute, 0, 0, time.Second},
		{"a read of the mailbox of 3s, read 1s before", -(10*time.Minute - time.Second), 50 * time.Minute, 3 * time.Second, 0, time.Second},
		{"a read of the mailbox of 10s, read 5s before", -(10*time.Minute - time.Second), 50 * time.Minute, 10 * time.Second, 0, 5 * time.Second},
		{"a read of the mailbox of 10s, read 10s before", -(10*time.Minute - time.Second), 50 * time.Minute, 10 * time.Second, 0, 10 * time.Second},
		{"control: a read of the mailbox of 10s, both clocks right, read 1s before", 0, 0, 10 * time.Second, 0, time.Second},
		{"a read of the mailbox of 5m, longer than the room protocol.Retention leaves, read 1s before", -(10*time.Minute - time.Second), 50 * time.Minute, 5 * time.Minute, 0, time.Second},
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
			read := "/v1/" + r.Address().String()
			e.setMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				if q.Method == http.MethodGet && q.URL.Path == read {
					e.clock.Add(c.delay)
				}
				if q.Method == http.MethodPost && q.URL.Path == read+"/messages" {
					e.clock.Add(c.postDelay)
				}
				next.ServeHTTP(w, q)
			})
			sent, err := s.Send(ctx, r.Address(), "a message")
			e.setMiddle(nil)
			if err != nil {
				t.Fatal(err)
			}
			expires, _ := protocol.ParseTime(sent.ExpiresAt)
			e.clock.Add(expires.Sub(e.clock.Now()) - c.before)
			res := receive(t, r)
			t.Logf("received_at %s, expires_at %s, read %v before it by the server's clock: delivered %d, refused %v", sent.ReceivedAt, sent.ExpiresAt, c.before, len(res.Delivered), res.Refused)
			if len(res.Delivered) != 1 {
				t.Error("refused while the server served it")
			}
		})
	}
}
