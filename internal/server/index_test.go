package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// loaded is an index holding mailbox, loaded with read.
// Each index tags its marks under a random key of its own, so nobody
// outside the process can compute a tag.
func TestTheMarkKeyIsRandom(t *testing.T) {
	t.Parallel()
	x, y := newIndex(), newIndex()
	if x.key == ([32]byte{}) || x.key == y.key {
		t.Fatalf("mark keys %x and %x", x.key, y.key)
	}
}

func loaded(t *testing.T, mailbox protocol.Address, read mailboxRead) *index {
	t.Helper()
	x := newIndex()
	if err := x.ensure(context.Background(), mailbox, func() (mailboxRead, error) { return read, nil }); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *index) tombs(mailbox protocol.Address) int {
	sh := x.shard(mailbox)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return len(sh.mailboxes[mailbox].tombs)
}

// Layer 1 must stay exact when a change arrives twice, late, or out of
// order with this process's own writes (ARCHITECTURE.md § Memory).
func TestIndex(t *testing.T) {
	t.Parallel()
	var mailbox protocol.Address
	mailbox[0] = 7
	const now = 1_000_000
	k1 := mark{tag: 1, id: 1, exp: now + 500}
	k2 := mark{tag: 2, id: 2, exp: now + 900}

	t.Run("a set: inserts twice count once", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{})
		x.insert(mailbox, k1, now)
		x.insert(mailbox, k1, now) // the stream's echo of our own write
		x.insert(mailbox, k2, now)
		if n := x.count(mailbox, now); n != 2 || !x.holds(mailbox, k1.tag, now) || !x.holds(mailbox, k2.tag, now) {
			t.Fatalf("count %d", n)
		}
	})

	t.Run("a late insert does not bring back an ack", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{})
		x.insert(mailbox, k1, now)
		x.remove(mailbox, k1.tag, k1.exp, now, false) // our ack
		x.insert(mailbox, k1, now)                    // the stream's late insert
		if n := x.count(mailbox, now); n != 0 {
			t.Fatal("the acked message came back")
		}
		x.deleted(mailbox, k1.tag, now) // the deletion's echo clears the tomb
		if x.tombs(mailbox) != 0 {
			t.Fatal("the tomb outlived its echo")
		}
	})

	t.Run("an ack of a message the stream has not shown yet", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{})
		x.remove(mailbox, k1.tag, k1.exp, now, false)
		x.insert(mailbox, k1, now)
		if n := x.count(mailbox, now); n != 0 {
			t.Fatal("the acked message came back")
		}
	})

	t.Run("a tomb whose echo came first dies at its expiry", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{})
		x.insert(mailbox, k1, now)
		x.deleted(mailbox, k1.tag, now)               // the echo, first
		x.remove(mailbox, k1.tag, k1.exp, now, false) // then our own apply
		x.count(mailbox, k1.exp)
		if x.tombs(mailbox) != 0 {
			t.Fatal("the tomb outlived the message's expiry")
		}
	})

	t.Run("expiry, with no event", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{})
		x.insert(mailbox, k1, now)
		x.insert(mailbox, k2, now)
		if n := x.count(mailbox, k1.exp-1); n != 2 || !x.holds(mailbox, k1.tag, k1.exp-1) || !x.holds(mailbox, k2.tag, k1.exp-1) {
			t.Fatalf("before expiry: %d", n)
		}
		if n := x.count(mailbox, k1.exp); n != 1 || !x.holds(mailbox, k2.tag, k1.exp) {
			t.Fatalf("at expiry: %d", n)
		}
		x.insert(mailbox, mark{tag: 3, id: 3, exp: now}, now)
		if n := x.count(mailbox, now); n != 1 {
			t.Fatal("an expired insert counted")
		}
	})

	t.Run("a removal by image names the message, not just its id", func(t *testing.T) {
		// The same ciphertext, resent after the first expired: the late
		// removal of the first must not remove the second.
		x := loaded(t, mailbox, mailboxRead{})
		again := mark{tag: k1.tag, id: k1.id, exp: k1.exp + 1000}
		x.insert(mailbox, again, k1.exp)
		x.remove(mailbox, k1.tag, k1.exp, k1.exp, true)
		if n := x.count(mailbox, k1.exp); n != 1 {
			t.Fatal("the resent message was removed")
		}
	})

	t.Run("a deletion takes the earliest of its id", func(t *testing.T) {
		// The same ciphertext, posted again after an ack: the ack's
		// deletion, which names the id alone, takes the first, whether
		// this process acked it (a tomb) or the stream brought it (a mark),
		// and leaves the second, which this process stored before the
		// deletion's echo.
		again := mark{tag: k1.tag, id: k1.id, exp: k1.exp + 100}
		for _, ours := range []bool{true, false} {
			x := loaded(t, mailbox, mailboxRead{})
			x.insert(mailbox, k1, now)
			if ours {
				x.remove(mailbox, k1.tag, k1.exp, now, false)
			}
			x.insert(mailbox, again, now)
			x.deleted(mailbox, k1.tag, now)
			x.insert(mailbox, again, now) // the stream's insert of the second, after
			if n := x.count(mailbox, now); n != 1 || !x.holds(mailbox, k1.tag, now) || x.tombs(mailbox) != 0 {
				t.Fatalf("acked by this process %v: count %d, tombs %d; want the second alone", ours, n, x.tombs(mailbox))
			}
		}
		// A deletion after the first expired, by the TTL, finds only the
		// second: it goes, and the stream's insert of it, which comes after
		// the deletion, brings it back.
		x := loaded(t, mailbox, mailboxRead{})
		x.insert(mailbox, again, k1.exp)
		x.deleted(mailbox, k1.tag, k1.exp)
		x.insert(mailbox, again, k1.exp)
		if n := x.count(mailbox, k1.exp); n != 1 {
			t.Fatalf("after the TTL's late deletion and the second's insert: count %d", n)
		}
	})

	t.Run("standing only moves forward", func(t *testing.T) {
		first, second := Standing{State: Active, Signer: [32]byte{1}}, Standing{State: Active, Signer: [32]byte{2}}
		x := loaded(t, mailbox, mailboxRead{exists: true, st: first, rev: 1})
		x.setStanding(mailbox, second, version{rev: 3})
		x.setStanding(mailbox, first, version{rev: 1}) // a late image
		if st, ok := x.standing(mailbox); !ok || st != second {
			t.Fatalf("standing %v %v", st, ok)
		}
		x.setStanding(mailbox, Standing{State: Active, Signer: [32]byte{3}}, version{rev: 4})
		if st, _ := x.standing(mailbox); st.Signer != [32]byte{3} {
			t.Fatal("a later standing not kept")
		}
		x.forget(mailbox)
		if _, ok := x.standing(mailbox); ok {
			t.Fatal("a deleted record kept its standing")
		}
		x.setStanding(mailbox, first, version{rev: 1}) // registered again: the next use loads it, so nothing is held until then
		if _, ok := x.standing(mailbox); ok {
			t.Fatal("a mailbox memory forgot was taken back from a change")
		}
	})

	t.Run("revocations only add", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{exists: true, st: Standing{State: Active, Rank: 5}, rev: 1})
		x.setRevocations(mailbox, false, 4)
		if st, _ := x.standing(mailbox); st.Listed {
			t.Fatal("certificates revoked through 4 listed the mailbox's 5")
		}
		x.setRevocations(mailbox, false, 5)
		x.setRevocations(mailbox, false, 2) // a lower one changes nothing
		if st, _ := x.standing(mailbox); !st.Listed {
			t.Fatal("certificates revoked through 5 did not list the mailbox's 5")
		}
		x.setStanding(mailbox, Standing{State: Active, Rank: 6}, version{rev: 2}) // a renewal above them
		if st, _ := x.standing(mailbox); st.Listed {
			t.Fatal("a renewal above the revoked certificates is still listed")
		}
		x.setRevocations(mailbox, true, 0)
		x.setStanding(mailbox, Standing{State: Active, Rank: 7}, version{rev: 3})
		if st, ok := x.standing(mailbox); !ok || st.State != Revoked {
			t.Fatalf("a revoked address: %+v %v", st, ok)
		}
	})

	t.Run("a revoked address with no record", func(t *testing.T) {
		x := loaded(t, mailbox, mailboxRead{revoked: true})
		if st, ok := x.standing(mailbox); !ok || st.State != Revoked {
			t.Fatalf("a revoked address with no record: %+v %v", st, ok)
		}
		y := loaded(t, mailbox, mailboxRead{through: 9})
		if _, ok := y.standing(mailbox); ok {
			t.Fatal("an address with no mailbox has a standing")
		}
	})
}

// Memory holds a mailbox only after its first use loads it, and a change that
// arrives meanwhile is applied after the load.
func TestIndexLoad(t *testing.T) {
	t.Parallel()
	var mailbox protocol.Address
	mailbox[0] = 7
	const now = 1_000_000
	k1 := mark{tag: 1, id: 1, exp: now + 500}
	k2 := mark{tag: 2, id: 2, exp: now + 900}
	ctx := context.Background()

	t.Run("a change to a mailbox memory does not hold is dropped", func(t *testing.T) {
		x := newIndex()
		x.insert(mailbox, k1, now)
		x.setStanding(mailbox, Standing{State: Revoked}, version{rev: 9})
		if err := x.ensure(ctx, mailbox, func() (mailboxRead, error) {
			return mailboxRead{exists: true, st: Standing{State: Active}, rev: 1}, nil
		}); err != nil {
			t.Fatal(err)
		}
		if n := x.count(mailbox, now); n != 0 {
			t.Fatal("a change before the load was kept")
		}
		if st, _ := x.standing(mailbox); st.State != Active {
			t.Fatal("a standing before the load was kept")
		}
	})

	t.Run("a change during the load waits for it", func(t *testing.T) {
		x := newIndex()
		reading, release := make(chan struct{}), make(chan struct{})
		done := make(chan error)
		go func() {
			done <- x.ensure(ctx, mailbox, func() (mailboxRead, error) {
				close(reading)
				<-release
				// Read before the changes below: k1 was live, the mailbox at rev 1.
				return mailboxRead{exists: true, st: Standing{State: Active}, rev: 1, marks: []mark{k1}}, nil
			})
		}()
		<-reading
		if n := x.count(mailbox, now); n != 0 {
			t.Fatal("counted while loading")
		}
		x.remove(mailbox, k1.tag, k1.exp, now, true) // acked meanwhile
		x.insert(mailbox, k2, now)                   // and a new message
		x.setStanding(mailbox, Standing{State: Active, Signer: [32]byte{1}}, version{rev: 2})
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if n := x.count(mailbox, now); n != 1 || !x.holds(mailbox, k2.tag, now) {
			t.Fatalf("count %d: the queued changes were not applied after the load", n)
		}
		if st, _ := x.standing(mailbox); st.Signer != [32]byte{1} {
			t.Fatal("the queued standing was not applied")
		}
	})

	t.Run("callers at once share one read", func(t *testing.T) {
		x := newIndex()
		var reads, early atomic.Int32
		release := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = x.ensure(ctx, mailbox, func() (mailboxRead, error) {
					reads.Add(1)
					<-release
					return mailboxRead{exists: true}, nil
				})
				if _, ok := x.standing(mailbox); !ok {
					early.Add(1) // returned before the load ended
				}
			}()
		}
		time.Sleep(50 * time.Millisecond)
		close(release)
		wg.Wait()
		if n := reads.Load(); n != 1 {
			t.Fatalf("%d reads", n)
		}
		if n := early.Load(); n != 0 {
			t.Fatalf("%d callers returned before the load", n)
		}
		_ = x.ensure(ctx, mailbox, func() (mailboxRead, error) { reads.Add(1); return mailboxRead{}, nil })
		if reads.Load() != 1 {
			t.Fatal("a loaded mailbox was read again")
		}
	})

	t.Run("a failed load leaves the mailbox unloaded", func(t *testing.T) {
		x := newIndex()
		reading, release := make(chan struct{}), make(chan struct{})
		done := make(chan error)
		go func() {
			done <- x.ensure(ctx, mailbox, func() (mailboxRead, error) {
				close(reading)
				<-release
				return mailboxRead{}, errors.New("throttled")
			})
		}()
		<-reading
		x.insert(mailbox, k1, now) // queued, then dropped with the load
		close(release)
		if err := <-done; err == nil {
			t.Fatal("the error was not returned")
		}
		if err := x.ensure(ctx, mailbox, func() (mailboxRead, error) { return mailboxRead{exists: true}, nil }); err != nil {
			t.Fatal(err)
		}
		if n := x.count(mailbox, now); n != 0 {
			t.Fatal("a failed load's queued change was applied")
		}
		if _, ok := x.standing(mailbox); !ok {
			t.Fatal("not loaded on the retry")
		}
	})
}

// Every change memory applies to a mailbox wakes the lists held on it, from
// this process's writes and from the streams alike, since both pass
// through apply; one mailbox's change wakes no other's (PROTOCOL.md §11.11).
func TestEveryChangeToAMailboxWakesItsHeldLists(t *testing.T) {
	t.Parallel()
	var mailbox, other protocol.Address
	mailbox[0], other[0] = 7, 7 // one shard
	other[1] = 1
	const now = 1_000_000
	k := mark{tag: 1, id: 1, exp: now + 500}
	woken := func(c <-chan struct{}) bool {
		select {
		case <-c:
			return true
		default:
			return false
		}
	}
	for name, change := range map[string]func(x *index){
		"insert":   func(x *index) { x.insert(mailbox, k, now) },
		"remove":   func(x *index) { x.remove(mailbox, k.tag, k.exp, now, false) },
		"deleted":  func(x *index) { x.deleted(mailbox, k.tag, now) },
		"standing": func(x *index) { x.setRevocations(mailbox, true, 0) },
		"forget":   func(x *index) { x.forget(mailbox) },
	} {
		t.Run(name, func(t *testing.T) {
			x := loaded(t, mailbox, mailboxRead{exists: true, marks: []mark{k}})
			if err := x.ensure(context.Background(), other, func() (mailboxRead, error) { return mailboxRead{exists: true}, nil }); err != nil {
				t.Fatal(err)
			}
			c, d := x.changed(mailbox), x.changed(other)
			if woken(c) {
				t.Fatal("woken before any change")
			}
			change(x)
			if !woken(c) || woken(d) {
				t.Fatalf("after the change: this mailbox's list woken %v, the other's %v", woken(c), woken(d))
			}
			if woken(x.changed(mailbox)) {
				t.Fatal("a list held after the change is woken by it")
			}
		})
	}
}
