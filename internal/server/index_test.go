package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// loaded is an index holding box, loaded with read.
// Each index tags its marks under a random key of its own, so nobody
// outside the process can compute a tag.
func TestTheMarkKeyIsRandom(t *testing.T) {
	t.Parallel()
	x, y := newIndex(), newIndex()
	if x.key == ([32]byte{}) || x.key == y.key {
		t.Fatalf("mark keys %x and %x", x.key, y.key)
	}
}

func loaded(t *testing.T, box protocol.Address, read boxRead) *index {
	t.Helper()
	x := newIndex()
	if err := x.ensure(context.Background(), box, func() (boxRead, error) { return read, nil }); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *index) tombs(box protocol.Address) int {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return len(sh.boxes[box].tombs)
}

// Layer 1 must stay exact when a change arrives twice, late, or out of
// order with this process's own writes (ARCHITECTURE.md § Memory).
func TestIndex(t *testing.T) {
	t.Parallel()
	var box protocol.Address
	box[0] = 7
	const now = 1_000_000
	k1 := mark{tag: 1, id: 1, from: 10, exp: now + 500}
	k2 := mark{tag: 2, id: 2, from: 10, exp: now + 900}

	t.Run("a set: inserts twice count once", func(t *testing.T) {
		x := loaded(t, box, boxRead{})
		x.insert(box, k1, now)
		x.insert(box, k1, now) // the stream's echo of our own write
		x.insert(box, k2, now)
		if n := x.count(box, now); n != 2 || !x.holds(box, k1.tag, now) || !x.holds(box, k2.tag, now) {
			t.Fatalf("count %d", n)
		}
		if n, oldest := x.pair(box, 10, now); n != 2 || oldest != k1.exp {
			t.Fatalf("pair %d, oldest %d", n, oldest)
		}
		if n, _ := x.pair(box, 11, now); n != 0 {
			t.Fatal("another sender counted")
		}
	})

	t.Run("a late insert does not bring back an ack", func(t *testing.T) {
		x := loaded(t, box, boxRead{})
		x.insert(box, k1, now)
		x.remove(box, k1.tag, k1.exp, now, false) // our ack
		x.insert(box, k1, now)                    // the stream's late insert
		if n := x.count(box, now); n != 0 {
			t.Fatal("the acked message came back")
		}
		x.remove(box, k1.tag, k1.exp, now, true) // the removal's echo clears the tomb
		if x.tombs(box) != 0 {
			t.Fatal("the tomb outlived its echo")
		}
	})

	t.Run("an ack of a message the stream has not shown yet", func(t *testing.T) {
		x := loaded(t, box, boxRead{})
		x.remove(box, k1.tag, k1.exp, now, false)
		x.insert(box, k1, now)
		if n := x.count(box, now); n != 0 {
			t.Fatal("the acked message came back")
		}
	})

	t.Run("a tomb whose echo came first dies at its expiry", func(t *testing.T) {
		x := loaded(t, box, boxRead{})
		x.insert(box, k1, now)
		x.remove(box, k1.tag, k1.exp, now, true)  // the echo, first
		x.remove(box, k1.tag, k1.exp, now, false) // then our own apply
		x.count(box, k1.exp)
		if x.tombs(box) != 0 {
			t.Fatal("the tomb outlived the message's expiry")
		}
	})

	t.Run("expiry, with no event", func(t *testing.T) {
		x := loaded(t, box, boxRead{})
		x.insert(box, k1, now)
		x.insert(box, k2, now)
		if n := x.count(box, k1.exp-1); n != 2 || !x.holds(box, k1.tag, k1.exp-1) || !x.holds(box, k2.tag, k1.exp-1) {
			t.Fatalf("before expiry: %d", n)
		}
		if n := x.count(box, k1.exp); n != 1 || !x.holds(box, k2.tag, k1.exp) {
			t.Fatalf("at expiry: %d", n)
		}
		x.insert(box, mark{tag: 3, id: 3, exp: now}, now)
		if n := x.count(box, now); n != 1 {
			t.Fatal("an expired insert counted")
		}
	})

	t.Run("a removal names the message, not just its id", func(t *testing.T) {
		// The same ciphertext, resent after the first expired: the late TTL
		// removal of the first must not remove the second.
		x := loaded(t, box, boxRead{})
		again := mark{tag: k1.tag, id: k1.id, from: k1.from, exp: k1.exp + 1000}
		x.insert(box, again, k1.exp)
		x.remove(box, k1.tag, k1.exp, k1.exp, true)
		if n := x.count(box, k1.exp); n != 1 {
			t.Fatal("the resent message was removed")
		}
	})

	t.Run("standing only moves forward", func(t *testing.T) {
		first, second := Standing{State: Active, Cert: [32]byte{1}}, Standing{State: Active, Cert: [32]byte{2}}
		x := loaded(t, box, boxRead{exists: true, st: first, rev: 1})
		x.setStanding(box, second, version{rev: 3})
		x.setStanding(box, first, version{rev: 1}) // a late image
		if st, ok := x.standing(box); !ok || st != second {
			t.Fatalf("standing %v %v", st, ok)
		}
		x.setStanding(box, Standing{State: Active, Cert: [32]byte{3}}, version{rev: 4})
		if st, _ := x.standing(box); st.Cert != [32]byte{3} {
			t.Fatal("a later standing not kept")
		}
		x.forget(box)
		if _, ok := x.standing(box); ok {
			t.Fatal("a deleted record kept its standing")
		}
		x.setStanding(box, first, version{rev: 1}) // registered again: the next use loads it, so nothing is held until then
		if _, ok := x.standing(box); ok {
			t.Fatal("a box memory forgot was taken back from a change")
		}
	})

	t.Run("revocations only add", func(t *testing.T) {
		x := loaded(t, box, boxRead{exists: true, st: Standing{State: Active, CertSerial: 5}, rev: 1})
		x.setRevocations(box, false, 4)
		if st, _ := x.standing(box); st.Listed {
			t.Fatal("certificates revoked through 4 listed the box's 5")
		}
		x.setRevocations(box, false, 5)
		x.setRevocations(box, false, 2) // a lower one changes nothing
		if st, _ := x.standing(box); !st.Listed {
			t.Fatal("certificates revoked through 5 did not list the box's 5")
		}
		x.setStanding(box, Standing{State: Active, CertSerial: 6}, version{rev: 2}) // a renewal above them
		if st, _ := x.standing(box); st.Listed {
			t.Fatal("a renewal above the revoked certificates is still listed")
		}
		x.setRevocations(box, true, 0)
		x.setStanding(box, Standing{State: Active, CertSerial: 7}, version{rev: 3})
		if st, ok := x.standing(box); !ok || st.State != Revoked {
			t.Fatalf("a revoked address: %+v %v", st, ok)
		}
	})

	t.Run("a revoked address with no record", func(t *testing.T) {
		x := loaded(t, box, boxRead{revoked: true})
		if st, ok := x.standing(box); !ok || st.State != Revoked {
			t.Fatalf("a revoked address with no record: %+v %v", st, ok)
		}
		y := loaded(t, box, boxRead{through: 9})
		if _, ok := y.standing(box); ok {
			t.Fatal("an address with no box has a standing")
		}
	})
}

// Memory holds a box only after its first use loads it, and a change that
// arrives meanwhile is applied after the load.
func TestIndexLoad(t *testing.T) {
	t.Parallel()
	var box protocol.Address
	box[0] = 7
	const now = 1_000_000
	k1 := mark{tag: 1, id: 1, from: 10, exp: now + 500}
	k2 := mark{tag: 2, id: 2, from: 10, exp: now + 900}
	ctx := context.Background()

	t.Run("a change to a box memory does not hold is dropped", func(t *testing.T) {
		x := newIndex()
		x.insert(box, k1, now)
		x.setStanding(box, Standing{State: Revoked}, version{rev: 9})
		if err := x.ensure(ctx, box, func() (boxRead, error) {
			return boxRead{exists: true, st: Standing{State: Active}, rev: 1}, nil
		}); err != nil {
			t.Fatal(err)
		}
		if n := x.count(box, now); n != 0 {
			t.Fatal("a change before the load was kept")
		}
		if st, _ := x.standing(box); st.State != Active {
			t.Fatal("a standing before the load was kept")
		}
	})

	t.Run("a change during the load waits for it", func(t *testing.T) {
		x := newIndex()
		reading, release := make(chan struct{}), make(chan struct{})
		done := make(chan error)
		go func() {
			done <- x.ensure(ctx, box, func() (boxRead, error) {
				close(reading)
				<-release
				// Read before the changes below: k1 was live, the box at rev 1.
				return boxRead{exists: true, st: Standing{State: Active}, rev: 1, marks: []mark{k1}}, nil
			})
		}()
		<-reading
		if n := x.count(box, now); n != 0 {
			t.Fatal("counted while loading")
		}
		x.remove(box, k1.tag, k1.exp, now, true) // acked meanwhile
		x.insert(box, k2, now)                   // and a new message
		x.setStanding(box, Standing{State: Active, Cert: [32]byte{1}}, version{rev: 2})
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if n := x.count(box, now); n != 1 || !x.holds(box, k2.tag, now) {
			t.Fatalf("count %d: the queued changes were not applied after the load", n)
		}
		if st, _ := x.standing(box); st.Cert != [32]byte{1} {
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
				_ = x.ensure(ctx, box, func() (boxRead, error) {
					reads.Add(1)
					<-release
					return boxRead{exists: true}, nil
				})
				if _, ok := x.standing(box); !ok {
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
		_ = x.ensure(ctx, box, func() (boxRead, error) { reads.Add(1); return boxRead{}, nil })
		if reads.Load() != 1 {
			t.Fatal("a loaded box was read again")
		}
	})

	t.Run("a failed load leaves the box unloaded", func(t *testing.T) {
		x := newIndex()
		reading, release := make(chan struct{}), make(chan struct{})
		done := make(chan error)
		go func() {
			done <- x.ensure(ctx, box, func() (boxRead, error) {
				close(reading)
				<-release
				return boxRead{}, errors.New("throttled")
			})
		}()
		<-reading
		x.insert(box, k1, now) // queued, then dropped with the load
		close(release)
		if err := <-done; err == nil {
			t.Fatal("the error was not returned")
		}
		if err := x.ensure(ctx, box, func() (boxRead, error) { return boxRead{exists: true}, nil }); err != nil {
			t.Fatal(err)
		}
		if n := x.count(box, now); n != 0 {
			t.Fatal("a failed load's queued change was applied")
		}
		if _, ok := x.standing(box); !ok {
			t.Fatal("not loaded on the retry")
		}
	})
}
