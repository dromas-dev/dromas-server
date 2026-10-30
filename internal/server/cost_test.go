package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// Measurements for costing: what one mailbox costs a process's memory,
// and how large the items the store writes are. Evidence, not a test: it
// asserts nothing and is skipped unless DROMAS_COST=1.
//
//	DROMAS_COST=1 go test ./internal/server -run TestCost -v

func costOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("DROMAS_COST") == "" {
		t.Skip("set DROMAS_COST=1 to measure")
	}
}

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func costAddrs(n int) []protocol.Address {
	as := make([]protocol.Address, n)
	for i := range as {
		_, _ = rand.Read(as[i][:])
	}
	return as
}

// costMailbox is a real mailbox record: an identity, and a prekey statement signed
// by a working key under its certificate, post-quantum or not, with n retired
// prekeys. It returns the working key's signer too.
func costMailbox(t *testing.T, pq bool, retired int) (*Mailbox, ssh.Signer) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(priv)
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	work, _ := ssh.NewSignerFromKey(wpriv)
	cert, err := protocol.NewCertificate(id, identity, work.PublicKey(), uint64(retired)+1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cert.Signer(work)
	if err != nil {
		t.Fatal(err)
	}
	var key string
	if pq {
		k, err := age.GenerateHybridIdentity()
		if err != nil {
			t.Fatal(err)
		}
		key = k.Recipient().String()
	} else {
		k, _ := age.GenerateX25519Identity()
		key = k.Recipient().String()
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := &protocol.Prekey{Address: id.Address(), Serial: uint64(retired) + 1, Key: key, NotAfter: now.Add(protocol.TTL)}
	sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	b := &Mailbox{Addr: id.Address(), Identity: id.Document(), State: Active, Statement: p.Statement(), Signature: sig, Prekey: p,
		CertSerial: cert.Serial(), Cert: certHash(cert), Rev: uint64(retired) + 2, Created: now}
	for i := range retired {
		b.Retired = append(b.Retired, Retired{Type: p.Type(), NotAfter: now.Add(time.Duration(i) * time.Hour), KeyHash: sha256.Sum256([]byte{byte(i)})})
	}
	return b, signer
}

// TestCostMemoryPerMailbox measures the heap each structure holds per mailbox.
func TestCostMemoryPerMailbox(t *testing.T) {
	t.Parallel()
	costOnly(t)
	const n = 200_000
	addrs := costAddrs(n)
	ctx := context.Background()
	now := time.Now()

	// The index: a loaded mailbox and its live messages' marks, grown by append
	// as the load and the stream grow them.
	for _, k := range []int{0, 1, 10, 100} {
		before := heapNow()
		x := newIndex()
		for _, a := range addrs {
			var marks []mark
			for i := range k {
				marks = append(marks, mark{id: uint64(i), exp: 1 << 62})
			}
			_ = x.ensure(ctx, a, func() (mailboxRead, error) {
				return mailboxRead{exists: true, st: Standing{State: Active, Key: string(bytes.Repeat([]byte{1}, 51)), Cert: [32]byte(a[:32])}, rev: 2, marks: marks}, nil
			})
		}
		t.Logf("index, %3d live messages: %6.0f B per loaded mailbox", k, float64(heapNow()-before)/n)
		runtime.KeepAlive(x)
	}

	// The poll bucket: one map entry per mailbox that has polled, until its
	// bucket is full again.
	before := heapNow()
	bs := newBuckets("test", 10, 50*time.Second)
	for _, a := range addrs {
		bs.take(a.String(), now)
	}
	t.Logf("poll bucket: %6.0f B per mailbox that has polled", float64(heapNow()-before)/n)
	runtime.KeepAlive(bs)

	// The sends a day: one bucket per sender that sent within a day.
	before = heapNow()
	d := perPeriod("sends", 20, day)
	for _, a := range addrs {
		d.take(a.String(), now)
	}
	t.Logf("sends a day: %6.0f B per sender that sent within a day", float64(heapNow()-before)/n)
	runtime.KeepAlive(d)

	// The passes remembered: one entry per mailbox that showed a pass which has
	// not run out.
	before = heapNow()
	ps := newPasses()
	for _, a := range addrs {
		ps.keep(a, seenPass{sum: [32]byte(a[:32]), cert: [32]byte(a[:32]), until: now.Add(protocol.PassLifetime)}, now)
	}
	t.Logf("pass remembered: %6.0f B per mailbox that showed one", float64(heapNow()-before)/n)
	runtime.KeepAlive(ps)

	// What a pass costs to check: the first time, a hash of the certificate
	// it carries and two signature checks, the working key's and then the
	// identity's; and every later call that carries it, a hash of the header
	// and a lookup.
	mailbox, work := costMailbox(t, false, 0)
	store := NewMemStore(time.Now)
	if err := store.CreateMailbox(ctx, mailbox); err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Store: store, Limits: DefaultLimits()})
	const name = "dromas.example"
	auth, _, err := protocol.NewPass(work, mailbox.Addr, name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+name+"/v1/"+mailbox.Addr.String()+"/messages", nil)
	req.SetPathValue("addr", mailbox.Addr.String())
	req.Header.Set("Authorization", auth)
	const first = 2000
	start := time.Now()
	for range first {
		srv.passes = newPasses()
		if _, err := srv.owner(req); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("a pass checked for the first time: %.0f µs (the Authorization value is %d B)", float64(time.Since(start).Microseconds())/first, len(auth))
	const later = 1_000_000
	start = time.Now()
	for range later {
		if _, err := srv.owner(req); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("a pass the server remembers: %.2f µs a call", float64(time.Since(start).Nanoseconds())/later/1000)

	// What a pass that is not the mailbox's costs to refuse. Under any other
	// certificate: no signature check. Carrying the mailbox's own certificate,
	// which is public, with a signature that does not verify: one, the
	// working key's. The identity's is reached only by a pass that is the
	// mailbox's.
	_, otherWork := costMailbox(t, false, 0)
	notAfter := time.Now().UTC().Truncate(time.Second).Add(protocol.PassLifetime)
	elsewhere, _, err := protocol.NewPass(otherWork, mailbox.Addr, name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for what, junk := range map[string]string{
		"under another certificate":                                 elsewhere,
		"carrying the mailbox's certificate, signed by another key": passCarrying(t, work.PublicKey(), otherWork, mailbox.Addr, name, notAfter),
	} {
		req.Header.Set("Authorization", junk)
		start = time.Now()
		for range first {
			if _, err := srv.owner(req); err == nil {
				t.Fatalf("a pass %s was taken", what)
			}
		}
		t.Logf("a pass %s, refused: %.0f µs", what, float64(time.Since(start).Microseconds())/first)
	}

	// The mailbox record cache: bounded (--mailbox-cache, default 10,000).
	for _, c := range []struct {
		pq      bool
		retired int
	}{{true, 0}, {true, 10}, {false, 0}} {
		const m = 10_000
		b, _ := costMailbox(t, c.pq, c.retired)
		before := heapNow()
		cache := newMailboxCache(m)
		for _, a := range addrs[:m] {
			// Its own bytes, as a record decoded from the table has.
			x := cloneMailbox(b)
			x.Addr = a
			x.Identity, x.Statement, x.Signature = bytes.Clone(b.Identity), bytes.Clone(b.Statement), bytes.Clone(b.Signature)
			p := *b.Prekey
			p.Key = strings.Clone(p.Key)
			x.Prekey = &p
			cache.put(x)
		}
		t.Logf("mailbox record cache, pq=%v, %2d retired: %6.0f B per record", c.pq, c.retired, float64(heapNow()-before)/m)
		runtime.KeepAlive(cache)
	}
}

// itemSize is an item's size as DynamoDB bills it: attribute names plus
// values (AWS docs, "DynamoDB item sizes and formats").
func itemSize(it map[string]types.AttributeValue) int {
	n := 0
	for k, v := range it {
		n += len(k) + valueSize(v)
	}
	return n
}

func valueSize(v types.AttributeValue) int {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return len(v.Value)
	case *types.AttributeValueMemberS:
		return len(v.Value)
	case *types.AttributeValueMemberN:
		digits := len(strings.Trim(strings.ReplaceAll(v.Value, ".", ""), "0"))
		return (digits+1)/2 + 1
	case *types.AttributeValueMemberBOOL:
		return 1
	case *types.AttributeValueMemberL:
		n := 3
		for _, e := range v.Value {
			n += 1 + valueSize(e)
		}
		return n
	case *types.AttributeValueMemberM:
		n := 3
		for k, e := range v.Value {
			n += 1 + len(k) + valueSize(e)
		}
		return n
	}
	return 0
}

// TestCostItemSizes prints the size of every item the store writes, from the
// functions that build them, and the write units each costs (1 per KB,
// rounded up).
func TestCostItemSizes(t *testing.T) {
	t.Parallel()
	costOnly(t)
	wcu := func(n int) int { return (n + 1023) / 1024 }
	for _, c := range []struct {
		pq      bool
		retired int
	}{{true, 0}, {true, 1}, {true, 10}, {false, 0}, {false, 10}} {
		b, _ := costMailbox(t, c.pq, c.retired)
		n := itemSize(mailboxItem(b))
		t.Logf("mailbox record, pq=%v, %2d retired: %5d B = %d write units (identity %d, statement %d, signature %d)",
			c.pq, c.retired, n, wcu(n), len(b.Identity), len(b.Statement), len(b.Signature))
	}
	// An ACL is part of the record, so every write of it costs its size.
	for _, entries := range []int{1, 50, DefaultLimits().ACLEntries} {
		b, _ := costMailbox(t, true, 10)
		b.ACL = &protocol.ACL{Allow: protocol.NewACLList(false, costAddrs(entries))}
		n := itemSize(mailboxItem(b))
		t.Logf("mailbox record, pq, 10 retired, an ACL of %3d entries: %5d B = %d write units", entries, n, wcu(n))
	}

	to := costAddrs(1)[0]
	body := make([]byte, 4096)
	now := time.Now().UTC().Truncate(time.Millisecond)
	h := &Header{ID: sha256.Sum256(body), Size: len(body), ReceivedAt: now, ExpiresAt: now.Add(protocol.TTL)}
	live := msgItem(to, h)
	n := itemSize(live)
	t.Logf("message item: %4d B = %d write unit; an ack deletes it", n, wcu(n))
	index := map[string]types.AttributeValue{"box": live["box"], "live": live["live"], "id": live["id"], "size": live["size"]}
	t.Logf("its entry in the live index: %4d B", itemSize(index))
}
