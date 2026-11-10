package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// twoProcesses is two processes on one schema, A and B, each a server over a
// store of its own. B's feed can be held (hold): it then takes no
// transaction as committed, so B's memory stays behind the database while B
// is ready, as it is for the feed's lag on any second process. Each case
// below is a write or a read on B that its copy would let through, and the
// database refuses (held.go).
type twoProcesses struct {
	t        *testing.T
	a, b     *env
	writer   *Memory
	follower *Memory
	mu       sync.Mutex
	held     bool
}

func newTwoProcesses(t *testing.T) *twoProcesses {
	t.Helper()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	x := &twoProcesses{t: t}
	schema, bodies := freshDatabase(t)
	x.writer = startPostgresIn(t, schema, bodies, nil, nil)
	x.a = newEnv(t, relaxed(), func(c *Config) { c.Store, c.Ready = x.writer, x.writer.Ready })
	x.a.store = x.writer
	f, fctx := newPostgresIn(t, schema, bodies, nil, nil)
	x.follower = f
	f.pg().visible = func(ctx context.Context, xid uint32) (bool, error) {
		x.mu.Lock()
		held := x.held
		x.mu.Unlock()
		if held {
			return false, nil
		}
		var snap string
		if err := f.pool().QueryRow(ctx, "SELECT pg_current_snapshot()::text").Scan(&snap); err != nil {
			return false, err
		}
		return snapshotSees(snap, xid)
	}
	if err := f.Start(fctx); err != nil {
		t.Fatal(err)
	}
	x.b = newEnv(t, relaxed(), func(c *Config) { c.Store, c.Ready, c.Now = f, f.Ready, x.a.clock.Now })
	x.b.store = f
	x.b.clock = x.a.clock
	return x
}

// hold holds B's feed, or lets it go and waits until B has caught up.
func (x *twoProcesses) hold(on bool) {
	x.mu.Lock()
	x.held = on
	x.mu.Unlock()
	if !on {
		fed(x.t, x.follower)
	}
}

// onB calls B by A's name, so that a pass made for A is taken there.
func (x *twoProcesses) onB(method, path string, body any, pass string, headers ...string) reply {
	x.t.Helper()
	return x.b.doAs(x.a.name(), method, path, body, pass, headers...)
}

// headOnB is a HEAD on B by A's name: its status, since its answer has no
// content to read a code from.
func (x *twoProcesses) headOnB(path, pass string) int {
	x.t.Helper()
	req, err := http.NewRequest(http.MethodHead, x.b.srv.URL+path, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	req.Host = x.a.name()
	req.Header.Set("Authorization", pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		x.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// count is the one integer q reads from the database.
func (x *twoProcesses) count(q string, args ...any) int {
	x.t.Helper()
	var n int
	if err := x.writer.pool().QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		x.t.Fatal(err)
	}
	return n
}

func messagesOf(x *twoProcesses, a protocol.Address) int {
	return x.count(`SELECT count(*)::int FROM messages WHERE box = $1`, a[:])
}

// After a renewal on A, B, behind, stores no send sealed to the statement
// the renewal replaced (PROTOCOL.md §15.3), and takes the replaced
// certificate's pass for no fetch, ack, message's HEAD, list, ACL or long
// poll held since before it, nor for a fetch or an ack of an id the mailbox
// does not hold (§15.5; dromas-dev/dromas-server#195, #247, #226, #266). Each call is
// B's first after the renewal, on a pair of processes of its own: B's
// memory, once it has found itself behind, answers the next call from the
// record read again.
func TestAProcessBehindTakesNothingARenewalElsewhereEnded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		empty bool // the mailbox holds no message, so a list reads no page
		call  func(t *testing.T, x *twoProcesses, from, to *raw, id [32]byte, old string, polled <-chan reply)
	}{
		{"a send sealed to the replaced statement", false, func(t *testing.T, x *twoProcesses, from, to *raw, _ [32]byte, _ string, _ <-chan reply) {
			x.a.want(x.onB("POST", to.path("/messages"), to.sealed(2, sealFor(t, to, 2)), from.pass(1)), http.StatusConflict, protocol.CodeConcurrentModification)
			x.a.want(x.onB("POST", to.path("/messages"), to.sealed(2, sealFor(t, to, 2)), from.pass(1)), http.StatusConflict, protocol.CodePrekeySuperseded)
		}},
		{"a fetch", false, func(t *testing.T, x *twoProcesses, _, to *raw, id [32]byte, old string, _ <-chan reply) {
			x.a.wantNotCurrent(x.onB("GET", to.path("/messages/"+hexID(id)), nil, old), 3)
		}},
		{"an ack", false, func(t *testing.T, x *twoProcesses, _, to *raw, id [32]byte, old string, _ <-chan reply) {
			x.a.wantNotCurrent(x.onB("DELETE", to.path("/messages/"+hexID(id)), nil, old), 3)
		}},
		{"a message's HEAD", false, func(t *testing.T, x *twoProcesses, _, to *raw, id [32]byte, old string, _ <-chan reply) {
			if got := x.headOnB(to.path("/messages/"+hexID(id)), old); got != http.StatusUnauthorized {
				t.Errorf("HEAD under the replaced certificate: %d; want 401", got)
			}
		}},
		{"a fetch of an id the mailbox does not hold", false, func(t *testing.T, x *twoProcesses, _, to *raw, _ [32]byte, old string, _ <-chan reply) {
			x.a.wantNotCurrent(x.onB("GET", to.path("/messages/"+hexID([32]byte{1})), nil, old), 3)
		}},
		{"an ack of an id the mailbox does not hold", false, func(t *testing.T, x *twoProcesses, _, to *raw, _ [32]byte, old string, _ <-chan reply) {
			x.a.wantNotCurrent(x.onB("DELETE", to.path("/messages/"+hexID([32]byte{1})), nil, old), 3)
		}},
		{"a list", false, func(t *testing.T, x *twoProcesses, _, to *raw, _ [32]byte, old string, _ <-chan reply) {
			x.a.wantNotCurrent(x.onB("GET", to.path("/messages"), nil, old), 3)
		}},
		{"an ACL", false, func(t *testing.T, x *twoProcesses, _, to *raw, _ [32]byte, old string, _ <-chan reply) {
			acl := aclOf([]string{"*"}, nil)
			x.a.want(x.onB("PUT", to.path("/acl"), acl, old), http.StatusConflict, protocol.CodeConcurrentModification)
			x.a.wantNotCurrent(x.onB("PUT", to.path("/acl"), acl, old), 3)
		}},
		{"a long poll of an empty mailbox, held from before", true, func(t *testing.T, x *twoProcesses, _, _ *raw, _ [32]byte, _ string, polled <-chan reply) {
			x.hold(false) // the renewal reaches B, and wakes the poll
			select {
			case p := <-polled:
				x.a.wantNotCurrent(p, 3)
			case <-time.After(10 * time.Second):
				t.Fatal("the long poll held under the replaced certificate was not answered")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			x := newTwoProcesses(t)
			a := x.a
			from := a.raw().register(protocol.MaxPrekeyLifetime)
			to := a.raw()
			to.registerCertified(protocol.MaxPrekeyLifetime) // statement 2, under certificate 2
			var id [32]byte
			if !c.empty {
				ct := sealFor(t, to, 2)
				id = sha256.Sum256(ct)
				a.want(x.onB("POST", to.path("/messages"), to.sealed(2, ct), from.pass(1)), http.StatusCreated, "")
			}
			fed(t, x.follower)
			old := to.pass(2)
			list := x.onB("GET", to.path("/messages"), nil, old)
			a.want(list, http.StatusOK, "")
			polled := make(chan reply, 1)
			if c.empty {
				go func() {
					polled <- x.b.doAs(a.name(), "GET", to.path("/messages?wait=30"), nil, old, "If-None-Match", list.header.Get("ETag"))
				}()
				until(t, func(int) bool { return x.b.server.holding.Load() == 1 })
			}
			x.hold(true)
			to.prekey(3, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil) // statement 3, under certificate 3
			a.want(a.do("PUT", to.path("/prekey"), to.upload(3), to.pass(3)), http.StatusOK, "")
			a.wantNotCurrent(a.do("GET", to.path("/messages"), nil, old), 3)
			if !x.follower.Ready() {
				t.Fatal("B is not ready: the case is no case")
			}
			c.call(t, x, from, to, id, old, polled)
			if n, want := messagesOf(x, to.id.Address()), map[bool]int{true: 0, false: 1}[c.empty]; n != want {
				t.Errorf("%d messages held; want %d", n, want)
			}
			x.hold(false)
		})
	}
}

// After an ACL on A denies a sender, B, behind, stores nothing of that
// sender's (PROTOCOL.md §11.14).
func TestAProcessBehindStoresNothingAnACLElsewhereDenies(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	from, to := a.raw().register(protocol.MaxPrekeyLifetime), a.raw().register(protocol.MaxPrekeyLifetime)
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusCreated, "")
	fed(t, x.follower)
	x.hold(true)
	a.want(a.do("PUT", to.path("/acl"), aclOf([]string{"*"}, []string{from.id.Address().String()}), to.pass(1)), http.StatusOK, "")
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusConflict, protocol.CodeConcurrentModification)
	if n := messagesOf(x, to.id.Address()); n != 1 {
		t.Errorf("after a send on B the ACL denies: %d messages held; want 1", n)
	}
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusForbidden, protocol.CodeSenderNotAllowed)
	x.hold(false)
}

// After a revocation of an address on A, B, behind, stores no send to it,
// and answers it as revoked (PROTOCOL.md §11.15). What a send left all the
// same, the sweep deletes (TestTheSweepTakesWhatARevokedAddressLeft).
func TestAProcessBehindStoresNothingForAnAddressRevokedElsewhere(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	from, to := a.raw().register(protocol.MaxPrekeyLifetime), a.raw().register(protocol.MaxPrekeyLifetime)
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusCreated, "")
	fed(t, x.follower)
	sig, err := protocol.Sign(to.signer, protocol.RevocationStatement(to.id.Address()), protocol.RevokeNamespace(to.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	x.hold(true)
	a.want(a.do("PUT", revocationPath(to.id.Address()), protocol.Revocations{Identity: to.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusGone, protocol.CodeMailboxRevoked)
	if n := messagesOf(x, to.id.Address()); n != 0 {
		t.Errorf("after a send on B to the revoked address: %d messages held; want none", n)
	}
	x.hold(false)
}

// After a revocation of an address on A, B, behind, answers its mailbox's
// own pass, for a message's HEAD and for a fetch or an ack of an id it does
// not hold, as revoked (PROTOCOL.md §11.15; dromas-dev/dromas-server#266):
// what memory shows of its messages is held to the pass.
func TestAProcessBehindAnswersAMailboxRevokedElsewhereAsRevoked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		held   bool // the id is of a message memory holds
	}{
		{"a message's HEAD", http.MethodHead, true},
		{"a fetch of an id the mailbox does not hold", "GET", false},
		{"an ack of an id the mailbox does not hold", "DELETE", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			x := newTwoProcesses(t)
			a := x.a
			from, to := a.raw().register(protocol.MaxPrekeyLifetime), a.raw().register(protocol.MaxPrekeyLifetime)
			ct := sealFor(t, to, 1)
			a.want(x.onB("POST", to.path("/messages"), to.sealed(1, ct), from.pass(1)), http.StatusCreated, "")
			fed(t, x.follower)
			id := [32]byte{1}
			if c.held {
				id = sha256.Sum256(ct)
			}
			path := to.path("/messages/" + hexID(id))
			sig, err := protocol.Sign(to.signer, protocol.RevocationStatement(to.id.Address()), protocol.RevokeNamespace(to.id.Address()))
			if err != nil {
				t.Fatal(err)
			}
			x.hold(true)
			a.want(a.do("PUT", revocationPath(to.id.Address()), protocol.Revocations{Identity: to.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
			if st, ok := x.follower.Held(to.id.Address()); !ok || st.State != Active {
				t.Fatal("control: B does not hold the mailbox as active")
			}
			if c.method == http.MethodHead {
				if got := x.headOnB(path, to.pass(1)); got != http.StatusGone {
					t.Errorf("HEAD of the revoked mailbox's message: %d; want 410", got)
				}
			} else {
				x.a.want(x.onB(c.method, path, nil, to.pass(1)), http.StatusGone, protocol.CodeMailboxRevoked)
			}
			x.hold(false)
		})
	}
}

// After a sender renews on A, B, behind, answers a post of a message the
// recipient holds, sent again by the sender's replaced certificate, with no
// receipt, and after the sender's address is revoked, a post by it of any
// (PROTOCOL.md §11.10 step 6, §15.5; dromas-dev/dromas-server#266): the
// dedupe is held to the sender's pass, as the write is.
func TestAProcessBehindAnswersNoDuplicateOfASenderEndedElsewhere(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	to := a.raw().register(protocol.MaxPrekeyLifetime)
	from := a.raw()
	from.registerCertified(protocol.MaxPrekeyLifetime)
	again := to.sealed(1, sealFor(t, to, 1))
	a.want(x.onB("POST", to.path("/messages"), again, from.pass(2)), http.StatusCreated, "")
	fed(t, x.follower)
	x.hold(true)
	from.prekey(3, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	a.want(a.do("PUT", from.path("/prekey"), from.upload(3), from.pass(3)), http.StatusOK, "")
	a.wantNotCurrent(a.do("POST", to.path("/messages"), again, from.pass(2)), 3)
	a.want(x.onB("POST", to.path("/messages"), again, from.pass(2)), http.StatusConflict, protocol.CodeConcurrentModification)
	a.wantNotCurrent(x.onB("POST", to.path("/messages"), again, from.pass(2)), 3)
	a.want(x.onB("POST", to.path("/messages"), again, from.pass(3)), http.StatusOK, "") // the sender's current pass: its receipt
	sig, err := protocol.Sign(from.signer, protocol.RevocationStatement(from.id.Address()), protocol.RevokeNamespace(from.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	a.want(a.do("PUT", revocationPath(from.id.Address()), protocol.Revocations{Identity: from.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	a.want(x.onB("POST", to.path("/messages"), again, from.pass(3)), http.StatusForbidden, protocol.CodeSenderRevoked)
	if n := messagesOf(x, to.id.Address()); n != 1 {
		t.Errorf("%d messages held; want 1, the first", n)
	}
	x.hold(false)
}

// A post of a message the recipient holds, sent again after the recipient
// renewed on A, is answered with its receipt (PROTOCOL.md §11.10 step 6), on
// B behind and once it has caught up: the dedupe is held to the sender's
// pass, never to the recipient's record.
func TestADuplicateAcrossARenewalElsewhereGetsItsReceipt(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	from, to := a.raw().register(protocol.MaxPrekeyLifetime), a.raw().register(protocol.MaxPrekeyLifetime)
	again := to.sealed(1, sealFor(t, to, 1))
	first := x.onB("POST", to.path("/messages"), again, from.pass(1))
	a.want(first, http.StatusCreated, "")
	fed(t, x.follower)
	x.hold(true)
	to.prekey(2, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	a.want(a.do("PUT", to.path("/prekey"), to.upload(2), to.pass(2)), http.StatusOK, "")
	behind := x.onB("POST", to.path("/messages"), again, from.pass(1))
	x.hold(false)
	caught := x.onB("POST", to.path("/messages"), again, from.pass(1))
	for name, r := range map[string]reply{"behind": behind, "caught up": caught} {
		if r.status != http.StatusOK || !bytes.Equal(bytes.TrimSpace(r.body), bytes.TrimSpace(first.body)) {
			t.Errorf("B %s: %d %s; want 200 and the receipt %s", name, r.status, r.body, first.body)
		}
	}
	if n := messagesOf(x, to.id.Address()); n != 1 {
		t.Errorf("%d messages held; want 1", n)
	}
}

// After the identity revokes certificates through 2 on A, B, behind, takes
// no statement under certificate 2 (PROTOCOL.md §10.2, §12.6;
// dromas-dev/dromas-server#248): the revocation raised the record's rev,
// which B's write is held to.
func TestAProcessBehindTakesNoRenewalUnderACertificateRevokedElsewhere(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	to := a.raw()
	to.registerCertified(protocol.MaxPrekeyLifetime)
	box := to.id.Address()
	a.want(x.onB("GET", to.path("/messages"), nil, to.pass(2)), http.StatusOK, "")
	fed(t, x.follower)
	x.hold(true)
	a.want(a.do("PUT", revocationPath(box), to.certs(2), ""), http.StatusOK, "")
	to.prekeyUnder(to.work[2], 3, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil) // whoever holds certificate 2's key
	a.want(a.do("PUT", to.path("/prekey"), to.upload(3), to.pass(3)), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	a.want(x.onB("PUT", to.path("/prekey"), to.upload(3), to.pass(3)), http.StatusConflict, protocol.CodeConcurrentModification)
	a.want(x.onB("PUT", to.path("/prekey"), to.upload(3), to.pass(3)), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	var stmt []byte
	if err := x.writer.pool().QueryRow(context.Background(), `SELECT statement FROM mailboxes WHERE addr = $1`, box[:]).Scan(&stmt); err != nil {
		t.Fatal(err)
	}
	if string(stmt) != string(to.stmt[2]) {
		t.Error("the record holds a statement under the revoked certificate")
	}
	x.hold(false)
}

// After a sender renews on A, B, behind, stores nothing by the sender's
// replaced certificate, and after the sender's address is revoked, nothing
// of it at all (PROTOCOL.md §15.5; dromas-dev/dromas-server#103): the write
// is held to the sender's pass too.
func TestAProcessBehindStoresNothingByASenderEndedElsewhere(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	to := a.raw().register(protocol.MaxPrekeyLifetime)
	from := a.raw()
	from.registerCertified(protocol.MaxPrekeyLifetime)
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(2)), http.StatusCreated, "")
	fed(t, x.follower)
	x.hold(true)
	from.prekey(3, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	a.want(a.do("PUT", from.path("/prekey"), from.upload(3), from.pass(3)), http.StatusOK, "")
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(2)), http.StatusConflict, protocol.CodeConcurrentModification)
	a.wantNotCurrent(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(2)), 3)
	sig, err := protocol.Sign(from.signer, protocol.RevocationStatement(from.id.Address()), protocol.RevokeNamespace(from.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	a.want(a.do("PUT", revocationPath(from.id.Address()), protocol.Revocations{Identity: from.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(3)), http.StatusForbidden, protocol.CodeSenderRevoked)
	if n := messagesOf(x, to.id.Address()); n != 1 {
		t.Errorf("after sends on B by an ended sender: %d messages held; want 1, the first", n)
	}
	x.hold(false)
}

// After A revokes an address with no mailbox, B, which remembers it as
// missing, registers nothing there (PROTOCOL.md §11.15;
// dromas-dev/dromas-server#249): a registration and a revocation of one
// address take its lock, and the registration reads what is revoked under it.
func TestAProcessBehindRegistersNoAddressRevokedElsewhere(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	r := a.raw()
	r.prekey(1, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	a.want(x.onB("GET", r.path(""), nil, ""), http.StatusNotFound, protocol.CodeMailboxNotFound)
	x.hold(true)
	sig, err := protocol.Sign(r.signer, protocol.RevocationStatement(r.id.Address()), protocol.RevokeNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	a.want(a.do("PUT", revocationPath(r.id.Address()), protocol.Revocations{Identity: r.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	a.want(x.onB("PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusGone, protocol.CodeMailboxRevoked)
	box := r.id.Address()
	if n := x.count(`SELECT count(*)::int FROM mailboxes WHERE addr = $1`, box[:]); n != 0 {
		t.Errorf("the revoked address has %d records; want none", n)
	}
	x.hold(false)
}

// The sweep deletes the messages and the record left beside a revocation of
// their address, which no call is answered from, and no other address's.
func TestTheSweepTakesWhatARevokedAddressLeft(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	e := newEnv(t, relaxed())
	from, gone, kept := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	for _, to := range []*raw{gone, kept} {
		e.want(e.do("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusCreated, "")
	}
	s := e.store.(*Memory)
	sig, err := protocol.Sign(gone.signer, protocol.RevocationStatement(gone.id.Address()), protocol.RevokeNamespace(gone.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	// The revocation kept, and nothing deleted: as a revocation whose purge
	// failed, or a send that landed as it ran, leaves the address.
	if _, _, err := s.backend.Revoke(t.Context(), gone.id.Address(), &Revocations{Identity: gone.id.Document(), Address: sig}, ExpectAnything); err != nil {
		t.Fatal(err)
	}
	rows := func(a protocol.Address) (msgs, recs int) {
		ctx := t.Context()
		if err := s.pool().QueryRow(ctx, `SELECT (SELECT count(*)::int FROM messages WHERE box = $1), (SELECT count(*)::int FROM mailboxes WHERE addr = $1)`, a[:]).Scan(&msgs, &recs); err != nil {
			t.Fatal(err)
		}
		return msgs, recs
	}
	if m, r := rows(gone.id.Address()); m != 1 || r != 1 {
		t.Fatalf("before the sweep, the revoked address holds %d messages and %d records; want 1 and 1", m, r)
	}
	s.pg().sweepRevoked(t.Context())
	if m, r := rows(gone.id.Address()); m != 0 || r != 0 {
		t.Errorf("after the sweep, the revoked address holds %d messages and %d records; want none", m, r)
	}
	if m, r := rows(kept.id.Address()); m != 1 || r != 1 {
		t.Errorf("after the sweep, another address holds %d messages and %d records; want 1 and 1", m, r)
	}
}

// A record made again at its address on A, once the sweep took the one
// before, starts its rev over, so B, behind, holds a copy of the record
// before at the rev the new one is at. A write on B is held to the record by
// its version, its created beside its rev, and changes nothing of the new
// one, a send sealed to the record before among them, which stores nothing
// (409 concurrent_modification); and B's own revocation of certificates, which
// raises the new record's rev, leaves B no copy of the record before
// (dromas-dev/dromas-server#266).
func TestAProcessBehindWritesNothingToARecordMadeAgainAtItsAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		call func(t *testing.T, x *twoProcesses, to, from *raw)
	}{
		{"a renewal", func(t *testing.T, x *twoProcesses, to, _ *raw) {
			to.prekey(3, x.a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			x.a.want(x.onB("PUT", to.path("/prekey"), to.upload(3), to.pass(3)), http.StatusConflict, protocol.CodeConcurrentModification)
		}},
		{"an ACL", func(t *testing.T, x *twoProcesses, to, _ *raw) {
			x.a.want(x.onB("PUT", to.path("/acl"), aclOf([]string{"*"}, nil), to.pass(2)), http.StatusConflict, protocol.CodeConcurrentModification)
		}},
		{"a send sealed to the record before", func(t *testing.T, x *twoProcesses, to, from *raw) {
			x.a.want(x.onB("POST", to.path("/messages"), to.sealed(1, sealFor(t, to, 1)), from.pass(1)), http.StatusConflict, protocol.CodeConcurrentModification)
		}},
		{"a revocation of certificates, after which B reads the record made again", func(t *testing.T, x *twoProcesses, to, _ *raw) {
			x.a.want(x.onB("PUT", revocationPath(to.id.Address()), to.certs(1), ""), http.StatusOK, "")
			rep := x.onB("GET", to.path(""), nil, "")
			x.a.want(rep, http.StatusOK, "")
			var got protocol.MailboxResponse
			if err := protocol.Unmarshal(rep.body, &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Prekey, to.stmt[2]) {
				t.Error("after its own revocation of certificates, B serves the record the sweep took")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			x := newTwoProcesses(t)
			a := x.a
			to := a.raw().register(protocol.MaxPrekeyLifetime) // statement 1, at rev 1
			from := a.raw().register(protocol.MaxPrekeyLifetime)
			box := to.id.Address()
			a.want(x.onB("GET", to.path("/messages"), nil, to.pass(1)), http.StatusOK, "")
			a.want(x.onB("GET", from.path("/messages"), nil, from.pass(1)), http.StatusOK, "")
			fed(t, x.follower)
			x.hold(true)
			if err := x.writer.DeleteMailbox(context.Background(), box); err != nil { // as the sweep does
				t.Fatal(err)
			}
			a.clock.Add(time.Second)
			to.prekey(2, a.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			a.want(a.do("PUT", to.path(""), to.registration(2), to.pass(2)), http.StatusCreated, "")
			if old, ok := x.follower.Known(box); !ok || old == nil || old.Rev != 1 || !bytes.Equal(old.Statement, to.stmt[1]) {
				t.Fatal("control: B holds no copy of the record before at rev 1")
			}
			if n := x.count(`SELECT count(*)::int FROM mailboxes WHERE addr = $1 AND rev = 1`, box[:]); n != 1 {
				t.Fatal("control: the record made again is not at rev 1")
			}
			c.call(t, x, to, from)
			if n := messagesOf(x, box); n != 0 {
				t.Errorf("B's call, read from the record before, stored %d messages for the record made again", n)
			}
			var stmt []byte
			var acl bool
			if err := x.writer.pool().QueryRow(context.Background(), `SELECT statement, acl IS NOT NULL FROM mailboxes WHERE addr = $1`, box[:]).Scan(&stmt, &acl); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stmt, to.stmt[2]) || acl {
				t.Error("B's write, read from the record before, changed the record made again")
			}
			x.hold(false)
		})
	}
}

// B, behind, holds a copy of a record the sweep took on A. B's own
// revocation of certificates finds no record in the database, and B then
// holds none either: it forgets the copy (Memory.Revoke), so it serves
// nothing the database no longer holds.
func TestAProcessBehindKeepsNoRecordItsRevocationFoundGone(t *testing.T) {
	t.Parallel()
	x := newTwoProcesses(t)
	a := x.a
	to := a.raw().register(protocol.MaxPrekeyLifetime)
	box := to.id.Address()
	a.want(x.onB("GET", to.path("/messages"), nil, to.pass(1)), http.StatusOK, "")
	fed(t, x.follower)
	x.hold(true)
	if err := x.writer.DeleteMailbox(context.Background(), box); err != nil { // as the sweep does
		t.Fatal(err)
	}
	if b, ok := x.follower.Known(box); !ok || !b.hasRecord() {
		t.Fatal("control: B holds no copy of the record")
	}
	a.want(x.onB("PUT", revocationPath(box), to.certs(1), ""), http.StatusOK, "")
	if n := x.count(`SELECT count(*)::int FROM mailboxes WHERE addr = $1`, box[:]); n != 0 {
		t.Fatal("control: the database holds a record")
	}
	if b, ok := x.follower.Known(box); ok && b.hasRecord() {
		t.Errorf("after its own revocation found no record, B holds a copy of the record the sweep took, at rev %d", b.Rev)
	}
	if st, ok := x.follower.Held(box); ok {
		t.Errorf("after its own revocation found no record, B holds the mailbox's standing: %+v", st)
	}
	a.want(x.onB("GET", to.path(""), nil, ""), http.StatusNotFound, protocol.CodeMailboxNotFound)
	x.hold(false)
}
