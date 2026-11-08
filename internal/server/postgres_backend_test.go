package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The PostgreSQL backend's own risks: what its feed, its sweep and its
// bodies directory do that no other backend does.

// A mailbox record past 2 kB, its ACL stored out of line, is never held in
// part by another process. An update that writes the ACL anew, as a renewal
// does, reaches it whole through the feed. One that leaves the ACL alone, as
// an adopt does, comes without the ACL's bytes (pgoutput's unchanged
// out-of-line value, under the table's REPLICA IDENTITY DEFAULT, which logs
// no old row): the other process forgets the record, and its next read
// reads it whole.
func TestALargeRecordReachesAnotherProcessWhole(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	ctx := context.Background()
	other := startPostgres(t, e.clock.Now)
	b := e.mailbox()
	a := b.Address()
	deny := make([]string, 200)
	for i := range deny {
		var x protocol.Address
		_, _ = rand.Read(x[:])
		deny[i] = x.String()
	}
	e.want(e.do("PUT", "/v1/"+a.String()+"/acl", aclOf([]string{"*"}, deny), e.pass(b)), 200, "")
	var outOfLine bool
	switch err := s.pool().QueryRow(ctx, `SELECT pg_column_toast_chunk_id(acl) IS NOT NULL FROM mailboxes WHERE addr = $1`, a[:]).Scan(&outOfLine); {
	case isPgCode(err, "42883"): // before PostgreSQL 17
		t.Log("this PostgreSQL cannot say whether the ACL is stored out of line")
	case err != nil:
		t.Fatal(err)
	case !outOfLine:
		t.Fatal("control: the ACL is stored in line, so the update sends it whole")
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for start := time.Now(); !ok(); time.Sleep(50 * time.Millisecond) {
			if time.Since(start) > 15*time.Second {
				t.Fatalf("%s: not within 15 s", what)
			}
		}
	}
	// The other process holds the record with the ACL, read once its feed
	// is past the ACL's write, so that no image of it keeps the read out.
	waitFor("the other process holding the record with its ACL", func() bool {
		if _, err := other.Mailbox(ctx, a); err != nil {
			t.Fatal(err)
		}
		rec, ok := other.Known(a)
		return ok && rec != nil && rec.ACL != nil
	})
	whole := func(what string, there *Mailbox) {
		t.Helper()
		fed(t, s)
		here, err := s.Mailbox(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if there.Rev != here.Rev || there.ACL == nil || there.ACL.Deny.Len() != len(deny) || !there.ACL.SameLists(here.ACL) {
			t.Fatalf("%s: the other process holds rev %d without its ACL whole (%+v); here rev %d", what, there.Rev, there.ACL, here.Rev)
		}
	}
	// A renewal's update writes the ACL anew: the other process takes the
	// change in place, and holds the record at its new revision with no read.
	held, err := s.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	renewed := *held
	renewed.Expires = renewed.Expires.Add(time.Minute)
	if err := s.pg().UpdateMailbox(ctx, &renewed); err != nil {
		t.Fatal(err)
	}
	waitFor("the renewal reaching the other process in place", func() bool {
		rec, ok := other.Known(a)
		if !ok {
			t.Fatal("the other process forgot the record a renewal wrote whole")
		}
		return rec != nil && rec.Rev == held.Rev+1
	})
	there, _ := other.Known(a)
	whole("the renewal", there)
	// An adopt leaves the ACL alone: the other process forgets the record,
	// and reads it whole on its next use.
	acc, key := accountEnv(t, e, false, 1)
	adopt(t, b, key)
	waitFor("the adopt reaching the other process", func() bool {
		rec, ok := other.Known(a)
		return !ok || rec != nil && rec.Account == acc.ID
	})
	if rec, ok := other.Known(a); ok && rec.Account == acc.ID {
		t.Fatal("control: the adopt reached the other process in place, so its update sent the ACL")
	}
	there, err = other.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if there.Account != acc.ID {
		t.Fatalf("the other process read the record adopted with account %q; want %q", there.Account, acc.ID)
	}
	whole("the adopt", there)
}

// The sweep deletes the rows past their expiry, in batches, of messages,
// mailboxes and adopt keys, and nothing live: run once per table with no
// grace, in a schema of the test's own.
func TestTheSweepDeletesWhatHasExpired(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	ctx := context.Background()
	schema, bodies := freshDatabase(t)
	s := startPostgresIn(t, schema, bodies, nil, nil)
	e := newEnv(t, relaxed(), func(c *Config) { c.Store = s })
	gone, kept := e.mailbox().Address(), e.mailbox().Address()
	now := time.Now()
	past := time.UnixMilli(1)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE mailboxes SET expires_at = $2 WHERE addr = $1`, gone[:], past)
	live := &Header{ID: [32]byte{1}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	if err := s.backend.PutMessage(ctx, kept, live, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	// More expired messages than one batch deletes.
	exec(`INSERT INTO messages (box, id, size, received_at, nonce)
		SELECT $1, sha256(i::text::bytea), 3, $2, '\x0000000000000000' FROM generate_series(1, $3::int) i`, kept[:], past, 2*sweepBatch+1)
	if err := s.backend.CreateAccount(ctx, &Account{ID: "acct", Rev: 1}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []*AdoptKey{
		{Account: "acct", Hash: [32]byte{1}, Uses: 1, Expires: past},
		{Account: "acct", Hash: [32]byte{2}, Uses: 1, Expires: now.Add(time.Hour)},
	} {
		if err := s.backend.PutAdoptKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := s.pool().QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("messages"); n != 2*sweepBatch+2 {
		t.Fatalf("control: %d messages planted", n)
	}
	for _, x := range []struct {
		table, column string
		keep          time.Duration
	}{{"messages", "received_at", protocol.Retention}, {"mailboxes", "expires_at", 0}, {"adopt_keys", "expires_at", 0}} {
		if err := s.pg().sweepExpired(ctx, x.table, x.column, x.keep); err != nil {
			t.Fatalf("the sweep of %s: %v", x.table, err)
		}
	}
	if n := count("messages"); n != 1 || s.storedMsg(t, kept, live.ID) == nil {
		t.Errorf("after the sweep %d messages are kept; want the live one alone", n)
	}
	if s.storedRecord(t, gone) != nil || s.storedRecord(t, kept) == nil || count("mailboxes") != 1 {
		t.Error("the sweep did not delete the expired mailbox's record alone")
	}
	if _, err := s.backend.AdoptKey(ctx, "acct", [32]byte{2}); err != nil || count("adopt_keys") != 1 {
		t.Errorf("the sweep did not delete the expired adopt key alone: the live one %v", err)
	}
}

// The bodies directory's collection deletes every body last written before
// its cutoff, and keeps the others; a directory it empties goes on a later
// pass, and the directory's root stays.
func TestTheBodiesDirectoryCollectsOldBodies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	d, err := newDirBodies(root)
	if err != nil {
		t.Fatal(err)
	}
	var oldBox, newBox protocol.Address
	oldBox[0], newBox[0] = 1, 2
	now := time.Now()
	// Judged by the time its key names, whatever the file's own: a body
	// written just now under an old send's key goes, and a new send's stays.
	oldKey, newKey := bodyKey(oldBox, [32]byte{1}, ms(now.Add(-2*time.Hour)), []byte{1}), bodyKey(newBox, [32]byte{2}, ms(now), []byte{2})
	for _, k := range []string{oldKey, newKey} {
		if err := d.Put(ctx, k, []byte("ciphertext")); err != nil {
			t.Fatal(err)
		}
	}
	// A file that is no body's key, a write a crash left, by its own time.
	if err := d.root.WriteFile("stray", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.root.Chtimes("stray", now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.collect(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, oldKey, 0, 0); !errors.Is(err, errNoBody) {
		t.Errorf("a body written before the cutoff: %v; want it gone", err)
	}
	if body, err := d.Get(ctx, newKey, 0, 0); err != nil || string(body) != "ciphertext" {
		t.Errorf("a body written after the cutoff: %q %v; want it kept", body, err)
	}
	if _, err := d.root.Stat("stray"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file that is no key, written before the cutoff: %v; want it gone", err)
	}
	for range 3 { // one directory a pass, from the deepest
		if err := d.collect(now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var left []string
	if err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err == nil && p != root {
			left = append(left, filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator))))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{newBox.String(), newBox.String() + "/" + hexID([32]byte{2}), newKey}
	if !slices.Equal(left, want) {
		t.Errorf("the directory holds %v; want %v", left, want)
	}
}

// A store whose feed's session ends is no longer ready, and calls Fatal: its
// memory can no longer be shown current.
func TestALostFeedIsNotReady(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	ctx := context.Background()
	schema, bodies := testDatabase(t)
	app := "dromas_test_" + randomHex(6)
	fatal := make(chan error, 1)
	s := startPostgresIn(t, schema, bodies, nil, func(c *PostgresConfig) {
		c.URL = "application_name=" + app // the rest from libpq's environment
		c.Fatal = func(err error) {
			select {
			case fatal <- err:
			default:
			}
		}
	})
	if !s.Ready() {
		t.Fatal("control: the store is not ready once started")
	}
	var n int
	if err := s.pool().QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_replication WHERE application_name = $1`, app).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ending the feed's session: %d sessions, %v; want 1", n, err)
	}
	select {
	case err := <-fatal:
		t.Logf("Fatal: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Fatal was not called within 10 s of the feed's session ending")
	}
	if s.Ready() {
		t.Error("the store is ready with its feed's session ended")
	}
}

// A column of a type this build has no codec for, a later migration's, is
// left out of the feed's row, which reads without it. A row that then does
// not read past its key, here for every column a record reads, is handed
// to memory as one that does not read, so memory forgets what it held of
// it; never skipped, which would leave memory answering from the row as it
// was.
func TestAFeedRowThatDoesNotReadIsForgotten(t *testing.T) {
	t.Parallel()
	var got []Change
	f := &pgFeed{
		s:     &pgBackend{schema: "s", apply: func(c Change) { got = append(got, c) }},
		types: pgtype.NewMap(),
		relations: map[uint32]*pglogrepl.RelationMessage{1: {RelationID: 1, Namespace: "s", RelationName: "mailboxes", Columns: []*pglogrepl.RelationMessageColumn{
			{Name: "addr", DataType: pgtype.ByteaOID},
			{Name: "mood", DataType: 4_000_000_000}, // a type no build decodes
		}}},
	}
	var a protocol.Address
	a[0] = 7
	tuple := &pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{
		{DataType: pglogrepl.TupleDataTypeBinary, Data: a[:]},
		{DataType: pglogrepl.TupleDataTypeText, Data: []byte("happy")},
	}}
	r, err := f.row(f.relations[1], tuple, nil)
	if _, mood := r["mood"]; err != nil || mood || r["addr"] == nil {
		t.Fatalf("a row with a column of a type no codec reads: %v, %v; want it read without that column", r, err)
	}
	fc, ok := f.decode(1, tuple, nil, false)
	if !ok {
		t.Fatal("the change is of no table of the schema's")
	}
	f.hand(fc)
	if len(got) != 1 || got[0].Kind != RecordChange || got[0].Addr != a || got[0].Err == nil || got[0].Mailbox != nil {
		t.Fatalf("the change handed over: %+v; want the address's record, as one that does not read", got)
	}
}

// The feed applies a transaction only once its commit is visible to a new
// snapshot: PostgreSQL sends a commit to the walsenders before it is
// visible, and memory takes a read begun after a change was applied to see
// it. Here another process's write is held invisible to the follower's
// feed: the follower neither applies it nor is synced past it until the
// hold ends, and then applies it. Every transaction outside the hold is
// asked of a real snapshot.
func TestTheFeedAppliesATransactionOnlyOnceItsCommitIsVisible(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	ctx := context.Background()
	schema, bodies := freshDatabase(t)
	writer := startPostgresIn(t, schema, bodies, nil, nil)
	e := newEnv(t, relaxed(), func(c *Config) { c.Store = writer })
	follower, fctx := newPostgresIn(t, schema, bodies, nil, nil)
	var mu sync.Mutex
	held, asked := false, map[uint32]bool{}
	follower.pg().visible = func(ctx context.Context, xid uint32) (bool, error) {
		mu.Lock()
		hold := held
		if hold {
			asked[xid] = true
		}
		mu.Unlock()
		if hold {
			return false, nil
		}
		var snap string
		if err := follower.pool().QueryRow(ctx, "SELECT pg_current_snapshot()::text").Scan(&snap); err != nil {
			return false, err
		}
		return snapshotSees(snap, xid)
	}
	if err := follower.Start(fctx); err != nil {
		t.Fatal(err)
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for start := time.Now(); !ok(); time.Sleep(20 * time.Millisecond) {
			if time.Since(start) > 15*time.Second {
				t.Fatalf("%s: not within 15 s", what)
			}
		}
	}
	b := e.mailbox()
	a := b.Address()
	waitFor("the follower holding the record", func() bool {
		if _, err := follower.Mailbox(ctx, a); err != nil {
			t.Fatal(err)
		}
		rec, ok := follower.Known(a)
		return ok && rec != nil
	})
	if rec, _ := follower.Known(a); rec.ACL != nil {
		t.Fatalf("control: the record holds an ACL before one is set: %+v", rec.ACL)
	}
	fed(t, follower)

	mu.Lock()
	held = true
	mu.Unlock()
	var x protocol.Address
	_, _ = rand.Read(x[:])
	e.want(e.do("PUT", "/v1/"+a.String()+"/acl", aclOf([]string{"*"}, []string{x.String()}), e.pass(b)), 200, "")
	written := time.Now()
	waitFor("the follower's feed asking whether the write is visible", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(asked) > 0
	})
	// Room for every status update and keepalive that would sync the feed
	// past the write.
	time.Sleep(10 * follower.pg().syncEvery)
	switch rec, ok := follower.Known(a); {
	case !ok || rec == nil:
		t.Fatal("the follower no longer holds the record")
	case rec.ACL != nil:
		t.Fatalf("the follower applied a write whose commit is held invisible: it holds the ACL %+v", rec.ACL)
	}
	if synced := time.Unix(0, follower.pg().synced.Load()); !synced.Before(written) {
		t.Fatalf("the follower's feed is synced through %v, past a write at %v whose commit is held invisible", synced, written)
	}

	mu.Lock()
	held = false
	mu.Unlock()
	waitFor("the follower applying the write once it is visible", func() bool {
		rec, ok := follower.Known(a)
		return ok && rec != nil && rec.ACL != nil && rec.ACL.Deny.Len() == 1
	})
	fed(t, follower)
}

// A snapshot sees a transaction committed below its xmin, or below its xmax
// and not in progress; a transaction at or past xmax is not yet visible,
// as the one writing its commit is before its end is. The 32-bit xid is
// taken as the one nearest xmax, across an epoch's end either way.
func TestASnapshotSeesWhatHasCommitted(t *testing.T) {
	t.Parallel()
	const e1 = 1 << 32 // the first xid of epoch 1
	for _, c := range []struct {
		snap string
		xid  uint32
		want bool
	}{
		{"100:104:", 99, true},
		{"100:104:", 100, true},
		{"100:104:", 103, true},
		{"100:104:", 104, false}, // the newest, writing its commit
		{"100:104:", 105, false},
		{"100:104:100,102", 100, false},
		{"100:104:100,102", 101, true},
		{"100:104:100,102", 102, false},
		{"100:104:100,102", 103, true},
		{"104:104:", 104, false},
		{"104:104:", 103, true},
		{"100:104:", 104 + 1<<31 - 1, false}, // as far ahead as one can be
		{"3:3:", 3, false},
		// xmax just past epoch 1's start.
		{fmt.Sprint(e1-6, ":", e1+5, ":"), 0xFFFFFFF0, true},
		{fmt.Sprint(e1-6, ":", e1+5, ":", e1-4), 0xFFFFFFFC, false},
		{fmt.Sprint(e1-6, ":", e1+5, ":", e1-4), 0xFFFFFFFD, true},
		{fmt.Sprint(e1-6, ":", e1+5, ":", e1+3), 3, false},
		{fmt.Sprint(e1-6, ":", e1+5, ":", e1+3), 4, true},
		{fmt.Sprint(e1-6, ":", e1+5, ":"), 5, false},
		{fmt.Sprint(e1-6, ":", e1+5, ":"), 6, false},
		// xmax just short of epoch 1: a transaction of epoch 1 is ahead.
		{fmt.Sprint(e1-20, ":", e1-10, ":"), 2, false},
		{fmt.Sprint(e1-20, ":", e1-10, ":"), 0xFFFFFFF0, true},
		{fmt.Sprint(e1-20, ":", e1-10, ":"), 0xFFFFFFF6, false},
		// Epoch 2.
		{fmt.Sprint(2*e1+8, ":", 2*e1+10, ":"), 8, true},
		{fmt.Sprint(2*e1+8, ":", 2*e1+10, ":"), 0xFFFFFFFF, true},
		{fmt.Sprint(2*e1+8, ":", 2*e1+10, ":", 2*e1+9), 9, false},
		{fmt.Sprint(2*e1+8, ":", 2*e1+10, ":"), 10, false},
	} {
		got, err := snapshotSees(c.snap, c.xid)
		if err != nil || got != c.want {
			t.Errorf("snapshot %s sees %d: %v, %v; want %v", c.snap, c.xid, got, err, c.want)
		}
	}
	for _, c := range []struct {
		snap string
		xid  uint32
	}{
		{"", 1}, {"1:2", 1}, {"1:2:3:4", 1}, {"a:2:", 1}, {"1:b:", 1}, {"-1:4:", 1},
		{"5:4:", 1},                  // xmin past xmax
		{"1:4:x", 1}, {"1:4:2,,", 1}, // an xip that does not read
		{"1:4:4", 1}, {"2:4:1", 1}, // an xip outside [xmin, xmax)
		{"100:104:", 104 + 1<<31}, // of an epoch before the first
		{"100:104:", 0xFFFFFFFF},  // likewise
	} {
		if got, err := snapshotSees(c.snap, c.xid); err == nil {
			t.Errorf("snapshot %q sees %d: %v; want an error", c.snap, c.xid, got)
		}
	}
}

// The sweep's condition takes its table's index: a volatile clock in it
// would make every pass read the whole table.
func TestTheSweepTakesItsIndex(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	s := startPostgres(t, time.Now)
	ctx := context.Background()
	for _, x := range [][2]string{{"messages", "received_at"}, {"mailboxes", "expires_at"}, {"adopt_keys", "expires_at"}} {
		tx, err := s.pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL enable_seqscan = off"); err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		rows, err := tx.Query(ctx, `EXPLAIN SELECT ctid FROM `+x[0]+` WHERE `+x[1]+` < now() - '1 hour'::interval LIMIT 500`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		rows.Close()
		_ = tx.Rollback(ctx)
		if strings.Contains(plan.String(), "Seq Scan") || !strings.Contains(plan.String(), "Index") {
			t.Errorf("the sweep of %s reads it without its index:\n%s", x[0], plan.String())
		}
	}
}

// A transaction that brings memory more changes than the feed holds loses
// its place, and the process restarts, rather than holding it whole; one of
// exactly as many is applied.
func TestATransactionPastWhatTheFeedHoldsLosesItsPlace(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	schema, bodies := freshDatabase(t)
	lost := make(chan error, 1)
	s := startPostgresIn(t, schema, bodies, nil, func(c *PostgresConfig) {
		c.Fatal = func(err error) {
			select {
			case lost <- err:
			default:
			}
		}
	})
	insert := func(n int) {
		t.Helper()
		if _, err := s.pool().Exec(context.Background(), `INSERT INTO messages (box, id, size, received_at, nonce)
			SELECT sha384(($2 || i)::bytea), sha256(($2 || i)::bytea), 0, now(), '\x0000000000000000'::bytea FROM generate_series(1, $1::int) i`, n, randomHex(4)); err != nil {
			t.Fatal(err)
		}
	}
	insert(feedHeldMax)
	fed(t, s)
	select {
	case err := <-lost:
		t.Fatalf("control: a transaction of %d rows lost the place: %v", feedHeldMax, err)
	default:
	}
	insert(feedHeldMax + 1)
	select {
	case err := <-lost:
		if !strings.Contains(err.Error(), "more than") {
			t.Fatalf("the place was lost for another reason: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("a transaction of %d rows did not lose the place", feedHeldMax+1)
	}
}

// The newest snapshot the feed read answers for a transaction it already
// sees committed, with no read of its own: the feed has no connection here.
func TestTheNewestSnapshotAnswersWhatItSees(t *testing.T) {
	t.Parallel()
	f := &pgFeed{seen: "100:105:102", seenAt: time.Now()}
	for _, xid := range []uint32{99, 101, 103} {
		if ok, err := f.sees(context.Background(), xid); err != nil || !ok {
			t.Errorf("transaction %d against %q: %v, %v; want seen, with no read", xid, f.seen, ok, err)
		}
	}
}

// A snapshot older than feedUnsyncedAfter answers nothing: against one 2^31
// transactions old, a new transaction's 32-bit xid reads as one of the
// epoch before, below its xmin, and seen.
func TestAnOldSnapshotAnswersNothing(t *testing.T) {
	t.Parallel()
	const xid = uint32(100 + 1<<31 + 5) // 2^31+5 past the snapshot's xmax, in its epoch
	f := &pgFeed{seen: "4294967396:4294967396:", seenAt: time.Now()}
	if !f.cachedSees(xid) {
		t.Fatalf("transaction %d against a young %q: not seen; the test no longer makes the case", xid, f.seen)
	}
	f.seenAt = time.Now().Add(-feedUnsyncedAfter)
	if f.cachedSees(xid) {
		t.Errorf("transaction %d against %q read %v ago: seen; want a new snapshot read", xid, f.seen, feedUnsyncedAfter)
	}
}

// A column an update left alone ('u') takes its value from the old row only
// where the old row holds it: under a key's old row ('K') every other
// column is null, and the row does not read, never reads it as null.
func TestAnUnchangedColumnIsNeverTakenFromAKeysOldRow(t *testing.T) {
	t.Parallel()
	f := &pgFeed{types: pgtype.NewMap()}
	rel := &pglogrepl.RelationMessage{RelationID: 1, Namespace: "s", RelationName: "mailboxes", Columns: []*pglogrepl.RelationMessageColumn{
		{Name: "addr", DataType: pgtype.ByteaOID},
		{Name: "acl", DataType: pgtype.ByteaOID},
	}}
	key := &pglogrepl.TupleDataColumn{DataType: pglogrepl.TupleDataTypeBinary, Data: []byte{7}}
	tuple := &pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{key, {DataType: pglogrepl.TupleDataTypeToast}}}
	whole := &pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{key, {DataType: pglogrepl.TupleDataTypeBinary, Data: []byte("acl")}}}
	if r, err := f.row(rel, tuple, whole); err != nil || string(r["acl"].([]byte)) != "acl" {
		t.Fatalf("under a whole old row: %v, %v; want the old row's value", r, err)
	}
	keyOnly := &pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{key, {DataType: pglogrepl.TupleDataTypeNull}}}
	if r, err := f.row(rel, tuple, keyOnly); err == nil {
		t.Errorf("under a key's old row: %v; want a row that does not read", r)
	}
}

// The feed's snapshot reader, ended by the database, is made again, and the
// feed keeps its place: a write after it reaches memory.
func TestTheSnapshotReaderIsMadeAgain(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	pid := s.pg().snapPID.Load()
	err := asTestRole(func(ctx context.Context, conn *pgx.Conn) error {
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, int32(pid)).Scan(&ok); err != nil || !ok {
			return fmt.Errorf("pg_terminate_backend(%d): %v, %w", pid, ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b := e.mailbox()
	e.want(e.do("PUT", "/v1/"+b.Address().String()+"/acl", aclOf([]string{"*"}, nil), e.pass(b)), 200, "")
	fed(t, s)
	for start := time.Now(); s.pg().snapPID.Load() == pid; time.Sleep(10 * time.Millisecond) {
		if time.Since(start) > 15*time.Second {
			t.Fatal("the snapshot reader was not made again")
		}
	}
	if !s.pg().Ready() {
		t.Fatal("the feed is not ready after its snapshot reader was made again")
	}
}

// Each connection of the pool has the database bound its statements, its
// lock waits and a transaction left idle by a call's bound, so a call its
// bound ends leaves nothing running there.
func TestTheDatabaseBoundsEveryCall(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	s := startPostgres(t, nil)
	for p, want := range map[string]time.Duration{
		"statement_timeout":                   storeTimeout - storeTimeout/10,
		"lock_timeout":                        storeTimeout - storeTimeout/10,
		"idle_in_transaction_session_timeout": storeTimeout,
	} {
		var ms int64
		if err := s.pool().QueryRow(context.Background(), `SELECT setting::bigint FROM pg_settings WHERE name = $1`, p).Scan(&ms); err != nil {
			t.Fatal(err)
		}
		if got := time.Duration(ms) * time.Millisecond; got != want {
			t.Errorf("%s = %v; want %v", p, got, want)
		}
	}
}

// A send whose row the database refuses deletes the body it put first:
// nothing names it.
func TestARefusedSendLeavesNoBody(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	schema, bodies := freshDatabase(t)
	s := startPostgresIn(t, schema, bodies, nil, nil)
	var box protocol.Address
	_, _ = rand.Read(box[:])
	var id [32]byte
	_, _ = rand.Read(id[:])
	// A size past the column's CHECK: the database refuses the row.
	h := &Header{ID: id, Size: 16777217, ReceivedAt: time.Now()}
	err := s.pg().PutMessage(context.Background(), box, h, []byte("body"))
	if err == nil || !isRefusal(err) {
		t.Fatalf("the send: %v; want a refusal", err)
	}
	if keys := s.bodiesOf(t, box); len(keys) != 0 {
		t.Fatalf("a refused send left its body: %v", keys)
	}
}
