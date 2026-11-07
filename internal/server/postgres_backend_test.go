package server

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgtype"
)

// The PostgreSQL backend's own risks: what its feed, its sweep and its
// bodies directory do that no other backend does.

// A mailbox record past 2 kB, its ACL stored out of line, reaches another
// process's memory whole through the feed when an update leaves the ACL
// alone, as an adopt does: pgoutput sends an unchanged out-of-line value
// without its bytes, and the old row, which REPLICA IDENTITY FULL sends
// whole, holds them.
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
	acc, key := accountEnv(t, e, false, 1)
	adopt(t, b, key)
	waitFor("the adopt reaching the other process", func() bool {
		rec, ok := other.Known(a)
		return ok && rec != nil && rec.Account == acc.ID
	})
	here, err := s.Mailbox(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if there, _ := other.Known(a); there.ACL == nil || there.ACL.Deny.Len() != len(deny) || !there.ACL.SameLists(here.ACL) {
		t.Fatalf("the other process holds the record adopted without its ACL whole: %+v", there.ACL)
	}
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
		if err := s.pg().sweepTable(ctx, x.table, x.column, x.keep); err != nil {
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
	f.change(1, tuple, nil, false)
	if len(got) != 1 || got[0].Kind != RecordChange || got[0].Addr != a || got[0].Err == nil || got[0].Mailbox != nil {
		t.Fatalf("the change handed over: %+v; want the address's record, as one that does not read", got)
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
