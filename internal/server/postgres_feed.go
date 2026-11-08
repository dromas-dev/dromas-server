package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

// The feed: logical replication of the publication's four tables, through
// pgoutput, on a temporary slot of this process's own (ARCHITECTURE.md
// § Following the feed). The slot starts at the current end of WAL and goes
// with the session, so nothing is kept across a restart: a lost session is a
// lost place, and the process restarts, which rebuilds memory.

const (
	// feedSyncEvery is how often, by default, the feed shows itself current
	// (PostgresConfig.SyncInterval): it reads
	// the database's flushed WAL position at T, and is synced through T once
	// the walsender's keepalive says it has decoded past it.
	feedSyncEvery = time.Second
	// feedUnsyncedAfter is how long the feed may go without being synced
	// before Ready says it is not.
	feedUnsyncedAfter = 30 * time.Second
	// feedSilentAfter is how long a session may answer nothing before it is
	// taken for gone: wal_receiver_timeout's default, as PostgreSQL's own
	// standby takes its walsender (its docs, Replication settings,
	// read 2026-11-07). A walsender busy decoding a transaction the
	// publication leaves out sends a keepalive only every
	// wal_sender_timeout/2, its default 30 s, so a bound of 30 s would take
	// it for gone.
	feedSilentAfter = 60 * time.Second
	// feedStartWithin bounds Start: creating a slot waits for every
	// transaction open at that moment to end.
	feedStartWithin = 30 * time.Second
	// feedVisibleEvery is how long the feed waits before it asks again
	// whether a commit it has received is visible.
	feedVisibleEvery = time.Millisecond
	// feedHeldMax bounds the changes one transaction brings memory, which
	// the feed holds from its Begin to its Commit: a mailbox record held is
	// about 6 kB, so the bound is tens of MB. Every write of dromas-server's,
	// and each of the sweep's batches, changes far fewer rows; a transaction
	// past it (a migration's fill in one statement) loses the place, and the
	// process restarts, which rebuilds memory from the tables
	// (ARCHITECTURE.md § Storage, the migrations' rules).
	feedHeldMax = 10000
)

// feedTarget is a flushed WAL position, and the wall time it was read at.
type feedTarget struct {
	lsn pglogrepl.LSN
	at  time.Time
}

// Start implements Backend: it makes this process's slot, starts the
// stream, and returns once the feed is synced through the moment it was
// started; the feed is followed until ctx ends, each change handed to apply.
func (s *pgBackend) Start(ctx context.Context, apply func(Change)) error {
	s.apply = apply
	sctx, cancel := context.WithTimeout(ctx, feedStartWithin)
	defer cancel()
	conn, err := pgconn.ConnectConfig(sctx, s.replication)
	if err != nil {
		return fmt.Errorf("postgres: the feed's session: %w", err)
	}
	slot := "dromas_" + randomHex(8)
	res, err := pglogrepl.CreateReplicationSlot(sctx, conn, slot, "pgoutput", pglogrepl.CreateReplicationSlotOptions{Temporary: true, SnapshotAction: "NOEXPORT_SNAPSHOT"})
	if err != nil {
		_ = conn.Close(context.Background())
		return fmt.Errorf("postgres: the feed's slot (a role with REPLICATION, and a free replication slot and WAL sender, are needed): %w", err)
	}
	from, err := pglogrepl.ParseLSN(res.ConsistentPoint)
	if err != nil {
		_ = conn.Close(context.Background())
		return fmt.Errorf("postgres: the feed's slot: %w", err)
	}
	err = pglogrepl.StartReplication(sctx, conn, slot, from, pglogrepl.StartReplicationOptions{PluginArgs: []string{
		"proto_version '1'",
		"publication_names '" + s.publication + "'",
		"binary 'true'",
	}})
	if err != nil {
		_ = conn.Close(context.Background())
		return fmt.Errorf("postgres: the feed: %w", err)
	}
	// The flushed position is read on a connection of its own, so a pool
	// every request holds never makes the feed look behind.
	pos, err := pgx.ConnectConfig(sctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		_ = conn.Close(context.Background())
		return fmt.Errorf("postgres: the feed's position reader: %w", err)
	}
	// Whether a commit is visible is read on a connection of run's own:
	// pos is targets', and the pool every request's.
	snap, err := pgx.ConnectConfig(sctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		_ = conn.Close(context.Background())
		_ = pos.Close(context.Background())
		return fmt.Errorf("postgres: the feed's snapshot reader: %w", err)
	}
	s.snapPID.Store(snap.PgConn().PID())
	fctx, stop := context.WithCancel(ctx)
	f := &pgFeed{s: s, conn: conn, pos: pos, snap: snap, applied: from, relations: map[uint32]*pglogrepl.RelationMessage{}, types: pgtype.NewMap()}
	f.visible = f.sees
	if s.visible != nil {
		f.visible = s.visible
	}
	began := time.Now()
	go f.run(fctx)
	go f.targets(fctx)
	for {
		if s.synced.Load() >= monoNanos(began) {
			s.started.Store(true)
			if s.sweepEvery > 0 {
				go s.sweep(fctx)
			}
			context.AfterFunc(ctx, stop)
			return nil
		}
		select {
		case <-sctx.Done():
			stop() // ends run and targets, and their connections
			return fmt.Errorf("postgres: the feed did not catch up: %w", sctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Ready implements Backend: the feed is followed, and has been synced
// within feedUnsyncedAfter.
func (s *pgBackend) Ready() bool {
	synced := s.synced.Load()
	return s.started.Load() && synced != 0 && monoNanos(time.Now())-synced <= int64(feedUnsyncedAfter)
}

// monoBase is the process's start, for monoNanos.
var monoBase = time.Now()

// monoNanos is t on the monotonic clock, as nanoseconds after monoBase,
// plus one, so that 0 is never: a step of the wall clock moves neither.
func monoNanos(t time.Time) int64 { return int64(t.Sub(monoBase)) + 1 }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails
	return hex.EncodeToString(b)
}

// pgFeed is one session of the feed. Its connections are run's alone, but
// pos, which is targets'.
type pgFeed struct {
	s       *pgBackend
	conn    *pgconn.PgConn
	pos     *pgx.Conn     // targets' own
	snap    *pgx.Conn     // run's own: whether a commit is visible (sees)
	applied pglogrepl.LSN // every change up to it is applied: what each status update confirms
	inTxn   bool          // a transaction is begun and not yet applied
	xid     uint32        // the transaction begun
	made    time.Time     // the commit time of the transaction begun
	held    []fedChange   // its changes, held until its commit is visible, at most feedHeldMax
	seen    string        // the newest snapshot sees read, pg_current_snapshot()'s text; "" before one
	types   *pgtype.Map
	// visible reports whether a transaction's commit is visible to a new
	// snapshot: sees, or the backend's replacement in a test.
	visible func(ctx context.Context, xid uint32) (bool, error)

	relations map[uint32]*pglogrepl.RelationMessage

	mu      sync.Mutex
	next    *feedTarget // the newest position read, not yet asked about
	waiting *feedTarget // the position a keepalive must pass, until one does
}

// targets reads the flushed WAL position each syncEvery, for run to
// ask about. The walsender sends flushed WAL only.
func (f *pgFeed) targets(ctx context.Context) {
	t := time.NewTicker(f.s.syncEvery)
	defer t.Stop()
	defer func() { _ = f.pos.Close(context.Background()) }()
	for {
		at := time.Now()
		rctx, cancel := context.WithTimeout(ctx, max(f.s.syncEvery, time.Second))
		var lsn string
		err := f.pos.QueryRow(rctx, "SELECT pg_current_wal_flush_lsn()::text").Scan(&lsn)
		cancel()
		if err == nil {
			if pos, err := pglogrepl.ParseLSN(lsn); err == nil {
				f.mu.Lock()
				f.next = &feedTarget{pos, at}
				f.mu.Unlock()
			}
		} else if ctx.Err() == nil {
			f.s.logf("feed: reading the flushed WAL position: %v", err)
			if f.pos.IsClosed() { // made again, so one lost connection is no lasting stall
				cctx, cancel := context.WithTimeout(ctx, max(f.s.syncEvery, time.Second))
				if c, err := pgx.ConnectConfig(cctx, f.s.pool.Config().ConnConfig.Copy()); err == nil {
					f.pos = c
				}
				cancel()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// run follows the stream until ctx ends or the session is lost, applying
// each transaction once its commit is visible (commit): memory's apply
// takes its locks briefly and never waits on I/O. A session that answers
// nothing for feedSilentAfter, keepalives asked for included, is gone
// half-open.
func (f *pgFeed) run(ctx context.Context) {
	defer func() { _ = f.conn.Close(context.Background()) }()
	defer func() { _ = f.snap.Close(context.Background()) }()
	// A panic here would end the process with its words on stderr, past the
	// redaction: it is logged through the store's log, which redacts, and
	// ends the process as a lost place does, so a restart rebuilds memory.
	defer func() {
		if p := recover(); p != nil {
			f.s.logf("feed: panic: %v\n%s", p, debug.Stack())
			f.lost(ctx, fmt.Errorf("panic: %v", p))
		}
	}()
	lastHeard := time.Now()
	var nextStatus time.Time
	for {
		if ctx.Err() != nil {
			return
		}
		// Each syncEvery: confirm what is applied, and ask for a
		// keepalive, which answers a position read since (heard) and shows
		// the session alive while no change flows.
		if now := time.Now(); !now.Before(nextStatus) {
			f.mu.Lock()
			if f.waiting == nil {
				f.waiting, f.next = f.next, nil
			}
			f.mu.Unlock()
			if err := pglogrepl.SendStandbyStatusUpdate(ctx, f.conn, pglogrepl.StandbyStatusUpdate{WALWritePosition: f.applied, ReplyRequested: true}); err != nil {
				f.lost(ctx, err)
				return
			}
			nextStatus = now.Add(f.s.syncEvery)
		}
		if time.Since(lastHeard) > feedSilentAfter {
			f.lost(ctx, errors.New("the walsender has answered nothing"))
			return
		}
		rctx, cancel := context.WithDeadline(ctx, nextStatus)
		msg, err := f.conn.ReceiveMessage(rctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if pgconn.Timeout(err) {
				continue
			}
			f.lost(ctx, err)
			return
		}
		lastHeard = time.Now()
		if err := f.handle(ctx, msg); err != nil {
			f.lost(ctx, err)
			return
		}
	}
}

// lost ends the feed: memory can no longer be shown current.
func (f *pgFeed) lost(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	f.s.started.Store(false)
	f.s.logf("feed: lost its place: %v", err)
	if f.s.fatal != nil {
		f.s.fatal(fmt.Errorf("postgres: the feed lost its place: %w", err))
	}
}

func (f *pgFeed) handle(ctx context.Context, msg pgproto3.BackendMessage) error {
	switch m := msg.(type) {
	case *pgproto3.CopyData:
		if len(m.Data) == 0 {
			return nil
		}
		switch m.Data[0] {
		case pglogrepl.PrimaryKeepaliveMessageByteID:
			pkm, err := pglogrepl.ParsePrimaryKeepaliveMessage(m.Data[1:])
			if err != nil {
				return err
			}
			f.heard(pkm.ServerWALEnd)
			return nil
		case pglogrepl.XLogDataByteID:
			xld, err := pglogrepl.ParseXLogData(m.Data[1:])
			if err != nil {
				return err
			}
			lm, err := pglogrepl.Parse(xld.WALData)
			if err != nil {
				return err
			}
			return f.logical(ctx, lm)
		}
		return nil
	case *pgproto3.ErrorResponse:
		return pgconn.ErrorResponseToPgError(m)
	case *pgproto3.CopyDone:
		return errors.New("the walsender ended the stream")
	}
	return nil
}

// heard takes a keepalive: the walsender has decoded the WAL to end, and
// sent every transaction committed before it ahead of this message
// (walsender.c, WalSndKeepalive sends sentPtr). Between transactions, none
// held, everything up to end is applied.
func (f *pgFeed) heard(end pglogrepl.LSN) {
	if f.inTxn {
		return
	}
	if end > f.applied {
		f.applied = end
	}
	f.mu.Lock()
	w := f.waiting
	if w != nil && end >= w.lsn {
		f.waiting = nil
	}
	f.mu.Unlock()
	if w != nil && end >= w.lsn {
		f.s.synced.Store(monoNanos(w.at))
	}
}

// logical takes one message of pgoutput's. A transaction's changes are
// held from its Begin and applied at its Commit, once the commit is visible
// (commit), at most feedHeldMax of them.
func (f *pgFeed) logical(ctx context.Context, lm pglogrepl.Message) error {
	switch m := lm.(type) {
	case *pglogrepl.RelationMessage:
		f.relations[m.RelationID] = m
	case *pglogrepl.BeginMessage:
		f.inTxn, f.xid, f.made, f.held = true, m.Xid, m.CommitTime, f.held[:0]
	case *pglogrepl.CommitMessage:
		return f.commit(ctx, m.TransactionEndLSN)
	case *pglogrepl.InsertMessage:
		return f.hold(m.RelationID, m.Tuple, nil, false)
	case *pglogrepl.UpdateMessage:
		return f.hold(m.RelationID, m.NewTuple, m.OldTuple, false)
	case *pglogrepl.DeleteMessage:
		return f.hold(m.RelationID, m.OldTuple, nil, true)
	case *pglogrepl.TruncateMessage:
		return errors.New("a table was truncated")
	}
	return nil
}

// commit applies the transaction begun, once its commit is visible to a new
// snapshot. PostgreSQL's CommitTransaction flushes the commit's WAL, which
// wakes the walsenders, and waits for a synchronous standby, before
// ProcArrayEndTransaction makes the commit visible to a new snapshot
// (xact.c, read 2026-11-07), so the feed can bring a change that a read
// begun after memory applied it does not see. Memory's record cache and a
// mailbox's load take a read begun after a change was applied to see it
// (ARCHITECTURE.md § Memory), so nothing is applied before it is visible.
// A snapshot that sees the commit is followed by none that does not. A
// transaction that brings memory nothing is not waited on; one whose commit
// is still not visible after feedUnsyncedAfter (a synchronous standby that
// never answers holds every commit so) is a lost place, saying so, since
// the feed reads nothing meanwhile.
func (f *pgFeed) commit(ctx context.Context, end pglogrepl.LSN) error {
	for began := time.Now(); len(f.held) > 0; {
		ok, err := f.visible(ctx, f.xid)
		if err != nil {
			return fmt.Errorf("whether transaction %d is visible: %w", f.xid, err)
		}
		if ok {
			break
		}
		if waited := time.Since(began); waited > feedUnsyncedAfter {
			return fmt.Errorf("transaction %d's commit has not been visible for %v", f.xid, waited.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(feedVisibleEvery):
		}
	}
	for i := range f.held {
		f.hand(f.held[i])
		f.held[i] = fedChange{}
	}
	f.held, f.inTxn = f.held[:0], false
	if cap(f.held) > feedHeldMax/10 {
		f.held = nil // a large transaction's array is not kept for the next
	}
	if end > f.applied {
		f.applied = end
	}
	return nil
}

// sees reports whether transaction xid's commit is visible to a new
// snapshot. The newest snapshot read answers first, since a snapshot that
// sees a commit is followed by none that does not: a feed behind reads one
// snapshot for every transaction committed before it, not one each. Else it
// reads a new one on the feed's own connection, made again if it is lost.
func (f *pgFeed) sees(ctx context.Context, xid uint32) (bool, error) {
	if f.seen != "" {
		if ok, err := snapshotSees(f.seen, xid); err == nil && ok {
			return true, nil
		}
	}
	rctx, cancel := context.WithTimeout(ctx, feedUnsyncedAfter)
	defer cancel()
	var snap string
	err := f.snap.QueryRow(rctx, "SELECT pg_current_snapshot()::text").Scan(&snap)
	if err != nil && f.snap.IsClosed() && rctx.Err() == nil {
		c, cerr := pgx.ConnectConfig(rctx, f.s.pool.Config().ConnConfig.Copy())
		if cerr != nil {
			return false, fmt.Errorf("%w; the snapshot reader made again: %w", err, cerr)
		}
		f.snap = c
		f.s.snapPID.Store(c.PgConn().PID())
		err = f.snap.QueryRow(rctx, "SELECT pg_current_snapshot()::text").Scan(&snap)
	}
	if err != nil {
		return false, err
	}
	f.seen = snap
	return snapshotSees(snap, xid)
}

// snapshotSees reports whether a snapshot, pg_current_snapshot()'s text
// (xmin:xmax:xip,...; each a 64-bit xid8, its epoch in the high 32 bits),
// sees transaction xid committed, xid being the 32 bits pgoutput's Begin
// carries of a transaction that has written its commit. The xid is taken
// as the one nearest xmax, within 2^31 either way, as PostgreSQL compares
// 32-bit xids (TransactionIdPrecedes): a transaction writing its commit
// may be at or past xmax, which is one past the newest transaction whose
// end is visible, and is then in no snapshot's xip (GetSnapshotData in
// procarray.c, read 2026-11-07). Committed is below xmin, or below xmax
// and not in progress (xip).
func snapshotSees(snap string, xid uint32) (bool, error) {
	bad := func() error { return fmt.Errorf("a snapshot that does not read: %q", snap) }
	parts := strings.Split(snap, ":")
	if len(parts) != 3 {
		return false, bad()
	}
	xmin, err1 := strconv.ParseUint(parts[0], 10, 64)
	xmax, err2 := strconv.ParseUint(parts[1], 10, 64)
	if err1 != nil || err2 != nil || xmin > xmax {
		return false, bad()
	}
	epoch := xmax &^ 0xFFFFFFFF
	full := epoch | uint64(xid)
	switch {
	case full > xmax && full-xmax >= 1<<31: // of the epoch before
		if epoch == 0 {
			return false, fmt.Errorf("transaction %d is before the first epoch, against the snapshot %q", xid, snap)
		}
		full -= 1 << 32
	case full < xmax && xmax-full > 1<<31: // of the epoch after
		full += 1 << 32
	}
	var running bool
	if parts[2] != "" {
		for x := range strings.SplitSeq(parts[2], ",") {
			n, err := strconv.ParseUint(x, 10, 64)
			if err != nil || n < xmin || n >= xmax {
				return false, bad()
			}
			running = running || n == full
		}
	}
	return full < xmin || full < xmax && !running, nil
}

// fedChange is one row's change, decoded as the feed received it.
type fedChange struct {
	table string
	c     Change
	ok    bool // memory takes it
}

// hold decodes one row's change, and holds it until its transaction is
// applied; past feedHeldMax the place is lost.
func (f *pgFeed) hold(rel uint32, tuple, old *pglogrepl.TupleData, gone bool) error {
	fc, ok := f.decode(rel, tuple, old, gone)
	if !ok {
		return nil
	}
	if len(f.held) >= feedHeldMax {
		return fmt.Errorf("transaction %d changes more than %d rows memory holds", f.xid, feedHeldMax)
	}
	f.held = append(f.held, fc)
	return nil
}

// decode decodes one row's change, and reports whether it is of a table
// of the schema's. A key that does not read is skipped, as nothing can be
// said of it; a row that does not read beyond its key, a column of a type
// this build does not decode among them, is handed over as one that does
// not read (Change.Err), which memory takes as gone, so that it holds
// nothing of the row as it was.
func (f *pgFeed) decode(rel uint32, tuple, old *pglogrepl.TupleData, gone bool) (fedChange, bool) {
	r, ok := f.relations[rel]
	if !ok || r.Namespace != f.s.schema || tuple == nil {
		return fedChange{}, false
	}
	data, rowErr := f.row(r, tuple, old)
	c, err := changeOf(r.RelationName, data, gone)
	switch {
	case err != nil:
		f.s.logf("%s: skipping a change whose key does not read: %v", r.RelationName, err)
		return fedChange{table: r.RelationName}, true
	case rowErr != nil:
		c = Change{Kind: c.Kind, Addr: c.Addr, AccountID: c.AccountID, Header: c.Header, Gone: c.Gone, Err: rowErr}
	}
	return fedChange{table: r.RelationName, c: c, ok: c.Kind != 0}, true
}

// hand hands one change to memory.
func (f *pgFeed) hand(fc fedChange) {
	if fc.ok && f.s.apply != nil {
		f.s.apply(fc.c)
	}
	f.s.metrics.applied(fc.table, f.made, time.Now())
}

// row decodes a tuple by its relation's columns: every column that reads,
// and the first error of one that does not, so the key can still be read. A
// column stored out of line that an update left alone comes without its
// value ('u'): the old row holds it where it is sent whole (REPLICA IDENTITY
// FULL, the revocations table's), and the row does not read where it is not
// (the mailboxes table's, whose old row is its key).
func (f *pgFeed) row(r *pglogrepl.RelationMessage, tuple, old *pglogrepl.TupleData) (out row, first error) {
	out = make(row, len(tuple.Columns))
	fail := func(err error) {
		if first == nil {
			first = err
		}
	}
	for i, col := range tuple.Columns {
		if i >= len(r.Columns) {
			break
		}
		name, oid := r.Columns[i].Name, r.Columns[i].DataType
		if col.DataType == pglogrepl.TupleDataTypeToast {
			if old == nil || i >= len(old.Columns) || old.Columns[i].DataType == pglogrepl.TupleDataTypeToast {
				fail(fmt.Errorf("%s: an unchanged value not sent, and no old row holds it", name))
				continue
			}
			col = old.Columns[i]
		}
		var format int16
		switch col.DataType {
		case pglogrepl.TupleDataTypeNull:
			out[name] = nil
			continue
		case pglogrepl.TupleDataTypeBinary:
			format = pgtype.BinaryFormatCode
		case pglogrepl.TupleDataTypeText:
			format = pgtype.TextFormatCode
		default:
			fail(fmt.Errorf("%s: a value of kind %q", name, col.DataType))
			continue
		}
		if isJSONType(oid) {
			out[name] = rawJSON(oid, format, col.Data)
			continue
		}
		typ, ok := f.types.TypeForOID(oid)
		if !ok {
			// A column of a type this build has no codec for is one it
			// never reads (a later migration's): it is left out of the
			// row, and a decoder that reads it fails by its name.
			continue
		}
		v, err := typ.Codec.DecodeValue(f.types, oid, format, col.Data)
		if err != nil {
			fail(fmt.Errorf("%s: %w", name, err))
			continue
		}
		out[name] = v
	}
	return out, first
}

// changeOf is the change a row of table makes to what memory holds. A
// deleted row carries its key (and, under REPLICA IDENTITY FULL, the rest),
// and only the key is read.
func changeOf(table string, r row, gone bool) (Change, error) {
	switch table {
	case "mailboxes":
		a, err := r.address("addr")
		if err != nil {
			return Change{}, err
		}
		c := Change{Kind: RecordChange, Addr: a, Gone: gone}
		if !gone {
			c.Mailbox, c.Err = decodeMailbox(r)
		}
		return c, nil
	case "revocations":
		a, err := r.address("addr")
		if err != nil {
			return Change{}, err
		}
		c := Change{Kind: RevocationsChange, Addr: a, Gone: gone}
		if !gone {
			c.Revocations, c.Err = decodeRevocations(r)
		}
		return c, nil
	case "messages":
		box, err := r.address("box")
		if err != nil {
			return Change{}, err
		}
		id, err := r.hash("id")
		if err != nil {
			return Change{}, err
		}
		c := Change{Kind: MessageChange, Addr: box, Gone: gone, Header: &Header{ID: id}}
		if !gone {
			c.Header, c.Err = decodeHeader(r)
			c.Live = c.Err == nil
		}
		return c, nil
	case "accounts":
		id, err := r.str("id")
		if err != nil {
			return Change{}, err
		}
		c := Change{Kind: AccountChange, AccountID: id, Gone: gone}
		if !gone {
			c.Account, c.Err = decodeAccount(r)
		}
		return c, nil
	}
	return Change{}, nil
}
