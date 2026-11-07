package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jackc/pglogrepl"
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
	// feedSyncEvery is how often the feed shows itself current: it reads
	// the database's flushed WAL position at T, and is synced through T once
	// the walsender's keepalive says it has decoded past it.
	feedSyncEvery = time.Second
	// feedUnsyncedAfter is how long the feed may go without being synced
	// before Ready says it is not.
	feedUnsyncedAfter = 30 * time.Second
	// feedStartWithin bounds Start: creating a slot waits for every
	// transaction open at that moment to end.
	feedStartWithin = 30 * time.Second
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
	f := &pgFeed{s: s, conn: conn, applied: from, relations: map[uint32]*pglogrepl.RelationMessage{}, types: pgtype.NewMap()}
	began := time.Now()
	go f.run(ctx)
	go f.targets(ctx)
	if s.sweepEvery > 0 {
		go s.sweep(ctx)
	}
	for {
		if s.synced.Load() >= began.UnixNano() {
			s.started.Store(true)
			return nil
		}
		select {
		case <-sctx.Done():
			return fmt.Errorf("postgres: the feed did not catch up: %w", sctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Ready implements Backend: the feed is followed, and has been synced
// within feedUnsyncedAfter.
func (s *pgBackend) Ready() bool {
	return s.started.Load() && time.Since(time.Unix(0, s.synced.Load())) <= feedUnsyncedAfter
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails
	return hex.EncodeToString(b)
}

// pgFeed is one session of the feed. Its connection is run's alone.
type pgFeed struct {
	s       *pgBackend
	conn    *pgconn.PgConn
	applied pglogrepl.LSN // every change up to it is applied: what each status update confirms
	inTxn   bool
	made    time.Time // the commit time of the transaction being applied
	types   *pgtype.Map

	relations map[uint32]*pglogrepl.RelationMessage

	mu      sync.Mutex
	next    *feedTarget // the newest position read, not yet asked about
	waiting *feedTarget // the position a keepalive must pass, until one does
}

// targets reads the flushed WAL position each feedSyncEvery, for run to
// ask about. The walsender sends flushed WAL only.
func (f *pgFeed) targets(ctx context.Context) {
	t := time.NewTicker(feedSyncEvery)
	defer t.Stop()
	for {
		at := time.Now()
		rctx, cancel := context.WithTimeout(ctx, feedSyncEvery)
		var lsn string
		err := f.s.pool.QueryRow(rctx, "SELECT pg_current_wal_flush_lsn()::text").Scan(&lsn)
		cancel()
		if err == nil {
			if pos, err := pglogrepl.ParseLSN(lsn); err == nil {
				f.mu.Lock()
				f.next = &feedTarget{pos, at}
				f.mu.Unlock()
			}
		} else if ctx.Err() == nil {
			f.s.logf("feed: reading the flushed WAL position: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// run follows the stream until ctx ends or the session is lost, applying
// each change as it arrives: memory's apply takes its locks briefly and
// never waits on I/O. A session that answers nothing for feedUnsyncedAfter,
// keepalives asked for included, is gone half-open.
func (f *pgFeed) run(ctx context.Context) {
	defer func() { _ = f.conn.Close(context.Background()) }()
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
		// Each feedSyncEvery: confirm what is applied, and ask for a
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
			nextStatus = now.Add(feedSyncEvery)
		}
		if time.Since(lastHeard) > feedUnsyncedAfter {
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
		if err := f.handle(msg); err != nil {
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

func (f *pgFeed) handle(msg pgproto3.BackendMessage) error {
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
			return f.logical(lm)
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
// (walsender.c, WalSndKeepalive sends sentPtr). Between transactions,
// everything up to end is applied.
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
		f.s.synced.Store(w.at.UnixNano())
	}
}

// logical applies one message of pgoutput's.
func (f *pgFeed) logical(lm pglogrepl.Message) error {
	switch m := lm.(type) {
	case *pglogrepl.RelationMessage:
		f.relations[m.RelationID] = m
	case *pglogrepl.BeginMessage:
		f.inTxn, f.made = true, m.CommitTime
	case *pglogrepl.CommitMessage:
		f.inTxn = false
		if m.TransactionEndLSN > f.applied {
			f.applied = m.TransactionEndLSN
		}
	case *pglogrepl.InsertMessage:
		f.change(m.RelationID, m.Tuple, nil, false)
	case *pglogrepl.UpdateMessage:
		f.change(m.RelationID, m.NewTuple, m.OldTuple, false)
	case *pglogrepl.DeleteMessage:
		f.change(m.RelationID, m.OldTuple, nil, true)
	case *pglogrepl.TruncateMessage:
		return errors.New("a table was truncated")
	}
	return nil
}

// change hands one row's change to memory. A key that does not read is
// skipped, as nothing can be said of it; a row that does not read beyond
// its key, a column of a type this build does not decode among them, is
// handed over as one that does not read (Change.Err), which memory takes as
// gone, so that it holds nothing of the row as it was.
func (f *pgFeed) change(rel uint32, tuple, old *pglogrepl.TupleData, gone bool) {
	r, ok := f.relations[rel]
	if !ok || r.Namespace != f.s.schema || tuple == nil {
		return
	}
	data, rowErr := f.row(r, tuple, old)
	c, err := changeOf(r.RelationName, data, gone)
	switch {
	case err != nil:
		f.s.logf("%s: skipping a change whose key does not read: %v", r.RelationName, err)
	case c.Kind != 0 && f.s.apply != nil:
		if rowErr != nil {
			c = Change{Kind: c.Kind, Addr: c.Addr, AccountID: c.AccountID, Header: c.Header, Gone: c.Gone, Err: rowErr}
		}
		f.s.apply(c)
	}
	f.s.metrics.applied(r.RelationName, f.made, time.Now())
}

// row decodes a tuple by its relation's columns: every column that reads,
// and the first error of one that does not, so the key can still be read. A
// column stored out of line that an update left alone comes without its
// value ('u'), which the old row, sent whole under REPLICA IDENTITY FULL,
// holds.
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
			fail(fmt.Errorf("%s: a column of type %d, which this build does not read", name, oid))
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
// deleted row carries its key (and, under REPLICA IDENTITY FULL, the rest).
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
