package server

import (
	"context"
	"strconv"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5"
)

// sweepBatch is how many rows one statement of the sweep deletes: pgoutput
// sends a transaction only once it commits, so one large delete would hold
// every follower behind it.
const sweepBatch = 500

// sweep deletes, each sweepEvery, the rows past their expiry by more than
// sweepGrace, which no read takes as live (PostgreSQL has no TTL), and what
// a revoked address left beside its revocation, which no call is answered
// from (a message a send stored as the revocation's delete ran, a record
// whose delete failed; PROTOCOL.md §11.15), and collects bodies on disk as
// old. It runs on the database's clock (each
// batch's transaction's start), unlike
// every other condition, so a process whose clock is wrong deletes nothing
// early.
func (s *pgBackend) sweep(ctx context.Context) {
	t := time.NewTicker(s.sweepEvery)
	defer t.Stop()
	retention := protocol.Retention
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, x := range []struct {
			table, column string
			keep          time.Duration
		}{
			{"messages", "received_at", retention + s.sweepGrace},
			{"mailboxes", "expires_at", s.sweepGrace},
			{"adopt_keys", "expires_at", s.sweepGrace},
		} {
			if err := s.sweepExpired(ctx, x.table, x.column, x.keep); err != nil && ctx.Err() == nil {
				s.logf("sweep: %s: %v", x.table, err)
			}
		}
		s.sweepRevoked(ctx)
		if s.bodiesDir != nil {
			// By the database's clock, as the rows' sweep: a body's key
			// names when its send was received.
			var now time.Time
			rctx, cancel := bounded(ctx)
			err := s.pool.QueryRow(rctx, "SELECT now()").Scan(&now)
			cancel()
			if err == nil {
				err = s.bodiesDir.collect(now.Add(-retention - s.sweepGrace))
			}
			if err != nil && ctx.Err() == nil {
				s.logf("sweep: the bodies directory: %v", err)
			}
		}
	}
}

// sweepRevoked deletes the messages and the record of each address revoked
// that are left beside its revocation.
func (s *pgBackend) sweepRevoked(ctx context.Context) {
	for _, x := range []struct{ table, column string }{{"messages", "box"}, {"mailboxes", "addr"}} {
		if err := s.sweepTable(ctx, x.table, x.column+` IN (SELECT addr FROM revocations WHERE revocation IS NOT NULL)`); err != nil && ctx.Err() == nil {
			s.logf("sweep: %s of revoked addresses: %v", x.table, err)
		}
	}
}

// sweepExpired deletes table's rows whose column is more than keep in the
// past (sweepTable).
func (s *pgBackend) sweepExpired(ctx context.Context, table, column string, keep time.Duration) error {
	return s.sweepTable(ctx, table, column+` < now() - $1::interval`, keep)
}

// sweepTable deletes table's rows that meet cond, whose arguments are args,
// in batches, each its own transaction holding the schema's sweep lock (an
// advisory lock keyed by the schema's name, so one process of a schema
// sweeps at a time), until a batch is short or another process holds the
// lock.
func (s *pgBackend) sweepTable(ctx context.Context, table, cond string, args ...any) error {
	limit := "$" + strconv.Itoa(len(args)+1)
	for {
		var n int64
		took := false
		err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtext('dromas sweep ' || current_schema()))").Scan(&took); err != nil || !took {
				return err
			}
			// now() is the transaction's start, the same through the
			// statement, so the condition takes the column's index (a
			// volatile clock never does); it is repeated outside, so a row
			// changed since the inner read is deleted only if it still meets it.
			tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE ctid = ANY (ARRAY(SELECT ctid FROM `+table+`
				WHERE `+cond+` LIMIT `+limit+`)) AND `+cond, append(args, sweepBatch)...)
			n = tag.RowsAffected()
			return err
		})
		if err != nil || !took || n < sweepBatch {
			return err
		}
	}
}
