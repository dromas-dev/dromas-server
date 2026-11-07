package server

import (
	"context"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5"
)

// sweepBatch is how many rows one statement of the sweep deletes: pgoutput
// sends a transaction only once it commits, so one large delete would hold
// every follower behind it.
const sweepBatch = 500

// sweep deletes, each sweepEvery, the rows past their expiry by more than
// sweepGrace, which no read takes as live (PostgreSQL has no TTL), and
// collects bodies on disk as old. It runs on the database's clock, unlike
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
			if err := s.sweepTable(ctx, x.table, x.column, x.keep); err != nil && ctx.Err() == nil {
				s.logf("sweep: %s: %v", x.table, err)
			}
		}
		if s.bodiesDir != nil {
			// A body is written at its row's received_at: the grace covers
			// a clock behind.
			if err := s.bodiesDir.collect(time.Now().Add(-retention - s.sweepGrace)); err != nil && ctx.Err() == nil {
				s.logf("sweep: the bodies directory: %v", err)
			}
		}
	}
}

// sweepTable deletes table's rows whose column is more than keep in the
// past, in batches, each its own transaction holding the schema's sweep
// lock (an advisory lock keyed by the schema's name, so one process of a
// schema sweeps at a time), until a batch is short or another process holds
// the lock.
func (s *pgBackend) sweepTable(ctx context.Context, table, column string, keep time.Duration) error {
	for {
		var n int64
		took := false
		err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtext('dromas sweep ' || current_schema()))").Scan(&took); err != nil || !took {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE ctid IN (SELECT ctid FROM `+table+`
				WHERE `+column+` < clock_timestamp() - $1::interval LIMIT $2)`, keep, sweepBatch)
			n = tag.RowsAffected()
			return err
		})
		if err != nil || !took || n < sweepBatch {
			return err
		}
	}
}
