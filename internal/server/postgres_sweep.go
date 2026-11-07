package server

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// sweepBatch is how many rows one statement of the sweep deletes: pgoutput
// sends a transaction only once it commits, so one large delete would hold
// every follower behind it.
const sweepBatch = 500

// sweepLock is the advisory lock the sweep takes, so one process at a time
// deletes.
const sweepLock = 0x64726f6d6173 // "dromas"

// sweep deletes, each sweepEvery, the rows past their expiry by more than
// sweepGrace, which no read takes as live (PostgreSQL has no TTL), and
// collects bodies on disk as old. It runs on the database's clock, unlike
// every other condition, so a process whose clock is wrong deletes nothing
// early.
func (s *pgBackend) sweep(ctx context.Context) {
	t := time.NewTicker(s.sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, table := range []string{"messages", "mailboxes", "adopt_keys"} {
			if err := s.sweepTable(ctx, table); err != nil && ctx.Err() == nil {
				s.logf("sweep: %s: %v", table, err)
			}
		}
		if s.bodiesDir != nil {
			// A body is older than its row's expiry, which its key's
			// time sets: the sweep's grace covers a clock behind.
			if err := s.bodiesDir.collect(time.Now().Add(-time.Duration(ttlMs)*time.Millisecond - s.sweepGrace)); err != nil && ctx.Err() == nil {
				s.logf("sweep: the bodies directory: %v", err)
			}
		}
	}
}

// sweepTable deletes table's expired rows in batches, each its own
// transaction holding the lock, until a batch is short or another process
// holds it.
func (s *pgBackend) sweepTable(ctx context.Context, table string) error {
	for {
		var n int64
		took := false
		err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", int64(sweepLock)).Scan(&took); err != nil || !took {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE ctid IN (SELECT ctid FROM `+table+`
				WHERE expires_at < (extract(epoch FROM clock_timestamp()) * 1000)::bigint - $1 LIMIT $2)`,
				s.sweepGrace.Milliseconds(), sweepBatch)
			n = tag.RowsAffected()
			return err
		})
		if err != nil || !took || n < sweepBatch {
			return err
		}
	}
}
