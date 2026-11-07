package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// The bounds on a migration's statements, set on its session: a DDL
// statement that waits for its lock behind a long transaction holds every
// statement on its table behind it, so it gives up after migrateLockTimeout,
// and the migration rolls back whole. These are what strong_migrations
// recommends (its README, read 2026-11-07). A file of -- +goose NO TRANSACTION that
// builds an index CONCURRENTLY sets its own statement_timeout.
const (
	migrateLockTimeout      = "10s"
	migrateStatementTimeout = "1h"
)

// Migrate brings the database's schema up to date, as dromas-server migrate
// does: it makes the schema if it is not there and applies, in order, every
// migration this build holds that the database has not (migrations/), one
// process of a schema at a time (goose's session lock, keyed by the schema).
// It runs as the schema's owner, with CREATE on the database; serve runs as
// a role that owns nothing (ARCHITECTURE.md § Storage). url is a libpq
// connection string, empty for libpq's environment; schema, empty, is
// public. It returns the versions applied, and the schema's version after.
func Migrate(ctx context.Context, url, schema string, l *log.Logger) (applied []int64, version int64, err error) {
	schema, err = schemaName(schema)
	if err != nil {
		return nil, 0, err
	}
	cc, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: %w", err)
	}
	cc.RuntimeParams["search_path"] = schema
	cc.RuntimeParams["lock_timeout"] = migrateLockTimeout
	cc.RuntimeParams["statement_timeout"] = migrateStatementTimeout
	db := stdlib.OpenDB(*cc)
	defer func() { _ = db.Close() }()
	if err := checkServer(ctx, db, l); err != nil {
		return nil, 0, err
	}
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil && !isPgCode(err, "42P06", "23505") {
		return nil, 0, fmt.Errorf("postgres: %w", err)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte("dromas migrate " + schema))
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(int64(h.Sum64()>>1)), lock.WithLockTimeout(1, 60)) //nolint:gosec // 63 bits
	if err != nil {
		return nil, 0, err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrationsFS(), goose.WithSessionLocker(locker))
	if err != nil {
		return nil, 0, err
	}
	results, err := p.Up(ctx)
	for _, r := range results {
		if r.Error == nil {
			applied = append(applied, r.Source.Version)
		}
	}
	if err != nil {
		return applied, 0, fmt.Errorf("postgres: migrations: %w", err)
	}
	version, _, err = p.GetVersions(ctx)
	if err != nil {
		return applied, 0, fmt.Errorf("postgres: migrations: %w", err)
	}
	return applied, version, nil
}

// errNotMigrated is a database whose schema is behind this build's: serve
// and account start only on one dromas-server migrate has brought up to date.
var errNotMigrated = errors.New("run dromas-server migrate first")

// schemaReady checks that the schema holds every migration this build
// holds, reading goose's version table and writing nothing (goose's own
// GetVersions and HasPending make that table where it is missing, which a
// role that owns nothing may not): a schema behind is errNotMigrated; one
// ahead, of a later build's migrations, is taken and logged, since a
// rolling upgrade runs the earlier build on it (each migration expands what
// the earlier build reads; ARCHITECTURE.md § Storage).
func schemaReady(ctx context.Context, db *sql.DB, schema string, l *log.Logger) error {
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrationsFS())
	if err != nil {
		return err
	}
	var exists bool
	if err := db.QueryRowContext(ctx, "SELECT to_regclass('goose_db_version') IS NOT NULL").Scan(&exists); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if !exists {
		return fmt.Errorf("postgres: the schema %s holds no migrations: %w", schema, errNotMigrated)
	}
	// A version's latest row says whether it is applied (goose's table: a
	// down migration adds a row, never deletes one).
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT ON (version_id) version_id, is_applied FROM goose_db_version ORDER BY version_id, id DESC")
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	applied := map[int64]bool{}
	var current int64
	for rows.Next() {
		var v int64
		var ok bool
		if err := rows.Scan(&v, &ok); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres: %w", err)
		}
		if ok && v > 0 {
			applied[v] = true
			current = max(current, v)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	var missing []string
	var target int64
	for _, m := range p.ListSources() {
		target = m.Version
		if !applied[m.Version] {
			missing = append(missing, strconv.FormatInt(m.Version, 10))
		}
	}
	switch {
	case len(missing) > 0:
		return fmt.Errorf("postgres: the schema %s lacks this build's migrations %s: %w", schema, strings.Join(missing, ", "), errNotMigrated)
	case current > target:
		logf(l, "postgres: the schema %s is at version %d, ahead of this build's %d, which runs on it", schema, current, target)
	}
	return nil
}

// checkServer checks what dromas-server needs of the database server, and
// logs what it recommends and finds unset (ARCHITECTURE.md § Following the
// feed).
func checkServer(ctx context.Context, db *sql.DB, l *log.Logger) error {
	var version int
	var walLevel, keep, senderTimeout string
	if err := db.QueryRowContext(ctx, "SELECT current_setting('server_version_num')::int, current_setting('wal_level'), current_setting('max_slot_wal_keep_size'), current_setting('wal_sender_timeout')").Scan(&version, &walLevel, &keep, &senderTimeout); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	var missing []string
	if version < minServerVersion {
		missing = append(missing, fmt.Sprintf("PostgreSQL %d or later (this is %d)", minServerVersion/10000, version/10000))
	}
	if walLevel != "logical" {
		missing = append(missing, fmt.Sprintf("wal_level = logical (it is %s)", walLevel))
	}
	if len(missing) > 0 {
		return fmt.Errorf("postgres: dromas-server needs %s", strings.Join(missing, ", and "))
	}
	if keep == "-1" {
		logf(l, "postgres: max_slot_wal_keep_size is unlimited: a feed that stops reading holds the database's WAL without bound")
	}
	if senderTimeout == "0" {
		logf(l, "postgres: wal_sender_timeout is 0: a feed whose process is gone keeps its slot, and its WAL, until the connection breaks")
	}
	return nil
}

// schemaName is schema, or public if empty, if it is an identifier that
// needs no quoting.
func schemaName(schema string) (string, error) {
	if schema == "" {
		schema = "public"
	}
	if !pgIdent(schema) {
		return "", fmt.Errorf("postgres: schema %q is not a lowercase identifier", schema)
	}
	return schema, nil
}

func logf(l *log.Logger, format string, args ...any) {
	if l != nil {
		l.Printf(format, args...)
	}
}

func migrationsFS() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err) // the embedded directory is always there
	}
	return sub
}
