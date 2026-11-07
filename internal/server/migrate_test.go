package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Several processes migrating one schema at once apply each migration
// once, and every one of them answers with the schema up to date.
func TestMigrateAppliesEachMigrationOnce(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	schema := newSchema()
	want, err := migrationVersions()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var mu sync.Mutex
	var applied []int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			got, version, err := Migrate(ctx, "", schema, nil)
			mu.Lock()
			defer mu.Unlock()
			applied = append(applied, got...)
			if err != nil || version != want[len(want)-1] {
				t.Errorf("a migration: version %d, %v; want %d", version, err, want[len(want)-1])
			}
		})
	}
	wg.Wait()
	if len(applied) != len(want) {
		t.Fatalf("applied %v across the processes; want each of %v once", applied, want)
	}
}

// A store starts only on a schema that holds every migration of its build
// (dromas-server migrate first), and on one a later build migrated further,
// which a rolling upgrade runs the earlier build on, saying so.
func TestAStoreStartsOnlyOnAMigratedSchema(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	versions, err := migrationVersions()
	if err != nil {
		t.Fatal(err)
	}
	last := versions[len(versions)-1]
	schema := newSchema()
	var logged bytes.Buffer
	var mu sync.Mutex
	open := func() error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := NewPostgresStore(ctx, PostgresConfig{Schema: schema, Log: log.New(lockedWriter{&mu, &logged}, "", 0)})
		return err
	}
	if err := open(); !errors.Is(err, errNotMigrated) {
		t.Fatalf("a store on a schema never migrated: %v; want %v", err, errNotMigrated)
	}
	url := pgURL(t, schema)
	if err := open(); err != nil {
		t.Fatalf("a store on the migrated schema: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := NewPostgresStore(ctx, PostgresConfig{URL: url, Schema: schema}); err != nil {
		t.Fatalf("control: a store as the runtime role: %v", err)
	}
	set := func(q string, args ...any) {
		t.Helper()
		err := asTestRole(func(ctx context.Context, conn *pgx.Conn) error {
			if _, err := conn.Exec(ctx, "SET search_path = "+schema); err != nil {
				return err
			}
			_, err := conn.Exec(ctx, q, args...)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	set("INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)", last+1)
	if err := open(); err != nil {
		t.Fatalf("a store on a schema a later build migrated: %v", err)
	}
	mu.Lock()
	ahead := strings.Contains(logged.String(), "ahead of this build's")
	mu.Unlock()
	if !ahead {
		t.Errorf("a store on a schema ahead of its build logged %q; want it said", logged.String())
	}
	set("DELETE FROM goose_db_version WHERE version_id >= $1", last)
	if err := open(); !errors.Is(err, errNotMigrated) {
		t.Fatalf("a store on a schema without one of its build's migrations: %v; want %v", err, errNotMigrated)
	}
}

// migrationVersions is this build's migrations' versions, in order.
func migrationVersions() ([]int64, error) {
	var out []int64
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		var v int64
		for _, c := range e.Name() {
			if c < '0' || c > '9' {
				break
			}
			v = v*10 + int64(c-'0')
		}
		out = append(out, v)
	}
	return out, nil
}
