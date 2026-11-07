package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The suite runs against the in-memory store, or, with DROMAS_TEST_POSTGRES
// set, against PostgreSQL: every test, plus the ones that need a shared store
// with a feed, in a schema of the run's own, bodies in a directory of the
// run's own. The database is the one libpq's environment names (PGHOST,
// PGPORT, PGUSER, PGPASSWORD, PGDATABASE, PGSSLMODE), as dromas-server serve
// finds its own. Name a database kept for tests, never one a running
// dromas-server uses: it needs wal_level = logical, a role with REPLICATION,
// and a replication slot and WAL sender for each store the tests run at once.
// TestMain drops the run's schema and its publication, and removes its
// bodies directory, once every test has run.

func onPostgres() bool { return os.Getenv("DROMAS_TEST_POSTGRES") != "" }

var (
	testSchemaOnce sync.Once
	testSchema     string
	testBodies     string
)

// testDatabase is this run's schema and bodies directory, made on first use.
func testDatabase(t testing.TB) (string, string) {
	t.Helper()
	testSchemaOnce.Do(func() {
		testSchema = "t_" + randomHex(6)
		dir, err := os.MkdirTemp("", "dromas-bodies-")
		if err != nil {
			panic(err)
		}
		testBodies = dir
	})
	return testSchema, testBodies
}

func newTestStore(t *testing.T, now func() time.Time) (Store, func() bool) {
	t.Helper()
	if !onPostgres() {
		return NewMemStore(now), nil
	}
	s := startPostgres(t, now)
	return s, s.Ready
}

func TestMain(m *testing.M) {
	code := m.Run()
	if onPostgres() {
		schemasMu.Lock()
		all := schemas
		if testSchema != "" {
			all = append(all, testSchema)
		}
		schemasMu.Unlock()
		for _, schema := range all {
			if err := dropSchema(schema); err != nil {
				fmt.Fprintf(os.Stderr, "dropping the schema %s: %v\n", schema, err)
				code = max(code, 1)
			}
		}
		_ = os.RemoveAll(testBodies)
	}
	os.Exit(code)
}

// A schema a test makes for itself is dropped when the run ends, never
// while other tests' feeds run: a feed decoding a change to a table dropped
// meanwhile loses its place ("could not map filenumber").
var (
	schemasMu sync.Mutex
	schemas   []string
)

// newSchema is a schema of a test's own, dropped when the run ends.
func newSchema() string {
	schema := "t_" + randomHex(6)
	schemasMu.Lock()
	schemas = append(schemas, schema)
	schemasMu.Unlock()
	return schema
}

// dropSchema drops a schema the tests made, its tables and its feed's
// publication.
func dropSchema(schema string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, "")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "DROP PUBLICATION IF EXISTS dromas_"+schema); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	return err
}

// startPostgres is a store on the run's schema, started, stopped when the
// test ends.
func startPostgres(t testing.TB, now func() time.Time) *Memory {
	t.Helper()
	schema, bodies := testDatabase(t)
	return startPostgresIn(t, schema, bodies, now, nil)
}

// freshDatabase is a schema and a bodies directory of the test's own,
// dropped when it ends, for a test that must know every row there.
func freshDatabase(t *testing.T) (string, string) {
	t.Helper()
	return newSchema(), t.TempDir()
}

// startPostgresIn is a store on schema, its bodies under the directory
// bodies, its config changed by with if set, started, stopped when the test
// ends. A feed that loses its place fails the test, unless with sets Fatal.
func startPostgresIn(t testing.TB, schema, bodies string, now func() time.Time, with func(*PostgresConfig)) *Memory {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := PostgresConfig{
		Schema:       schema,
		BodiesDir:    bodies,
		Now:          now,
		MailboxCache: 100,
		MaxConns:     4,
		Fatal:        func(err error) { t.Errorf("feed: %v", err) },
	}
	if with != nil {
		with(&c)
	}
	s, err := NewPostgresStore(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// sharedEnv is an env on a shared store with a feed, PostgreSQL; the test is
// skipped without.
func sharedEnv(t *testing.T) (*env, *Memory) {
	t.Helper()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	e := newEnv(t, relaxed())
	return e, e.store.(*Memory)
}

func (s *Memory) pg() *pgBackend { return s.backend.(*pgBackend) }

// onPg is the store as memory over the PostgreSQL backend, if it is.
func onPg(st Store) (*Memory, bool) {
	s, ok := st.(*Memory)
	if !ok {
		return nil, false
	}
	_, ok = s.backend.(*pgBackend)
	return s, ok
}

// pool is a connection pool on the run's schema, for a test's reads of the
// tables as they are.
func (s *Memory) pool() *pgxpool.Pool { return s.pg().pool }

// failOnce makes the PostgreSQL backend fail once between the two steps of
// a write, as a crash there would.
func failOnce(s *Memory, point string) {
	var mu sync.Mutex
	done := false
	s.pg().crash = func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		if p == point && !done {
			done = true
			return errors.New("injected: a crash " + p)
		}
		return nil
	}
}

// storedMsg reads a message's row as it is, or nil.
func (s *Memory) storedMsg(t *testing.T, mailbox protocol.Address, id [32]byte) row {
	t.Helper()
	rows, err := rowsOf(s.pool().Query(context.Background(), `SELECT * FROM messages WHERE box = $1 AND id = $2`, mailbox[:], id[:]))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// storedRecord reads a mailbox's record as it is, or nil.
func (s *Memory) storedRecord(t *testing.T, a protocol.Address) row {
	t.Helper()
	rows, err := rowsOf(s.pool().Query(context.Background(), `SELECT * FROM mailboxes WHERE addr = $1`, a[:]))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// bodyKeyOf is where a live message's body is kept, as its row names it.
func (s *Memory) bodyKeyOf(t *testing.T, mailbox protocol.Address, id [32]byte) string {
	t.Helper()
	r := s.storedMsg(t, mailbox, id)
	if r == nil {
		t.Fatalf("no row of the message %s", hexID(id))
	}
	recv, err := r.time("received_at")
	if err != nil {
		t.Fatal(err)
	}
	return bodyKey(mailbox, id, ms(recv))
}

// hasBody reports whether a body is kept under key.
func (s *Memory) hasBody(t *testing.T, key string) bool {
	t.Helper()
	_, err := s.pg().bodies.Get(context.Background(), key, 0, 0)
	if err != nil && !errors.Is(err, errNoBody) {
		t.Fatal(err)
	}
	return err == nil
}

// bodyExists reports whether a live message's body is kept: the message's
// row names it.
func (s *Memory) bodyExists(t *testing.T, mailbox protocol.Address, id [32]byte) bool {
	t.Helper()
	if s.storedMsg(t, mailbox, id) == nil {
		return false
	}
	return s.hasBody(t, s.bodyKeyOf(t, mailbox, id))
}

// lists reports whether the mailboxes table holds mailbox a under account.
func (s *Memory) lists(t *testing.T, account string, a protocol.Address, want bool) {
	t.Helper()
	var n int
	if err := s.pool().QueryRow(context.Background(), `SELECT count(*) FROM mailboxes WHERE account = $1 AND addr = $2`, account, a[:]).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if (n > 0) != want {
		t.Fatalf("the mailboxes table lists %s under %q: %v, want %v", a, account, n > 0, want)
	}
}
