package server

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The suite runs against the in-memory store, or, with DROMAS_TEST_POSTGRES
// set to a libpq connection string, against PostgreSQL: every test, plus the
// ones that need a shared store with a feed, in a schema of the run's own,
// bodies in a directory of the run's own. Name a database kept for tests,
// never one a running dromas-server uses: it needs wal_level = logical, a
// role with REPLICATION, and a replication slot and WAL sender for each
// store the tests run at once.

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

// startPostgres is a store on the run's schema, started, stopped when the
// test ends.
func startPostgres(t testing.TB, now func() time.Time) *Memory {
	t.Helper()
	schema, bodies := testDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := NewPostgresStore(ctx, PostgresConfig{
		URL:          os.Getenv("DROMAS_TEST_POSTGRES"),
		Schema:       schema,
		BodiesDir:    bodies,
		Now:          now,
		MailboxCache: 100,
		MaxConns:     4,
		Fatal:        func(err error) { t.Errorf("feed: %v", err) },
	})
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

// bodyExists reports whether a live message's body is kept: the message's
// row names it.
func (s *Memory) bodyExists(t *testing.T, mailbox protocol.Address, id [32]byte) bool {
	t.Helper()
	r := s.storedMsg(t, mailbox, id)
	if r == nil {
		return false
	}
	recv, err := r.uint("received_at")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.pg().bodies.Get(context.Background(), bodyKey(mailbox, id, recv), 0, 0)
	if err != nil && !errors.Is(err, errNoBody) {
		t.Fatal(err)
	}
	return err == nil
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
