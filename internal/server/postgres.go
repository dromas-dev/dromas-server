package server

import (
	"cmp"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// pgBackend is the durable backend (ARCHITECTURE.md § Storage): mailbox
// records, revocations, messages' headers, accounts and adopt keys in
// PostgreSQL, one table each, bodies outside it (bodies), and the change
// feed by logical replication (postgres_feed.go). It is the mapping of SQL
// to the Backend's operations and their three outcomes, and nothing more:
// what a write's answer means is read in one place (pgOutcome), and every
// call is bounded in one place (bounded).
//
// A send writes the body, then the message's row; an ack deletes the row,
// then the body. A crash between leaves a body no row names, which goes by
// age; never a row whose body is gone.
type pgBackend struct {
	pool        *pgxpool.Pool
	replication *pgconn.Config // the feed's session
	schema      string
	publication string
	bodies      bodies
	now         func() time.Time
	log         *log.Logger
	metrics     *Metrics
	fatal       func(error)

	sweepEvery, sweepGrace time.Duration
	syncEvery              time.Duration // how often the feed shows itself current
	bodiesDir              *dirBodies    // collected by the sweep, when bodies are on disk

	apply   func(Change) // what Start was given
	started atomic.Bool
	synced  atomic.Int64 // the time (monoNanos) through which the feed has applied every change; 0, never

	// crash, in tests, fails a write of two steps between them, as a
	// crash there would leave it: "put: after the body", "ack: after the
	// row".
	crash func(step string) error
}

// PostgresConfig configures a store over PostgreSQL.
type PostgresConfig struct {
	// URL is a libpq connection string, a URL or key=value pairs; empty,
	// the database is found as libpq finds one, by its environment
	// (PGHOST, PGDATABASE, PGUSER, PGPASSWORD, PGSERVICE and the rest),
	// which is how dromas-server serve finds it.
	URL string
	// Schema holds the tables, and names the publication the feed reads
	// (publicationName); empty: public.
	Schema string
	// Bodies are kept in a bucket, through AWS, or under a directory: one
	// of the two, or neither for a store that keeps no messages (the
	// operator's account commands).
	AWS       aws.Config
	Bucket    string
	BodiesDir string
	Now       func() time.Time // time.Now if nil
	// MailboxCache is how many mailbox records memory holds, as many account
	// records, and as many mailboxes remembered as missing; 0: none.
	MailboxCache int
	// MaxConns bounds the pool; 0: pgxpool's default.
	MaxConns int32
	Log      *log.Logger // nil: no log
	// Fatal is called if the feed loses its place. Memory can no longer be
	// shown current; the process must restart, which rebuilds it from the
	// tables.
	Fatal func(error)
	// SweepInterval is how often expired rows are deleted, and bodies on
	// disk collected; 0: never. SweepGrace is how long past its expiry a
	// row is kept.
	SweepInterval, SweepGrace time.Duration
	// SyncInterval is how often the feed shows itself current (postgres_feed.go);
	// 0: feedSyncEvery.
	SyncInterval time.Duration
	// Metrics, if set, count the caches' hits, misses and evictions, and how
	// far behind the feed memory follows.
	Metrics *Metrics
}

// minServerVersion is the oldest PostgreSQL this backend runs on
// (server_version_num).
const minServerVersion = 150000

//go:embed migrations/*.sql
var migrations embed.FS

// NewPostgresStore returns the store over PostgreSQL: Memory over the
// PostgreSQL backend, on a schema Migrate has brought up to date, not ready
// until Start returns. The pool is closed when ctx ends.
func NewPostgresStore(ctx context.Context, c PostgresConfig) (*Memory, error) {
	if c.Bucket != "" && c.BodiesDir != "" {
		return nil, errors.New("postgres: name a bucket or a bodies directory, not both")
	}
	schema, err := schemaName(c.Schema)
	if err != nil {
		return nil, err
	}
	pc, err := pgxpool.ParseConfig(c.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	// A write is answered once its WAL is flushed, which the feed's
	// "synced through" reads (postgres_feed.go): never later.
	pc.ConnConfig.RuntimeParams["synchronous_commit"] = "on"
	if c.MaxConns > 0 {
		pc.MaxConns = c.MaxConns
	}
	rc, err := pgconn.ParseConfig(c.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	rc.RuntimeParams["replication"] = "database"
	if rc.RuntimeParams["application_name"] == "" {
		// The feed's walsender by name: never one that
		// synchronous_standby_names takes for a standby.
		rc.RuntimeParams["application_name"] = "dromas-server feed"
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	go func() { <-ctx.Done(); pool.Close() }()
	s := newMemory(c.Now, c.MailboxCache, c.Log, c.Metrics)
	p := &pgBackend{
		pool:        pool,
		replication: rc,
		schema:      schema,
		publication: publicationName(schema),
		now:         s.clock,
		log:         s.log,
		metrics:     c.Metrics,
		fatal:       c.Fatal,
		sweepEvery:  c.SweepInterval,
		sweepGrace:  c.SweepGrace,
		syncEvery:   cmp.Or(c.SyncInterval, feedSyncEvery),
	}
	switch {
	case c.Bucket != "":
		p.bodies = s3Bodies{newS3(c.AWS), c.Bucket}
	case c.BodiesDir != "":
		d, err := newDirBodies(c.BodiesDir)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("--bodies-dir: %w", err)
		}
		p.bodies, p.bodiesDir = d, d
	}
	if err := p.prepare(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s.backend = p
	return s, nil
}

// pgIdent reports whether s is an identifier that needs no quoting.
func pgIdent(s string) bool {
	if s == "" || len(s) > 63 || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// prepare checks what the backend needs of the database, and that the
// schema is migrated (schemaReady): the backend applies no migration
// (Migrate does) and changes no schema.
func (s *pgBackend) prepare(ctx context.Context) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	db := stdlib.OpenDBFromPool(s.pool)
	defer func() { _ = db.Close() }()
	if err := checkServer(ctx, db, s.log); err != nil {
		return err
	}
	return schemaReady(ctx, db, s.schema, s.log)
}

// isPgCode reports whether err is PostgreSQL's answer with one of codes.
func isPgCode(err error, codes ...string) bool {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return false
	}
	for _, c := range codes {
		if pe.Code == c {
			return true
		}
	}
	return false
}

func (s *pgBackend) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Printf(format, args...)
	}
}

func (s *pgBackend) nowMs() uint64 { return ms(s.now()) }

// liveFrom is the earliest received_at a live message has at now: one
// received at or before now − Retention has expired, though the sweep may
// not have deleted it yet (ttlMs, protocol.Retention).
func (s *pgBackend) liveFrom() time.Time { return time.UnixMilli(toInt(s.nowMs() - ttlMs + 1)).UTC() }

// msTime is t as the tables keep a time: to the millisecond, as memory
// compares it (ms).
func msTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// crashed is a step of a two-step write failing as a crash there would.
func (s *pgBackend) crashed(step string) error {
	if s.crash == nil {
		return nil
	}
	return s.crash(step)
}

// toInt is a time in ms, or a count, as PostgreSQL's bigint keeps it.
func toInt(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// numeric is v as PostgreSQL's numeric, which holds every uint64.
func numeric(v uint64) pgtype.Numeric {
	return pgtype.Numeric{Int: new(big.Int).SetUint64(v), Valid: true}
}

// pgOutcome is the one reading of what PostgreSQL answered a write, as one
// of the three outcomes (Backend). err nil: applied. An answer of the
// database's own is a statement it rolled back, a transaction's statement or
// its COMMIT included, so a refusal stated, when it is an ERROR; so is a
// write pgx never sent:
// one whose connection was never made (pgconn.ConnectError), or that pgx
// marks safe to retry (pgconn.SafeToRetry). Anything else is unknown: an
// answer lost, a context that ended mid-statement, a COMMIT with no
// answer. pgx retries nothing it sent.
func pgOutcome(err error) error {
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	var ce *pgconn.ConnectError
	// A connection never made sent nothing, whatever the database said
	// to refuse it: a FATAL at its start (57P03, starting up or shutting
	// down; 53300, too many connections; 28P01, a password refused)
	// comes wrapped in it.
	if errors.As(err, &ce) || pgconn.SafeToRetry(err) {
		return refused(err)
	}
	if errors.As(err, &pe) {
		// Only an ERROR rolls its statement back: a FATAL or a PANIC can
		// come after the commit (xact.c: "cannot abort transaction %u, it
		// was already committed"), and a connection's end (08, 57P) leaves
		// it open.
		sev := pe.SeverityUnlocalized
		if sev == "" {
			sev = pe.Severity
		}
		if sev == "ERROR" && !strings.HasPrefix(pe.Code, "08") && !strings.HasPrefix(pe.Code, "57P") {
			return refused(err)
		}
		return unknown(err)
	}
	return unknown(err)
}

// acquire is a connection of the pool for one write. Nothing of the write
// is sent before it returns, so its error is a refusal, whatever it reads
// as: a connection the database refused, or a context that ended while the
// write waited in the pool's queue.
func (s *pgBackend) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	c, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, refused(err)
	}
	return c, nil
}

// write runs fn in one transaction and reads its outcome: an error fn
// states (ErrStale and the like) is a refusal it made, and rolls back.
func (s *pgBackend) write(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	c, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	tx, err := c.Begin(ctx)
	if err != nil {
		return refused(err) // the transaction never began: none of fn was sent
	}
	if err := fn(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		if isRefusal(err) || errors.Is(err, ErrUnknown) {
			return err
		}
		return pgOutcome(err)
	}
	return pgOutcome(tx.Commit(ctx))
}

// exec runs one statement as one write, and returns the rows it changed.
func (s *pgBackend) exec(ctx context.Context, sql string, args ...any) (int64, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	c, err := s.acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Release()
	tag, err := c.Exec(ctx, sql, args...)
	if err != nil {
		return 0, pgOutcome(err)
	}
	return tag.RowsAffected(), nil
}

// row is one row as pgx decodes it, by column name: what a query reads and
// what the feed hands over (postgres_feed.go), read by one set of decoders.
type row map[string]any

// rowsOf collects a query's rows.
func rowsOf(rows pgx.Rows, err error) ([]row, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []row
	fields := rows.FieldDescriptions()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		raw := rows.RawValues()
		r := make(row, len(vals))
		for i, f := range fields {
			r[f.Name] = vals[i]
			if vals[i] != nil && isJSONType(f.DataTypeOID) {
				r[f.Name] = rawJSON(f.DataTypeOID, f.Format, raw[i])
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// isJSONType reports whether oid is json or jsonb, which a row holds as
// the document's text (rawJSON), never as pgx decodes it: the ACL is read
// by the protocol's own rules, from its exact text.
func isJSONType(oid uint32) bool { return oid == pgtype.JSONOID || oid == pgtype.JSONBOID }

// rawJSON is a json or jsonb value's text, from the bytes of either format:
// jsonb's binary format is a version byte, 1, then the text.
func rawJSON(oid uint32, format int16, b []byte) json.RawMessage {
	if oid == pgtype.JSONBOID && format == pgtype.BinaryFormatCode && len(b) > 0 && b[0] == 1 {
		b = b[1:]
	}
	return json.RawMessage(slices.Clone(b))
}

// has reports whether the column name holds a value, not NULL; a row with
// no such column is an error, never a NULL: a feed's row of a schema that
// dropped a column this build reads (ARCHITECTURE.md § Storage).
func (r row) has(name string) (bool, error) {
	v, ok := r[name]
	if !ok {
		return false, fmt.Errorf("row: %s is missing", name)
	}
	return v != nil, nil
}

func (r row) bytes(name string) ([]byte, error) {
	switch v := r[name].(type) {
	case []byte:
		return v, nil
	case json.RawMessage:
		return v, nil
	}
	return nil, fmt.Errorf("row: %s is missing or not bytes", name)
}

// time reads a timestamptz.
func (r row) time(name string) (time.Time, error) {
	if v, ok := r[name].(time.Time); ok {
		return v.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("row: %s is missing or not a time", name)
}

func (r row) address(name string) (protocol.Address, error) {
	var a protocol.Address
	b, err := r.bytes(name)
	if err != nil {
		return a, err
	}
	if len(b) != len(a) {
		return a, fmt.Errorf("row: %s is not %d bytes", name, len(a))
	}
	copy(a[:], b)
	return a, nil
}

func (r row) hash(name string) ([32]byte, error) {
	var h [32]byte
	b, err := r.bytes(name)
	if err != nil {
		return h, err
	}
	if len(b) != len(h) {
		return h, fmt.Errorf("row: %s is not 32 bytes", name)
	}
	copy(h[:], b)
	return h, nil
}

func (r row) str(name string) (string, error) {
	if v, ok := r[name].(string); ok {
		return v, nil
	}
	return "", fmt.Errorf("row: %s is missing or not text", name)
}

func (r row) boolean(name string) (bool, error) {
	if v, ok := r[name].(bool); ok {
		return v, nil
	}
	return false, fmt.Errorf("row: %s is missing or not a boolean", name)
}

// uint reads a whole number this server wrote, of any of the integer types
// or numeric, that is not negative.
func (r row) uint(name string) (uint64, error) {
	switch v := r[name].(type) {
	case int64:
		if v >= 0 {
			return uint64(v), nil
		}
	case int32:
		if v >= 0 {
			return uint64(v), nil
		}
	case int16:
		if v >= 0 {
			return uint64(v), nil
		}
	case pgtype.Numeric:
		if n, ok := numericUint(v); ok {
			return n, nil
		}
	}
	return 0, fmt.Errorf("row: %s is missing or not a whole number of at most %d", name, uint64(math.MaxUint64))
}

func numericUint(n pgtype.Numeric) (uint64, bool) {
	if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite || n.Int == nil {
		return 0, false
	}
	v := new(big.Int).Set(n.Int)
	if n.Exp > 0 {
		v.Mul(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n.Exp)), nil))
	} else if n.Exp < 0 {
		d, m := new(big.Int).DivMod(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-n.Exp)), nil), new(big.Int))
		if m.Sign() != 0 {
			return 0, false
		}
		v = d
	}
	if v.Sign() < 0 || !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

// count reads a count no larger than the largest int32.
func (r row) count(name string) (int, error) {
	n, err := r.uint(name)
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("row: %s is not a count of at most %d", name, math.MaxInt32)
	}
	return int(n), nil
}

// size reads a message's size: no larger than the protocol's largest
// ciphertext.
func (r row) size(name string) (int, error) {
	n, err := r.uint(name)
	if err != nil || n > protocol.MaxCiphertext {
		return 0, fmt.Errorf("row: %s is not a size of at most %d bytes", name, protocol.MaxCiphertext)
	}
	return int(n), nil
}

// strings reads a text[].
func (r row) strings(name string) ([]string, error) {
	switch v := r[name].(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("row: an element of %s is not text", name)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("row: %s is missing or not a text array", name)
}

// json reads a json or jsonb column into v.
func (r row) json(name string, v any) error {
	b, ok := r[name].(json.RawMessage)
	if !ok {
		return fmt.Errorf("row: %s is missing or not JSON", name)
	}
	return json.Unmarshal(b, v)
}

// The mailbox record.

// mailboxCols are a mailbox record's columns, as ReadAddress reads them.
const mailboxCols = "m.addr, m.identity, m.created, m.statement, m.statement_sig, m.rank, m.signer, m.senders, m.retired, m.acl, m.account, m.expires_at, m.rev"

// retiredJSON is a retired prekey as the retired column keeps it.
type retiredJSON struct {
	Type     string `json:"type"`
	NotAfter uint64 `json:"not_after"`
	KeyHash  string `json:"key_hash"` // hex
}

func retiredColumn(b *Mailbox) []byte {
	l := make([]retiredJSON, 0, len(b.Retired))
	for _, r := range b.Retired {
		l = append(l, retiredJSON{string(r.Type), ms(r.NotAfter), hex.EncodeToString(r.KeyHash[:])})
	}
	doc, _ := json.Marshal(l) // strings and numbers always marshal
	return doc
}

func aclColumn(b *Mailbox) []byte {
	if b.ACL == nil {
		return nil
	}
	doc, err := json.Marshal(b.ACL.Document())
	if err != nil { // a document of strings and a number always marshals
		return nil
	}
	return doc
}

func expiresColumn(b *Mailbox) time.Time { return msTime(b.Expires) }

func sendersColumn(b *Mailbox) []string {
	if b.SenderKeyTypes == nil {
		return []string{}
	}
	return b.SenderKeyTypes
}

func accountColumn(b *Mailbox) *string {
	if b.Account == "" {
		return nil
	}
	return &b.Account
}

// decodeStanding reads from a mailbox record what memory holds of it, at its
// rev: a record is active, and Listed is the revocations' to say
// (index.standing).
func decodeStanding(r row) (Standing, uint64, error) {
	doc, err := r.bytes("identity")
	if err != nil {
		return Standing{}, 0, err
	}
	key, err := identityWire(doc)
	if err != nil {
		return Standing{}, 0, fmt.Errorf("row: the stored identity: %w", err)
	}
	signer, err := r.hash("signer")
	if err != nil {
		return Standing{}, 0, err
	}
	rev, err := r.uint("rev")
	if err != nil {
		return Standing{}, 0, err
	}
	rank, err := r.uint("rank")
	if err != nil {
		return Standing{}, 0, err
	}
	st := Standing{State: Active, Key: key, Signer: signer, Rank: rank}
	inAccount, err := r.has("account")
	if err != nil {
		return Standing{}, 0, err
	}
	if inAccount {
		acc, err := r.str("account")
		if err != nil {
			return Standing{}, 0, err
		}
		st.InAccount = acc != ""
	}
	return st, rev, nil
}

// decodeACL reads a mailbox record's ACL. It was checked when it was stored, so
// one that does not read is a fault of the record.
func decodeACL(r row) (*protocol.ACL, error) {
	doc, err := r.bytes("acl")
	if err != nil {
		return nil, err
	}
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("row: the stored ACL: %w", err)
	}
	acl, err := protocol.CheckACL(&d, 0)
	if err != nil {
		return nil, fmt.Errorf("row: the stored ACL: %w", err)
	}
	return acl, nil
}

func decodeMailbox(r row) (*Mailbox, error) {
	a, err := r.address("addr")
	if err != nil {
		return nil, err
	}
	st, rev, err := decodeStanding(r)
	if err != nil {
		return nil, err
	}
	b := &Mailbox{Addr: a, State: st.State, Signer: st.Signer, Rank: st.Rank, Rev: rev}
	if b.Identity, err = r.bytes("identity"); err != nil {
		return nil, err
	}
	if st.InAccount {
		if b.Account, err = r.str("account"); err != nil {
			return nil, err
		}
	}
	if b.Expires, err = r.time("expires_at"); err != nil {
		return nil, err
	}
	hasACL, err := r.has("acl")
	if err != nil {
		return nil, err
	}
	if hasACL {
		if b.ACL, err = decodeACL(r); err != nil {
			return nil, err
		}
	}
	if b.Statement, err = r.bytes("statement"); err != nil {
		return nil, err
	}
	if b.Signature, err = r.bytes("statement_sig"); err != nil {
		return nil, err
	}
	if b.Created, err = r.time("created"); err != nil {
		return nil, err
	}
	if b.Prekey, err = protocol.ParsePrekey(b.Statement); err != nil {
		return nil, fmt.Errorf("row: the stored prekey: %w", err)
	}
	if b.SenderKeyTypes, err = r.strings("senders"); err != nil {
		return nil, err
	}
	if len(b.SenderKeyTypes) == 0 {
		b.SenderKeyTypes = nil
	}
	var retired []retiredJSON
	if err := r.json("retired", &retired); err != nil {
		return nil, err
	}
	for _, x := range retired {
		h, err := hex.DecodeString(x.KeyHash)
		if err != nil || len(h) != 32 {
			return nil, errors.New("row: a retired prekey's key_hash is not 32 bytes")
		}
		notAfter, err := fromMs(x.NotAfter)
		if err != nil {
			return nil, err
		}
		ret := Retired{Type: protocol.KeyType(x.Type), NotAfter: notAfter}
		copy(ret.KeyHash[:], h)
		b.Retired = append(b.Retired, ret)
	}
	return b, nil
}

// The revocations row.

const revocationCols = "addr, identity, revocation, revoked_certs, revoked_certs_sig, through"

// decodeRevocations reads an address's revocations row.
func decodeRevocations(r row) (*Revocations, error) {
	rv := &Revocations{}
	var err error
	if rv.Identity, err = r.bytes("identity"); err != nil {
		return nil, err
	}
	listed, err := r.has("revocation")
	if err != nil {
		return nil, err
	}
	if listed {
		if rv.Address, err = r.bytes("revocation"); err != nil {
			return nil, err
		}
	}
	certs, err := r.has("through")
	if err != nil {
		return nil, err
	}
	if certs {
		if rv.Through, err = r.uint("through"); err != nil {
			return nil, err
		}
		if rv.Certs, err = r.bytes("revoked_certs"); err != nil {
			return nil, err
		}
		if rv.CertsSig, err = r.bytes("revoked_certs_sig"); err != nil {
			return nil, err
		}
	}
	return rv, nil
}

// ReadAddress implements Backend: the address's mailbox record and its
// revocations, in one statement, one snapshot.
func (s *pgBackend) ReadAddress(ctx context.Context, a protocol.Address) (*Mailbox, *Revocations, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := rowsOf(s.pool.Query(ctx, `SELECT `+mailboxCols+`,
		r.identity AS r_identity, r.revocation AS r_revocation, r.revoked_certs AS r_revoked_certs, r.revoked_certs_sig AS r_revoked_certs_sig, r.through AS r_through
		FROM (SELECT $1::bytea AS addr) k
		LEFT JOIN mailboxes m ON m.addr = k.addr
		LEFT JOIN revocations r ON r.addr = k.addr`, a[:]))
	if err != nil {
		return nil, nil, err
	}
	if len(rows) != 1 {
		return nil, nil, fmt.Errorf("postgres: a read of one address gave %d rows", len(rows))
	}
	r := rows[0]
	var rec *Mailbox
	var rv *Revocations
	if r["addr"] != nil {
		if rec, err = decodeMailbox(r); err != nil {
			return nil, nil, err
		}
	}
	if r["r_identity"] != nil {
		rr := row{"identity": r["r_identity"], "revocation": r["r_revocation"], "revoked_certs": r["r_revoked_certs"], "revoked_certs_sig": r["r_revoked_certs_sig"], "through": r["r_through"]}
		if rv, err = decodeRevocations(rr); err != nil {
			return nil, nil, err
		}
	}
	return rec, rv, nil
}

// CreateMailbox implements Backend.
func (s *pgBackend) CreateMailbox(ctx context.Context, b *Mailbox) error {
	if err := b.writable(); err != nil {
		return refused(err)
	}
	n, err := s.exec(ctx, `INSERT INTO mailboxes (addr, identity, created, statement, statement_sig, rank, signer, senders, retired, acl, account, expires_at, rev)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (addr) DO NOTHING`,
		b.Addr[:], b.Identity, msTime(b.Created), b.Statement, b.Signature, numeric(b.Rank), b.Signer[:], sendersColumn(b), retiredColumn(b), aclColumn(b), accountColumn(b), expiresColumn(b), toInt(b.Rev))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrExists // it has a record, whoever wrote it
	}
	return nil
}

// UpdateMailbox implements Backend: every column that can change, if the
// record is still at b.Rev. The ACL is only set: no route removes one.
func (s *pgBackend) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	if err := b.writable(); err != nil {
		return refused(err)
	}
	n, err := s.exec(ctx, `UPDATE mailboxes SET statement = $2, statement_sig = $3, rank = $4, signer = $5, senders = $6, retired = $7,
		acl = COALESCE($8, acl), expires_at = $9, rev = rev + 1
		WHERE addr = $1 AND rev = $10`,
		b.Addr[:], b.Statement, b.Signature, numeric(b.Rank), b.Signer[:], sendersColumn(b), retiredColumn(b), aclColumn(b), expiresColumn(b), toInt(b.Rev))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrStale
	}
	return nil
}

// DeleteMailbox implements Backend.
func (s *pgBackend) DeleteMailbox(ctx context.Context, a protocol.Address) error {
	_, err := s.exec(ctx, `DELETE FROM mailboxes WHERE addr = $1`, a[:])
	return err
}

// Revoke implements Backend: one statement on the address's revocations row,
// which keeps the revocation of the address once, whatever is beside it
// (PROTOCOL.md §11.15), takes a revocation of certificates only through a
// higher serial than the one it holds, is ErrStale where it brings neither,
// and, where want asks it, writes only where the row exists, or only where
// it does not.
func (s *pgBackend) Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, error) {
	var addrRev, certs, certsSig []byte
	if len(rv.Address) > 0 {
		addrRev = rv.Address
	}
	through := pgtype.Numeric{}
	if rv.Through > 0 {
		certs, certsSig, through = rv.Certs, rv.CertsSig, numeric(rv.Through)
	}
	// higher guards the certificates' columns alone; the row is written
	// where the write brings a revocation of the address or a higher one.
	const higher = `($6::numeric IS NOT NULL AND (revocations.through IS NULL OR revocations.through < $6::numeric))`
	const set = `revocation = COALESCE(revocations.revocation, $3),
		revoked_certs = CASE WHEN ` + higher + ` THEN $4 ELSE revocations.revoked_certs END,
		revoked_certs_sig = CASE WHEN ` + higher + ` THEN $5 ELSE revocations.revoked_certs_sig END,
		through = CASE WHEN ` + higher + ` THEN $6::numeric ELSE revocations.through END`
	const brings = `($3::bytea IS NOT NULL OR ` + higher + `)`
	var q string
	switch want {
	case ExpectNone:
		q = `INSERT INTO revocations (` + revocationCols + `) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (addr) DO NOTHING RETURNING ` + revocationCols
	case ExpectHeld:
		// $2, the identity, is the row's already: named so that every
		// statement takes the same six arguments.
		q = `UPDATE revocations SET ` + set + ` WHERE addr = $1 AND $2::bytea IS NOT NULL AND ` + brings + ` RETURNING ` + revocationCols
	default:
		q = `INSERT INTO revocations (` + revocationCols + `) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (addr) DO UPDATE SET ` + set + ` WHERE ` + brings + ` RETURNING ` + revocationCols
	}
	var got row
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := rowsOf(tx.Query(ctx, q, a[:], rv.Identity, addrRev, certs, certsSig, through))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrStale // it brings nothing the row lacks, or the row is not what want asks
		}
		got = rows[0]
		return nil
	})
	if err != nil {
		return nil, err
	}
	held, err := decodeRevocations(got)
	if err != nil {
		return nil, unknown(fmt.Errorf("applied, and its answer does not read: %w", err))
	}
	return held, nil
}

// Messages.

// decodeHeader reads a message's row: its id, size and received_at.
func decodeHeader(r row) (*Header, error) {
	id, err := r.hash("id")
	if err != nil {
		return nil, err
	}
	recv, err := r.time("received_at")
	if err != nil {
		return nil, err
	}
	size, err := r.size("size")
	if err != nil {
		return nil, err
	}
	return header(id, size, ms(recv))
}

// header is a message's header from its id, its size and when it was
// received, in ms (fromMs).
func header(id [32]byte, size int, recv uint64) (*Header, error) {
	received, err := fromMs(recv)
	if err != nil {
		return nil, err
	}
	expires, err := fromMs(recv + ttlMs)
	if err != nil {
		return nil, err
	}
	return &Header{ID: id, Size: size, ReceivedAt: received, ExpiresAt: expires}, nil
}

// getMsg reads a live message's row, and its body's key; ErrNotFound if
// there is none or it has expired.
func (s *pgBackend) getMsg(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, string, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := rowsOf(s.pool.Query(ctx, `SELECT id, size, received_at, nonce FROM messages WHERE box = $1 AND id = $2 AND received_at >= $3`, mailbox[:], id[:], s.liveFrom()))
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", ErrNotFound // the sweep deletes an expired one later
	}
	return msgOf(mailbox, rows[0])
}

// msgOf reads a message's row: its header, and its body's key.
func msgOf(mailbox protocol.Address, r row) (*Header, string, error) {
	h, err := decodeHeader(r)
	if err != nil {
		return nil, "", err
	}
	nonce, err := r.bytes("nonce")
	if err != nil {
		return nil, "", err
	}
	return h, bodyKey(mailbox, h.ID, ms(h.ReceivedAt), nonce), nil
}

// Dedupe implements Backend: the live message's row. A miss a send makes
// at once is caught by PutMessage's conditional write.
func (s *pgBackend) Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error) {
	h, _, err := s.getMsg(ctx, mailbox, id)
	return h, err
}

// ReadLive implements Backend: the mailbox's live messages, oldest first.
func (s *pgBackend) ReadLive(ctx context.Context, mailbox protocol.Address) ([]Header, error) {
	return s.list(ctx, mailbox, nil, 0)
}

// List implements Backend: a page of the mailbox's live messages, oldest
// first by (received_at, id), after the cursor. Every read is consistent.
func (s *pgBackend) List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, _ bool) ([]Header, error) {
	return s.list(ctx, mailbox, after, limit)
}

func (s *pgBackend) list(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int) ([]Header, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	q := `SELECT id, size, received_at FROM messages WHERE box = $1 AND received_at >= $2`
	args := []any{mailbox[:], s.liveFrom()}
	if after != nil {
		q += ` AND (received_at, id) > ($3, $4)`
		args = append(args, msTime(after.ReceivedAt), after.ID[:])
	}
	q += ` ORDER BY received_at, id`
	if limit > 0 {
		args = append(args, limit)
		q += ` LIMIT $` + strconv.Itoa(len(args))
	}
	rows, err := rowsOf(s.pool.Query(ctx, q, args...))
	if err != nil {
		return nil, err
	}
	hs := make([]Header, 0, len(rows))
	for _, r := range rows {
		h, err := decodeHeader(r)
		if err != nil {
			return nil, err
		}
		hs = append(hs, *h)
	}
	return hs, nil
}

// PutMessage implements Backend (ARCHITECTURE.md § Storage): the body, then
// the row, if no live one has this id. A crash after the body leaves an
// orphan, collected by age. A body that fails stores nothing
// (errNotStored). A live row met instead, an expired one aside, which the
// write replaces, is a duplicate, whose header is handed back; the body just
// put, under a key of this send's own, is deleted.
func (s *pgBackend) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) error {
	recv := ms(h.ReceivedAt)
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce) // never fails
	key := bodyKey(mailbox, h.ID, recv, nonce)
	at := time.UnixMilli(toInt(recv)).UTC()
	bctx, cancel := bounded(ctx)
	err := s.bodies.Put(bctx, key, body)
	cancel()
	if err != nil {
		return fmt.Errorf("%w: %w", errNotStored, err)
	}
	if err := s.crashed("put: after the body"); err != nil {
		return err
	}
	var met row
	err = s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := rowsOf(tx.Query(ctx, `INSERT INTO messages (box, id, size, received_at, nonce) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (box, id) DO UPDATE SET size = EXCLUDED.size, received_at = EXCLUDED.received_at, nonce = EXCLUDED.nonce
			WHERE messages.received_at < $6
			RETURNING received_at`,
			mailbox[:], h.ID[:], h.Size, at, nonce, s.liveFrom()))
		if err != nil || len(rows) > 0 {
			return err
		}
		// The row met is locked by the statement, so it is read as it is.
		rows, err = rowsOf(tx.Query(ctx, `SELECT id, size, received_at, nonce FROM messages WHERE box = $1 AND id = $2`, mailbox[:], h.ID[:]))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return unknown(errors.New("the row its insert met is gone"))
		}
		met = rows[0]
		return nil
	})
	if err != nil || met == nil {
		return err
	}
	orig, _, err := msgOf(mailbox, met)
	if err != nil {
		return unknown(fmt.Errorf("the row its insert met does not read: %w", err))
	}
	dctx, cancel := bounded(ctx)
	defer cancel()
	if err := s.bodies.Delete(dctx, key); err != nil {
		s.logf("a duplicate send's body was left to be collected: %v", err)
	}
	return duplicate{orig}
}

// Retire implements Backend: the row is deleted, if it is live and, where
// received is not zero, the one received then, and nothing of the message is
// kept but a body, collected by age.
func (s *pgBackend) Retire(ctx context.Context, mailbox protocol.Address, id [32]byte, received time.Time) (time.Time, error) {
	_, recv, err := s.retire(ctx, mailbox, id, received)
	return recv, err
}

func (s *pgBackend) retire(ctx context.Context, mailbox protocol.Address, id [32]byte, received time.Time) (string, time.Time, error) {
	var at *time.Time
	if !received.IsZero() {
		t := msTime(received)
		at = &t
	}
	var got row
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := rowsOf(tx.Query(ctx, `DELETE FROM messages WHERE box = $1 AND id = $2 AND received_at >= $3
			AND ($4::timestamptz IS NULL OR received_at = $4) RETURNING id, size, received_at, nonce`, mailbox[:], id[:], s.liveFrom(), at))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrNotFound
		}
		got = rows[0]
		return nil
	})
	if err != nil {
		return "", time.Time{}, err
	}
	h, key, err := msgOf(mailbox, got)
	if err != nil {
		return "", time.Time{}, unknown(fmt.Errorf("applied, and its answer does not read: %w", err))
	}
	return key, h.ReceivedAt, nil
}

// DeleteMessage implements Backend (ack): the row, then the body. A body
// not deleted is left to be collected.
func (s *pgBackend) DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) (time.Time, error) {
	key, recv, err := s.retire(ctx, mailbox, id, time.Time{})
	if err != nil {
		return recv, err
	}
	if err := s.crashed("ack: after the row"); err != nil {
		return recv, nil // the body is left, as a crash would leave it
	}
	dctx, cancel := bounded(ctx)
	defer cancel()
	if err := s.bodies.Delete(dctx, key); err != nil {
		s.logf("an acked message's body was left to be collected: %v", err)
	}
	return recv, nil
}

// Message implements Backend. A live message whose body is gone is
// errNoBody, with its header, whose received_at its retire names.
func (s *pgBackend) Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error) {
	h, key, err := s.getMsg(ctx, mailbox, id)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	body, err := s.bodies.Get(ctx, key, from, h.Size)
	if errors.Is(err, errNoBody) {
		return h, nil, err
	}
	if err != nil {
		return nil, nil, err
	}
	return h, body, nil
}

// DeleteAll implements Backend: every live message of the mailbox, as acks
// are, its rows in one statement, then their bodies. A message stored
// before it is in it.
func (s *pgBackend) DeleteAll(ctx context.Context, mailbox protocol.Address, retired func([32]byte, time.Time)) error {
	var got []row
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := rowsOf(tx.Query(ctx, `DELETE FROM messages WHERE box = $1 AND received_at >= $2 RETURNING id, size, received_at, nonce`, mailbox[:], s.liveFrom()))
		got = rows
		return err
	})
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(got))
	var bad error
	for _, r := range got {
		h, key, err := msgOf(mailbox, r)
		if err != nil {
			bad = err
			continue
		}
		retired(h.ID, h.ReceivedAt)
		keys = append(keys, key)
	}
	dctx, cancel := bounded(ctx)
	defer cancel()
	if err := s.bodies.Delete(dctx, keys...); err != nil {
		s.logf("a mailbox's deleted messages' bodies were left to be collected: %v", err)
	}
	if bad != nil {
		return unknown(fmt.Errorf("applied, and a row of its answer does not read: %w", bad))
	}
	return nil
}

// Accounts and adopt keys.

func decodeAccount(r row) (*Account, error) {
	id, err := r.str("id")
	if err != nil {
		return nil, err
	}
	rev, err := r.uint("rev")
	if err != nil {
		return nil, err
	}
	u, err := r.boolean("unmetered")
	if err != nil {
		return nil, err
	}
	return &Account{ID: id, Unmetered: u, Rev: rev}, nil
}

// Account implements Backend.
func (s *pgBackend) Account(ctx context.Context, id string) (*Account, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := rowsOf(s.pool.Query(ctx, `SELECT id, unmetered, rev FROM accounts WHERE id = $1`, id))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return decodeAccount(rows[0])
}

// CreateAccount implements Backend.
func (s *pgBackend) CreateAccount(ctx context.Context, a *Account) error {
	n, err := s.exec(ctx, `INSERT INTO accounts (id, unmetered, rev) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, a.ID, a.Unmetered, toInt(a.Rev))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrExists
	}
	return nil
}

// PutAdoptKey implements Backend.
func (s *pgBackend) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	n, err := s.exec(ctx, `INSERT INTO adopt_keys (account, hash, uses, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (account, hash) DO NOTHING`,
		k.Account, k.Hash[:], k.Uses, msTime(k.Expires))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrExists
	}
	return nil
}

// AdoptKey implements Backend.
func (s *pgBackend) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	rows, err := rowsOf(s.pool.Query(ctx, `SELECT uses, expires_at FROM adopt_keys WHERE account = $1 AND hash = $2`, account, hash[:]))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	uses, err := rows[0].count("uses")
	if err != nil {
		return nil, err
	}
	exp, err := rows[0].time("expires_at")
	if err != nil {
		return nil, err
	}
	return &AdoptKey{Account: account, Hash: hash, Uses: uses, Expires: exp}, nil
}

// Adopt implements Backend: the mailbox's record moved into the account, at
// b.Rev, and a use of the adopt key spent, in one transaction.
func (s *pgBackend) Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE mailboxes SET account = $2, rev = rev + 1 WHERE addr = $1 AND rev = $3`, b.Addr[:], account, toInt(b.Rev))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrStale
		}
		tag, err = tx.Exec(ctx, `UPDATE adopt_keys SET uses = uses - 1 WHERE account = $1 AND hash = $2 AND uses >= 1 AND expires_at > $3`, account, key[:], msTime(s.now()))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrKeyRefused
		}
		return nil
	})
}

// Leave implements Backend.
func (s *pgBackend) Leave(ctx context.Context, b *Mailbox) error {
	n, err := s.exec(ctx, `UPDATE mailboxes SET account = NULL, rev = rev + 1 WHERE addr = $1 AND rev = $2`, b.Addr[:], toInt(b.Rev))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrStale
	}
	return nil
}
