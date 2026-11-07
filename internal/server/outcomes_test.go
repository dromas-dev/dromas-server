package server

// What a write the backend answered with an error is taken to have done:
// applied, or possibly so, and the count reserved for it is kept; or
// refused, as the store stated, and the count is given back (LIMITS.md rule
// 4; dromas-dev/dromas-server#14, #89, #90). The injector (faults,
// shared_test.go) makes each outcome of a write; what memory makes of each,
// for every write of the Backend, is TestEveryWriteOfTheBackendReachesMemory
// ByItsOutcome's.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// unsent is an error that states whether pgx sent nothing of its statement
// (pgconn.SafeToRetry).
type unsent bool

func (unsent) Error() string       { return "a statement's error" }
func (u unsent) SafeToRetry() bool { return bool(u) }

// What PostgreSQL answered a write is read as one of the three outcomes
// (pgOutcome): an ERROR of the database's own is a statement it rolled
// back, so a refusal stated, and so is a write pgx never sent, one whose
// connection was never made among them; a FATAL or a PANIC, which can follow
// a commit, an ERROR that ends the connection, an answer lost, a context
// that ended mid-statement, or any other error leaves open whether the write
// was applied. On PostgreSQL, also a statement it refused and one whose
// context ended while it ran.
func TestWhatPostgreSQLAnsweredAWriteIsOneOutcome(t *testing.T) {
	t.Parallel()
	type outcome struct {
		name    string
		err     error
		refused bool
	}
	cases := []outcome{
		{"an ERROR of the database's own", &pgconn.PgError{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: "23505"}, true},
		{"one wrapped", fmt.Errorf("the insert: %w", &pgconn.PgError{Severity: "ERROR", Code: "40001"}), true},
		{"an ERROR in another language", &pgconn.PgError{Severity: "FEHLER", SeverityUnlocalized: "ERROR", Code: "23505"}, true},
		{"a FATAL, which may follow a commit", &pgconn.PgError{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: "XX000"}, false},
		{"a PANIC: a commit that could not abort", &pgconn.PgError{Severity: "PANIC", SeverityUnlocalized: "PANIC", Code: "XX000"}, false},
		{"an ERROR that ends the connection", &pgconn.PgError{Severity: "ERROR", Code: "57P01"}, false},
		{"an ERROR of the connection", &pgconn.PgError{Severity: "ERROR", Code: "08006"}, false},
		{"a write pgx never sent", unsent(true), true},
		{"control: an error pgx may have sent", unsent(false), false},
		{"a context that ended mid-statement", context.DeadlineExceeded, false},
		{"an answer lost", io.ErrUnexpectedEOF, false},
		{"an error of no kind", errInjected, false},
	}
	closed, err := pgxpool.New(t.Context(), "postgres://dromas@127.0.0.1:1/dromas?sslmode=disable&connect_timeout=5")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closed.Close)
	_, err = closed.Exec(t.Context(), `DELETE FROM mailboxes`)
	cases = append(cases, outcome{"a call to a port where no database listens", err, true})
	if onPostgres() {
		pool := startPostgres(t, time.Now).pool()
		_, err := pool.Exec(t.Context(), `SELECT 1/0`)
		cases = append(cases, outcome{"a statement PostgreSQL refused", err, true})
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		_, err = pool.Exec(ctx, `SELECT pg_sleep(5)`)
		cases = append(cases, outcome{"a statement whose context ended while it ran", err, false})
	}
	if got := pgOutcome(nil); got != nil {
		t.Errorf("applied: %v", got)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pgOutcome(c.err)
			t.Logf("%v: refused %v, mayHaveApplied %v", c.err, isRefusal(got), mayHaveApplied(got))
			if c.err == nil || isRefusal(got) != c.refused || mayHaveApplied(got) == c.refused || !errors.Is(got, c.err) {
				t.Errorf("%v is read as %v: refused %v, mayHaveApplied %v; want refused %v", c.err, got, isRefusal(got), mayHaveApplied(got), c.refused)
			}
		})
	}
}

// injected is a test server whose store has the injector between it and its
// backend.
func injected(t *testing.T, l Limits) (*env, *faults) {
	t.Helper()
	var f *faults
	e := newEnv(t, l, func(c *Config) { f = injectFaults(c.Store.(*Memory)) })
	return e, f
}

// A send's write that meets a live row of the same id, received in the same
// millisecond or at another time, is another send's: a duplicate, whose
// header is handed back, and memory holds one mark of the message
// (pgBackend.PutMessage). Every send's row is its own, by its nonce.
func TestAPutThatMeetsALiveRowIsADuplicate(t *testing.T) {
	t.Parallel()
	if !onPostgres() {
		t.Skip("needs PostgreSQL: DROMAS_TEST_POSTGRES")
	}
	s := startPostgres(t, time.Now)
	ctx := t.Context()
	for _, c := range []struct {
		name   string
		later  time.Duration // the second write's time, after the first's
		stored bool
	}{
		{"the same millisecond", 0, false},
		{"a second later", time.Second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			to := protocol.Address{0x0e, byte(c.later / time.Second)}
			if _, err := s.Count(ctx, to); err != nil { // loaded, so its marks are counted
				t.Fatal(err)
			}
			now := s.now().UTC().Truncate(time.Millisecond)
			first := &Header{ID: [32]byte{9}, Size: 10, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
			if orig, err := s.PutMessage(ctx, to, first, []byte("0123456789")); err != nil || orig != nil {
				t.Fatalf("the first write: %v, %v", orig, err)
			}
			second := *first
			second.ReceivedAt, second.ExpiresAt = now.Add(c.later), first.ExpiresAt.Add(c.later)
			orig, err := s.PutMessage(ctx, to, &second, []byte("0123456789"))
			marks := s.idx.count(to, s.nowMs())
			t.Logf("the second write: orig %v, err %v; marks in memory %d", orig, err, marks)
			if err != nil || (orig == nil) != c.stored || marks != 1 || orig != nil && !orig.ReceivedAt.Equal(first.ReceivedAt) {
				t.Errorf("answered as orig %v, err %v, with %d marks in memory; want stored %v, one mark", orig, err, marks, c.stored)
			}
		})
	}
}

// s3Answering is an S3 that answers every call with status and an error of
// code, its retries included.
func s3Answering(t *testing.T, status int, code string) s3Bodies {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}))
	t.Cleanup(srv.Close)
	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDFAKE", "fake", ""),
		BaseEndpoint: aws.String(srv.URL),
		Retryer:      func() aws.Retryer { return retry.AddWithMaxBackoffDelay(retry.NewStandard(), time.Millisecond) },
	}
	return s3Bodies{newS3(cfg, func(o *s3.Options) { o.UsePathStyle = true }), "bodies"}
}

// A send whose body's PUT failed, whatever S3 answered, wrote no row: it is
// a refusal the store states, nothing is stored and its count is given back
// (errNotStored; dromas-dev/dromas-server#90). Its body is written before
// any statement, so the store's database is never reached.
func TestASendWhoseBodyWasNotStoredGivesTheCountBack(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		status int
		code   string
	}{
		{http.StatusForbidden, "AccessDenied"},
		{http.StatusInternalServerError, "InternalError"},
		{http.StatusServiceUnavailable, "SlowDown"},
	} {
		t.Run(fmt.Sprintf("%d %s", c.status, c.code), func(t *testing.T) {
			s := newMemory(time.Now, 16, nil, nil)
			s.backend = &pgBackend{bodies: s3Answering(t, c.status, c.code), now: s.clock}
			now := s.now().UTC().Truncate(time.Millisecond)
			h := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
			orig, err := s.PutMessage(context.WithoutCancel(t.Context()), protocol.Address{4}, h, []byte("abc"))
			t.Logf("orig %v; err %v; refused %v, mayHaveApplied %v", orig, err, isRefusal(err), mayHaveApplied(err))
			if !errors.Is(err, errNotStored) || !isRefusal(err) || mayHaveApplied(err) || orig != nil {
				t.Errorf("a send whose body was never stored: %v, refused %v, mayHaveApplied %v; want errNotStored, a refusal", err, isRefusal(err), mayHaveApplied(err))
			}
		})
	}
}

// failingDeletes is bodies whose deletes all fail.
type failingDeletes struct{ bodies }

func (failingDeletes) Delete(context.Context, ...string) error {
	return errors.New("injected: the bodies' delete failed")
}

// An ack deletes its message's row, then its body: one whose body's delete
// failed is applied all the same, the message gone from the table and from
// memory, its body left to be collected by age (pgBackend.DeleteMessage).
func TestAnAckWhoseBodyWasNotDeletedIsApplied(t *testing.T) {
	t.Parallel()
	e, s := sharedEnv(t)
	from, to := e.mailbox(), e.mailbox()
	id := e.sent(e.do("POST", "/v1/"+to.Address().String()+"/messages", e.sealTo(to), e.pass(from)))
	s.pg().bodies = failingDeletes{s.pg().bodies}
	got := e.do("DELETE", "/v1/"+to.Address().String()+"/messages/"+id, nil, e.pass(to))
	var mid [32]byte
	copy(mid[:], mustHex(t, id))
	n, err := s.Count(t.Context(), to.Address())
	if err != nil {
		t.Fatal(err)
	}
	row := s.storedMsg(t, to.Address(), mid)
	t.Logf("the ack: %d %s; the mailbox holds %d in memory; its row kept %v", got.status, got.code(), n, row != nil)
	if got.status != http.StatusNoContent || n != 0 || row != nil {
		t.Errorf("an ack whose body was not deleted: %d %s, %d messages in memory, its row kept %v; want 204, none, gone", got.status, got.code(), n, row != nil)
	}
}

// A renewal whose write may have been applied, the backend's answer lost
// before it or after it, is counted: with one renewal a day, the next is
// refused (dromas-dev/dromas-server#89). The control: a renewal the backend
// refused, its count given back.
func TestARenewalTheStoreMayHaveAppliedIsCounted(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fault   fault
		refusal error
		counted bool
	}{
		{unknownAfter, nil, true},
		{unknownBefore, nil, true},
		{refusedBefore, errStated, false},
	} {
		t.Run(c.fault.String(), func(t *testing.T) {
			l := relaxed()
			l.RenewalsPerDay, l.RenewalsBurst = 1, 1
			e, f := injected(t, l)
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			r.prekeyUnder(r.by[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			f.set("UpdateMailbox", c.fault)
			f.refuse["UpdateMailbox"] = c.refusal
			first := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1))
			f.set("UpdateMailbox", asIs)
			b, err := e.store.Mailbox(t.Context(), r.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			r.prekeyUnder(r.by[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			next := e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1))
			t.Logf("renewal %d %s, the mailbox at prekey %d; next renewal %d %s", first.status, first.code(), b.Prekey.Serial, next.status, next.code())
			if first.status != http.StatusServiceUnavailable {
				t.Errorf("a renewal whose write failed: %d %s, want 503", first.status, first.code())
			}
			if (next.status == http.StatusTooManyRequests) != c.counted {
				t.Errorf("the next renewal is %d %s: want the first counted %v", next.status, next.code(), c.counted)
			}
		})
	}
}

// A raise of a revocation of certificates whose write was applied, and its
// answer lost, leaves memory holding nothing of the address, the index as
// the cache (Memory.write): the next call with a pass under the revoked
// certificate is refused at once, from the record read again, and never
// taken on the standing from before the write (dromas-dev/dromas-server#89).
// The control: a raise the backend refused leaves the index standing, and
// the same pass is taken.
func TestARevocationWhoseAnswerWasLostIsInTheNextPassCheck(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fault   fault
		refusal error
		status  int
		code    protocol.Code
	}{
		{unknownAfter, nil, http.StatusUnauthorized, protocol.CodeCertificateRevoked},
		{refusedBefore, errStated, http.StatusOK, ""},
	} {
		t.Run(c.fault.String(), func(t *testing.T) {
			e, f := injected(t, relaxed())
			s := e.store.(*Memory)
			r := e.raw()
			n := r.registerCertified(protocol.MaxPrekeyLifetime)
			a := r.id.Address()
			e.want(e.do("GET", r.path("/messages"), nil, r.pass(n)), http.StatusOK, "")
			if _, held := s.Held(a); !held {
				t.Fatal("the mailbox is not loaded")
			}
			rv := r.certs(n)
			list, err := protocol.ParseRevokedCertificates(rv.RevokedCertificates)
			if err != nil {
				t.Fatal(err)
			}
			f.set("Revoke", c.fault)
			f.refuse["Revoke"] = c.refusal
			err = s.Revoke(context.WithoutCancel(t.Context()), a, &Revocations{Identity: rv.Identity, Certs: rv.RevokedCertificates, CertsSig: rv.RevokedCertificatesSignature, Through: list.Through}, ExpectAnything)
			_, held := s.Held(a)
			got := e.do("GET", r.path("/messages"), nil, r.pass(n))
			t.Logf("the raise: %v (mayHaveApplied %v); the index holds the mailbox %v; then a pass under certificate %d: %d %s", err, mayHaveApplied(err), held, n, got.status, got.code())
			if got.status != c.status || got.code() != c.code {
				t.Errorf("a pass under certificate %d after the raise: %d %s; want %d %s", n, got.status, got.code(), c.status, c.code)
			}
		})
	}
}

// A Leave whose write may have been applied is answered as any write whose
// outcome is unknown, 503, never 409 mailbox_changed. The control: a Leave
// whose condition failed is 409 (dromas-dev/dromas-server#89).
func TestALeaveTheStoreMayHaveAppliedIsNot409(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fault  fault
		status int
		code   protocol.Code
	}{
		{unknownAfter, http.StatusServiceUnavailable, protocol.CodeUnavailable},
		{refusedBefore, http.StatusConflict, protocol.CodeMailboxChanged},
	} {
		t.Run(c.fault.String(), func(t *testing.T) {
			ctx := t.Context()
			e, f := injected(t, relaxed())
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			acc, key := accountEnv(t, e, false, 1)
			_, hash, _ := parseAdopt(key)
			rec, err := e.store.Mailbox(ctx, r.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			if err := e.store.Adopt(ctx, rec, acc.ID, hash); err != nil {
				t.Fatal(err)
			}
			f.set("Leave", c.fault)
			got := e.do("DELETE", r.path("/account"), nil, r.pass(1))
			t.Logf("the leave: %d %s", got.status, got.code())
			if got.status != c.status || got.code() != c.code {
				t.Errorf("the leave is answered %d %s; want %d %s", got.status, got.code(), c.status, c.code)
			}
		})
	}
}

// A registration whose write was applied, and its answer lost, is answered
// from the record, which it reads as it does after a refusal of its
// condition: with one registration an hour, neither it nor its client's
// retry is 503, then 429 (dromas-dev/dromas-client#411 item 2).
func TestARegistrationWhoseOutcomeIsUnknownIsAnsweredFromTheRecord(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RegistrationsPerHour = 1
	e, f := injected(t, l)
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	f.set("CreateMailbox", unknownAfter)
	first := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
	f.set("CreateMailbox", asIs)
	again := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
	t.Logf("the registration %d %s; its retry %d %s", first.status, first.code(), again.status, again.code())
	if first.status != http.StatusOK || again.status != http.StatusOK {
		t.Errorf("a registration the store applied, its outcome unknown: %d %s, then its retry %d %s; want each answered from the record, 200", first.status, first.code(), again.status, again.code())
	}
}
