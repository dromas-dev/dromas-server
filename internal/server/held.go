package server

import (
	"context"
	"fmt"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A call's checks read memory, which from the second process on can be
// behind the database: another process's renewal, revocation or ACL reaches
// this one only by the feed (ARCHITECTURE.md § Following the feed). So what
// a check relied on travels with the call's context to the backend, which
// holds its statement to it: a read or write whose standing changed since
// its check reads and changes nothing, and is refused as ErrStale. Memory
// takes that as its copy of the address being behind and forgets it
// (Memory.write), and the caller checks again or answers concurrent_modification.
// Under READ COMMITTED every statement sees each commit answered before it
// began (PostgreSQL's docs, Transaction Isolation, read 2026-11-08), so a
// call that starts after another's answer is held to it.

// passBy is the pass a call was taken under (checkPassBy), a mailbox's own
// call's or a send's sender's: the identity's, taken while the address is not revoked and the mailbox
// has a record, or the signer's whose key's hash is signer, taken while it
// is the record's signer and no revocation of certificates covers it.
type passBy struct {
	addr     protocol.Address
	identity bool
	signer   [32]byte
}

// sendHeld is what a send's write is held to: the recipient's record as its
// checks read it, by its version, which every write of the record raises, a
// revocation of the address's included (Backend.Revoke); and the sender's
// pass.
type sendHeld struct {
	rcpt    protocol.Address
	created time.Time
	rev     uint64
	from    passBy
}

type (
	passKey struct{}
	sendKey struct{}
)

// withPass is ctx carrying the pass a call was taken under: the backend
// holds a mailbox's reads of its messages and writes of its record to it,
// and a send's dedupe to its sender's (passOf).
func withPass(ctx context.Context, p passBy) context.Context {
	return context.WithValue(ctx, passKey{}, p)
}

// passOf is the pass ctx's call was taken under, if it carries one.
func passOf(ctx context.Context) (passBy, bool) {
	p, ok := ctx.Value(passKey{}).(passBy)
	return p, ok
}

// withSend is ctx carrying what a send's write is held to (sendOf): read by
// PutMessage alone, so a send's other calls, its delete after a revocation
// among them, are held to nothing.
func withSend(ctx context.Context, h sendHeld) context.Context {
	return context.WithValue(ctx, sendKey{}, h)
}

// sendOf is what ctx's send is held to, if it carries it.
func sendOf(ctx context.Context) (sendHeld, bool) {
	h, ok := ctx.Value(sendKey{}).(sendHeld)
	return h, ok
}

// passHeldSQL is the condition that holds a statement to pass p, its
// arguments numbered from n.
func passHeldSQL(p passBy, n int) (string, []any) {
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM mailboxes hm WHERE hm.addr = $%[1]d::bytea AND ($%[2]d::boolean OR hm.signer = $%[3]d::bytea)
		AND NOT EXISTS (SELECT 1 FROM revocations hr WHERE hr.addr = $%[1]d::bytea AND (hr.revocation IS NOT NULL OR (NOT $%[2]d::boolean AND hr.through >= hm.rank))))`, n, n+1, n+2),
		[]any{p.addr[:], p.identity, p.signer[:]}
}

// sendHeldSQL is the condition that holds a send's write to h, its arguments
// numbered from n.
func sendHeldSQL(h sendHeld, n int) (string, []any) {
	from, args := passHeldSQL(h.from, n+3)
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM mailboxes hr WHERE hr.addr = $%d::bytea AND hr.created = $%d::timestamptz AND hr.rev = $%d::bigint) AND `, n, n+1, n+2) + from,
		append([]any{h.rcpt[:], msTime(h.created), toInt(h.rev)}, args...)
}

// passHeldBy reports whether what memBackend keeps holds pass p, as
// passHeldSQL does in the database. The caller holds mu.
func (s *memBackend) passHeldBy(p passBy) bool {
	rec := s.mailboxes[p.addr]
	if rec == nil || !p.identity && rec.Signer != p.signer {
		return false
	}
	rv := s.revocations[p.addr]
	return rv == nil || len(rv.Address) == 0 && (p.identity || rv.Through == 0 || rv.Through < rec.Rank)
}

// held reports whether what memBackend keeps holds ctx's pass, where it
// carries one. The caller holds mu.
func (s *memBackend) held(ctx context.Context) bool {
	p, ok := passOf(ctx)
	return !ok || s.passHeldBy(p)
}
