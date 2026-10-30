package server

import (
	"context"
	"errors"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Backend is what a store keeps durably, and the change feed of it: the
// durable operations only. Memory, the one Store, holds over it what a poll
// needs, and applies to that what each write and each change did
// (ARCHITECTURE.md § Storage). A backend maps its storage to these
// operations and their three outcomes, and nothing else: dynamoBackend
// (DynamoDB and S3 Express) and memBackend (maps in this process).
//
// Each write has exactly one of three outcomes, read in one place
// (Memory.write):
//   - applied: it returns nil (and what it returns beside);
//   - refused, as the store stated, of a write it did not make: ErrExists,
//     ErrStale, ErrNotFound, ErrKeyRefused, a send's body not stored
//     (errNotStored), a send that met another's item (duplicate, with that
//     item's header), or errRefused (refused);
//   - unknown, which may have applied: ErrUnknown, wrapping its cause. Any
//     other error is taken as unknown too.
//
// A write of several steps is one operation, whose outcome is its item's
// write: a send writes its body, then its item; an ack deletes its body,
// then its item; DeleteAll finds a mailbox's messages, deletes their bodies,
// then each item, and hands each it took to retired as it lands. A step that fails before the item's write is
// a refusal: it changed nothing a reader of the list sees.
type Backend interface {
	// ReadAddress reads what is held of address a, strongly consistent:
	// its mailbox's record and its identity's revocations, each nil if absent.
	ReadAddress(ctx context.Context, a protocol.Address) (*Mailbox, *Revocations, error)
	// ReadLive reads a mailbox's live messages, strongly consistent: what a
	// mailbox's load counts (Memory.readMailbox).
	ReadLive(ctx context.Context, mailbox protocol.Address) ([]Header, error)
	// List returns up to limit live headers, oldest first by (ReceivedAt,
	// ID), after the given key (nil: from the start); strongly consistent
	// where consistent is set.
	List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error)
	// Message returns a live message and its body, from byte from on where
	// from is inside it, above 0 and below its Size, and otherwise whole; or
	// ErrNotFound; or errNoBody for a live item whose body is gone.
	Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error)
	// Dedupe returns the header of the live message mailbox holds with this
	// id, or ErrNotFound.
	Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error)
	// Account reads an account's record, strongly consistent, or returns
	// ErrNotFound.
	Account(ctx context.Context, id string) (*Account, error)
	// AdoptKey reads an adopt key's state, strongly consistent, or returns
	// ErrNotFound.
	AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error)

	// CreateMailbox stores b's record, at b.Rev, if the address has none;
	// otherwise ErrExists.
	CreateMailbox(ctx context.Context, b *Mailbox) error
	// UpdateMailbox stores b's record at b.Rev+1 if the stored one is at b.Rev;
	// otherwise ErrStale. It writes nothing of the revocations, and leaves b
	// as it is.
	UpdateMailbox(ctx context.Context, b *Mailbox) error
	// DeleteMailbox deletes a's record, and keeps its revocations.
	DeleteMailbox(ctx context.Context, a protocol.Address) error
	// Revoke keeps what the identity of address a revoked (Store.Revoke),
	// and returns the address's revocations as they now are; ErrStale if a
	// revocation of certificates through as high a serial was stored first,
	// or if the address's revocations item is not what want asks: there, or
	// not. The item exists only holding a revocation, since none is written
	// that holds neither, so that is whether any is held.
	Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) (*Revocations, error)
	// Adopt moves mailbox b, at b.Rev, into account, spending a use of the
	// account's adopt key whose hash is key, in one write: ErrStale,
	// ErrKeyRefused.
	Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error
	// Leave takes mailbox b, at b.Rev, out of its account, or returns ErrStale.
	Leave(ctx context.Context, b *Mailbox) error
	// CreateAccount stores a new account at a.Rev, or returns ErrExists.
	CreateAccount(ctx context.Context, a *Account) error
	// PutAdoptKey stores a new adopt key's state, or returns ErrExists.
	PutAdoptKey(ctx context.Context, k *AdoptKey) error
	// PutMessage stores a message: its body, then its item. A live item of
	// another send of the id refuses it (duplicate).
	PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) error
	// Retire deletes a live message's item, so it leaves the list and
	// nothing of it is kept, and returns when it was received; ErrNotFound
	// if it is not live.
	Retire(ctx context.Context, mailbox protocol.Address, id [32]byte) (time.Time, error)
	// DeleteMessage acks a message: its body goes, then it is retired.
	DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) (time.Time, error)
	// DeleteAll deletes, as acks do, every live message in a mailbox, and hands
	// each retired as its item is deleted. A message already gone is no
	// error.
	DeleteAll(ctx context.Context, mailbox protocol.Address, retired func(id [32]byte, received time.Time)) error

	// Start hands every change to what the backend keeps, from then on, to
	// apply: in order for each item, and at least once. It returns once the
	// feed is followed, and the feed ends with ctx.
	Start(ctx context.Context, apply func(Change)) error
	// Ready reports whether the feed is followed.
	Ready() bool
}

// errNoBody is a live message's item whose body is gone: a half-finished
// ack, or a body the lifecycle rule took early. Memory retires it.
var errNoBody = errors.New("the message's body is gone")

// ChangeKind is what a Change is a change to.
type ChangeKind int

// The kinds of change, each with one rule in Memory.apply.
const (
	// RecordChange is a mailbox's record.
	RecordChange ChangeKind = iota + 1
	// RevocationsChange is an address's revocations.
	RevocationsChange
	// MessageChange is a message's item.
	MessageChange
	// AccountChange is an account's record.
	AccountChange
	numChangeKinds = int(AccountChange)
)

// Change is one change to what a backend keeps, as its feed hands it over:
// what the item now holds, decoded by the backend, or that it is gone. An
// item that does not read is carried with Err, and applied as one gone,
// whatever its kind: memory then holds nothing of it, and its next use
// reads it again (dromas-dev/dromas-client#407 item 1).
type Change struct {
	Kind ChangeKind
	// Addr is the record's address, the revocations', or the message's mailbox.
	Addr protocol.Address
	// AccountID is the account's id.
	AccountID string
	// Gone is an item deleted.
	Gone bool
	// Err is an item whose image does not read.
	Err error

	Mailbox     *Mailbox     // RecordChange
	Revocations *Revocations // RevocationsChange
	Header      *Header      // MessageChange: of an item deleted, its ID alone
	Live        bool         // MessageChange: in the list
	Account     *Account     // AccountChange
}
