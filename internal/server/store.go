package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// State is what a server holds of an address (PROTOCOL.md §11.6). A mailbox's
// record is Active, the one state a record is written in or read back as;
// Revoked and NoMailbox are what the store answers from the address's
// revocations alone.
type State string

// The states.
const (
	// Active is a registered mailbox.
	Active State = "active"
	// Revoked is an address its identity revoked. Its record is deleted,
	// and the revocation is kept for good.
	Revoked State = "revoked"
	// NoMailbox is an address with no mailbox whose identity revoked certificates:
	// a later registration is held above them.
	NoMailbox State = "none"
)

// Mailbox is what a server holds of an address: its mailbox's record, if it has
// one, and what its identity revoked, if anything, which is kept in an item
// of its own (Revocations) with or without a mailbox. A revocation of the
// address is the State whatever the record says.
type Mailbox struct {
	Addr     protocol.Address
	Identity []byte // the identity document, exactly as registered or as the revocations carried it
	State    State
	// The current prekey: its statement, its signer's signature over it,
	// which carries the signing key, and the statement parsed.
	Statement []byte
	Signature []byte
	Prekey    *protocol.Prekey
	// The current statement's signer (PROTOCOL.md §5): its rank, 0 for the
	// identity and a certificate's serial for a working key, and the SHA-256
	// of its signing key's wire bytes, the identity's key or the certificate.
	// A pass is taken only by it, and a prekey only by it or a signer of a
	// higher rank. A mailbox's statements are ordered by this rank first, and
	// by the prekey's own serial second.
	Rank   uint64
	Signer [32]byte
	// SenderKeyTypes is what the mailbox declared with its current prekey: the
	// identity key types of the senders it takes messages from, or
	// protocol.AnySender (PROTOCOL.md §7). Only names this build verifies
	// are kept (declared): a mailbox of any other type cannot send here.
	SenderKeyTypes []string
	// Retired holds the newest retired prekeys (Limits.RetiredKept), each
	// until its not_after: its key may not come back.
	Retired []Retired
	Rev     uint64 // the record's revision, 0 with no record; a write must name the one it read
	Created time.Time
	// Expires is when the record may go: DynamoDB's TTL deletes it some time
	// after (PROTOCOL.md §13). Every registration and renewal raises it to
	// when nothing the mailbox has published is valid any more, and nothing
	// lowers it (keep). Zero: never.
	Expires time.Time
	// Account is the account the mailbox belongs to, or "" (PROTOCOL.md §11.16).
	// Only Adopt and Leave change it.
	Account string
	// What the identity revoked, from the address's revocations item
	// (Revocations): kept for good and served to whoever asks.
	//
	// Revocation is the identity's signature that revoked the address
	// (PROTOCOL.md §10.1): nil unless State is Revoked. With Identity it
	// proves itself, so nobody takes this server's word that the mailbox is
	// revoked.
	Revocation []byte
	// RevokedCerts is the identity's highest revocation of its certificates,
	// exactly as it signed it, and RevokedCertsSig its signature
	// (PROTOCOL.md §10.2): nil until one is published. The address goes on.
	// Served with Identity to whoever asks, it proves itself as Revocation
	// does. It was verified when it was stored, and only one through a higher
	// serial replaces it.
	RevokedCerts    []byte
	RevokedCertsSig []byte
	// ACL is the mailbox's sender ACL (PROTOCOL.md §11.14): who may send to it,
	// deny read first and then allow. nil until the mailbox puts one, and a mailbox
	// with none takes messages from everyone. It is replaced whole, and never
	// removed.
	ACL *protocol.ACL
}

// open reports whether b is a mailbox that takes calls: one registered and not
// revoked. Every other state is answered as no mailbox, but Revoked, which is
// 410.
func (b *Mailbox) open() bool { return b != nil && b.State == Active }

// writable returns an error unless b's state is the one a record holds:
// what the store answers from revocations alone is never written as a
// record.
func (b *Mailbox) writable() error {
	if b.State != Active {
		return fmt.Errorf("a mailbox record is %s, never %s", Active, b.State)
	}
	return nil
}

// hasRecord reports whether b's mailbox has a record, whatever its state.
func (b *Mailbox) hasRecord() bool { return b != nil && b.Rev > 0 }

// holdsRevocations reports whether what is held of an address carries a
// revocation of it or of its certificates: what GET …/revocations answers,
// and the target a PUT there changes (precondition).
func (b *Mailbox) holdsRevocations() bool {
	return b != nil && (len(b.Revocation) > 0 || len(b.RevokedCerts) > 0)
}

// listed reports whether the revocation of certificates on record covers a
// signer of this rank (PROTOCOL.md §5): a certificate at or below it. It
// covers certificates only: the identity, rank 0, is ended only by revoking
// the address. A mailbox with none has revoked none.
func (b *Mailbox) listed(rank uint64) (bool, error) {
	if rank == 0 || len(b.RevokedCerts) == 0 {
		return false, nil
	}
	return listNames(b.RevokedCerts, rank)
}

// Expect is what a conditional write asks of its target as it writes: what a
// request's If-Match or If-None-Match held of the target at its read
// (expected; PROTOCOL.md §11.2), so that a change between the two refuses the
// write, ErrStale, and the request is answered 409 mailbox_changed. It is the
// write's own condition, beside any other it has, and asks nothing of a
// request that carried neither.
type Expect int

const (
	// ExpectAnything asks nothing.
	ExpectAnything Expect = iota
	// ExpectHeld asks that the target exist: an If-Match held.
	ExpectHeld
	// ExpectNone asks that it not: an If-None-Match of "*" held.
	ExpectNone
)

// Revocations is what an address's identity has revoked, as kept in an item
// of its own beside the mailbox's record, mailbox or none (PROTOCOL.md §10.1, §10.2):
// the revocation of the address once, and the highest revocation of its
// certificates. Nothing in it is ever taken away, so two copies merge to the
// larger of each.
type Revocations struct {
	Identity []byte
	// Address is the identity's signature that revoked the address, or nil.
	Address []byte
	// Certs and CertsSig are its highest revocation of its certificates, or
	// nil; Through is the serial it revokes through, 0 with none.
	Certs, CertsSig []byte
	Through         uint64
}

// merge adds what o holds to r: the revocation of the address if r has none,
// and o's revocation of certificates if it reaches higher.
func (r *Revocations) merge(o *Revocations) {
	if o == nil {
		return
	}
	if len(r.Identity) == 0 {
		r.Identity = o.Identity
	}
	if len(r.Address) == 0 {
		r.Address = o.Address
	}
	if o.Through > r.Through {
		r.Certs, r.CertsSig, r.Through = o.Certs, o.CertsSig, o.Through
	}
}

// record is the revocation record of what b holds of its identity's
// revocations, as a client reads one (PROTOCOL.md §10.3): served by
// GET …/revocations, and carried by a 410 revoked (revokedWith).
func (b *Mailbox) record() *protocol.Revocations {
	return &protocol.Revocations{Identity: b.Identity, Revocation: b.Revocation, RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig}
}

// revocations returns what b holds of its identity's revocations, or nil.
func (b *Mailbox) revocations() (*Revocations, error) {
	if len(b.Revocation) == 0 && len(b.RevokedCerts) == 0 {
		return nil, nil
	}
	r := &Revocations{Identity: b.Identity, Address: b.Revocation, Certs: b.RevokedCerts, CertsSig: b.RevokedCertsSig}
	if len(b.RevokedCerts) > 0 {
		c, err := protocol.ParseRevokedCertificates(b.RevokedCerts)
		if err != nil {
			return nil, fmt.Errorf("the stored revocation of certificates: %w", err)
		}
		r.Through = c.Through
	}
	return r, nil
}

// view is what a server holds of address a: its mailbox's record rec, or nil,
// with its identity's revocations rv, or nil. It is nil if neither is held.
// A revocation of the address makes the state Revoked, whatever the record
// says: a registration that raced the revocation leaves a record that is
// never served, and its TTL takes it.
func view(a protocol.Address, rec *Mailbox, rv *Revocations) *Mailbox {
	if rec == nil && rv == nil {
		return nil
	}
	b := &Mailbox{Addr: a, State: NoMailbox}
	if rec != nil {
		b = cloneMailbox(rec)
	}
	if rv != nil {
		if len(b.Identity) == 0 {
			b.Identity = rv.Identity
		}
		b.Revocation, b.RevokedCerts, b.RevokedCertsSig = rv.Address, rv.Certs, rv.CertsSig
		if len(rv.Address) > 0 {
			b.State = Revoked
		}
	}
	return b
}

// withRevocations is b with rv merged into what it holds of its identity's
// revocations.
func (b *Mailbox) withRevocations(rv *Revocations) (*Mailbox, error) {
	held, err := b.revocations()
	if err != nil {
		return nil, err
	}
	if held == nil {
		held = &Revocations{}
	}
	held.merge(rv)
	c := cloneMailbox(b)
	if len(c.Identity) == 0 {
		c.Identity = held.Identity
	}
	c.Revocation, c.RevokedCerts, c.RevokedCertsSig = held.Address, held.Certs, held.CertsSig
	if len(c.Revocation) > 0 {
		c.State = Revoked
	}
	return c, nil
}

// mergeViews is what two reads of one address hold together: the newer
// record (version), and every revocation either holds, since none is ever
// taken away: the revocation of the address if either holds it, and the
// higher revocation of its certificates (higherCerts). Nothing is dropped
// for a list that does not parse (dromas-dev/dromas-server#64).
func mergeViews(old, cur *Mailbox) *Mailbox {
	base, other := cur, old
	if versionOf(old).after(versionOf(cur)) {
		base, other = old, cur
	}
	m := cloneMailbox(base)
	if len(m.Identity) == 0 {
		m.Identity = other.Identity
	}
	if len(m.Revocation) == 0 {
		m.Revocation = other.Revocation
	}
	if len(m.Revocation) > 0 {
		m.State = Revoked
	}
	if higherCerts(other, m) {
		m.RevokedCerts, m.RevokedCertsSig = slices.Clone(other.RevokedCerts), slices.Clone(other.RevokedCertsSig)
	}
	return m
}

// higherCerts reports whether o's revocation of certificates is to stand in
// place of b's: o holds one and b none, or o's reaches higher. One that does
// not parse stands in place of one that does, so that its next use fails as
// listNames does, closed.
func higherCerts(o, b *Mailbox) bool {
	switch {
	case len(o.RevokedCerts) == 0:
		return false
	case len(b.RevokedCerts) == 0:
		return true
	}
	oc, oerr := protocol.ParseRevokedCertificates(o.RevokedCerts)
	bc, berr := protocol.ParseRevokedCertificates(b.RevokedCerts)
	switch {
	case berr != nil:
		return false
	case oerr != nil:
		return true
	}
	return oc.Through > bc.Through
}

// listNames reports whether a stored revocation of certificates covers a
// serial. It was verified when it was stored, so one that does not parse is
// a fault of the record, and no answer.
func listNames(statement []byte, serial uint64) (bool, error) {
	r, err := protocol.ParseRevokedCertificates(statement)
	if err != nil {
		return false, fmt.Errorf("the stored revocation of certificates: %w", err)
	}
	return r.Revokes(serial), nil
}

// Account is an account's record (PROTOCOL.md §11.16). An account pays,
// from prepaid credit, for its mailboxes' sends past the free limits and for
// size over the cap; with no credit they have the free limits. An unmetered
// account's mailboxes have no daily limit, the largest cap and new messages at
// ReceiveCeiling, and are never charged: the echo account. Credit is not built yet, so a metered account's
// mailboxes have the free limits.
type Account struct {
	ID        string
	Unmetered bool
	Rev       uint64
}

// AdoptKey is what is kept of an adopt key: its hash, never the key
// (adoptkey.go).
type AdoptKey struct {
	Account string
	Hash    [32]byte // SHA-256 of the key
	Uses    int      // left
	Expires time.Time
}

// good reports whether the key has a use left and has not expired.
func (k *AdoptKey) good(now time.Time) bool { return k.Uses >= 1 && now.Before(k.Expires) }

// Retired is what is kept of a retired prekey while it is live.
type Retired struct {
	Type     protocol.KeyType
	NotAfter time.Time
	KeyHash  [32]byte // SHA-256 of the age recipient
}

// Header is one message's metadata: everything but its body.
type Header struct {
	ID         [32]byte // SHA-256 of the ciphertext
	Size       int
	ReceivedAt time.Time // to the millisecond
	ExpiresAt  time.Time
}

// Standing is what checking a mailbox's pass needs of it (PROTOCOL.md §8):
// its state, its identity's public key, which signer is its current one,
// and whether its identity's revocation of certificates covers that signer.
type Standing struct {
	State  State
	Key    string   // the identity's key in SSH wire form, of whatever type: what line 2 of its document holds
	Signer [32]byte // Mailbox.Signer
	// Rank is Mailbox.Rank, which Listed is judged by.
	Rank uint64
	// Listed is true while the revocation of certificates held covers the
	// mailbox's current signer (PROTOCOL.md §10.2): a certificate at or below
	// it, never the identity. Only the identity's pass is taken until the
	// mailbox publishes a prekey under a certificate above it.
	Listed bool
	// InAccount is true for a mailbox in an account, whose limits are read from
	// it; a mailbox in none has the server's, with nothing to read.
	InAccount bool
}

// standing is b's standing. ok is false for an address with no mailbox: one
// whose identity revoked certificates and registered nothing.
func (b *Mailbox) standing() (st Standing, ok bool, err error) {
	if b.State == NoMailbox {
		return Standing{}, false, nil
	}
	key, err := identityWire(b.Identity)
	if err != nil {
		return Standing{}, false, fmt.Errorf("the stored identity: %w", err)
	}
	st = Standing{State: b.State, Key: key, Signer: b.Signer, Rank: b.Rank, InAccount: b.Account != ""}
	if b.State != Revoked {
		if st.Listed, err = b.listed(b.Rank); err != nil {
			return Standing{}, false, err
		}
	}
	return st, true, nil
}

// identityWire is the key of a stored identity document, in SSH wire form:
// the base64 of its second line, decoded. The document was parsed when its
// mailbox registered, so this reads it and checks nothing.
func identityWire(doc []byte) (string, error) {
	_, line, _ := bytes.Cut(doc, []byte("\n"))
	_, b64, _ := bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
	wire, err := base64.StdEncoding.Strict().DecodeString(string(b64))
	if err != nil || len(wire) == 0 {
		return "", errors.New("its key is not base64")
	}
	return string(wire), nil
}

// identityType is the key type of a stored identity document: the first word
// of its second line. The document was parsed when its mailbox registered.
func identityType(doc []byte) string {
	_, line, _ := bytes.Cut(doc, []byte("\n"))
	name, _, _ := bytes.Cut(line, []byte(" "))
	return string(name)
}

// signerHash names the signer of a statement of identity id's mailbox by the
// SHA-256 of its signing key's wire bytes: the identity's key, or the
// certificate (protocol.Pass.VerifyUnder).
func signerHash(id *protocol.Identity, s *protocol.Signer) [32]byte {
	if c := s.Certificate(); c != nil {
		return sha256.Sum256(c.Marshal())
	}
	return sha256.Sum256(id.PublicKey().Marshal())
}

// keep is when the record of a mailbox may go once it takes statement p,
// signed by s, where it was to go at held (PROTOCOL.md §13): the latest of
// held, the end of the last message sealed to p, and the end of s's
// certificate, if s is one, so that no working key a certificate it took
// certified is left to register with. It is one date, raised and never
// lowered: a statement under a shorter certificate keeps the end of every
// longer one taken before it.
func keep(held time.Time, p *protocol.Prekey, s *protocol.Signer) time.Time {
	ends := []time.Time{held, p.NotAfter.Add(protocol.TTL)}
	if c := s.Certificate(); c != nil {
		ends = append(ends, c.NotAfter())
	}
	return slices.MaxFunc(ends, time.Time.Compare)
}

// Store errors. A write's error is one of two outcomes (Memory.write): a
// refusal the store stated, of a write it did not make, which these name
// (and errNotStored, errRefused, a duplicate); or ErrUnknown, which leaves
// open whether the write was applied. A write that returns nil was applied.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrStale    = errors.New("the record changed since it was read")
	// ErrKeyRefused is an adopt key that is spent, expired or gone.
	ErrKeyRefused = errors.New("the adopt key is spent, expired or revoked")
	// ErrUnknown is a write's error that leaves open whether it was
	// applied: an answer lost, a timeout, a fault of the backend's own, or
	// any error a backend did not state as a refusal. It wraps the cause.
	// A count reserved for the write is kept (LIMITS.md rule 4).
	ErrUnknown = errors.New("the write may have been applied")
)

// errRefused marks a backend's error as a refusal it stated, of a write it
// did not make: AWS's throttle or its answer of 4xx to the call itself, or
// a step of a multi-step write that failed before its item's write, and
// changed nothing memory holds (an ack's body not deleted, a delete of a
// mailbox's messages that deleted no body).
var errRefused = errors.New("refused")

// refused is err, marked as a refusal stated (errRefused).
func refused(err error) error { return fmt.Errorf("%w: %w", errRefused, err) }

// unknown is err, marked as leaving open whether its write was applied.
func unknown(err error) error {
	if errors.Is(err, ErrUnknown) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnknown, err)
}

// duplicate is a send's refusal, stated by the store: the live message item
// of another send of the same ciphertext was there first, and h is its
// header. A send answers from it (ARCHITECTURE.md § Storage).
type duplicate struct{ h *Header }

func (d duplicate) Error() string { return "a message of the same ciphertext is held" }

// isRefusal reports whether a backend's error is a refusal it stated. Any
// other error leaves open whether its write was applied.
func isRefusal(err error) bool {
	return !errors.Is(err, ErrUnknown) && (errors.Is(err, ErrExists) || errors.Is(err, ErrStale) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrKeyRefused) || errors.Is(err, errNotStored) || errors.Is(err, errRefused) || errors.As(err, new(duplicate)))
}

// errNotStored is a send's error that the store states left nothing stored:
// its body's PUT failed, before its item was written, whatever S3 answered
// (dromas-dev/dromas-server#90).
var errNotStored = errors.New("not stored")

// version is a record's place in its address's history: the time its mailbox
// registered, to the millisecond as the store keeps it, then its rev. A mailbox
// registered again once the TTL took its record starts at rev 1 again, and
// later (dromas-dev/dromas-client#407 item 2). It is the one comparison
// of two records of an address: the record cache's (putLocked, image,
// mergeViews) and the index's (setStanding). An account's has its rev
// alone.
type version struct{ created, rev uint64 }

// after reports whether v is a later record than o.
func (v version) after(o version) bool {
	return v.created > o.created || v.created == o.created && v.rev > o.rev
}

// versionOf is b's record's version: 0 for a view with no record.
func versionOf(b *Mailbox) version {
	if b.Created.IsZero() {
		return version{rev: b.Rev}
	}
	return version{ms(b.Created), b.Rev}
}

// storeTimeout bounds each call to AWS the store makes, a read as a write,
// whatever context its caller hands it (bound, boundedStreams), and each
// read that a call shared by several callers makes apart from the request
// that started it: a lookup's read of a mailbox's record (Server.lead) and the
// reads of a send's steps 6 to 9 (Server.deliver).
const storeTimeout = 10 * time.Second

// bounded is ctx bounded by storeTimeout: for a read that callers share,
// made apart from their requests, on any store (Server.deliver), and for
// each call of the stream follower (boundedStreams). A handler hands every
// store write a context apart from its request (detached), so that what a
// write changed is counted and reaches memory whenever the write was made
// (dromas-dev/dromas-server#14), and a call that callers share reads on
// one (dromas-dev/dromas-server#91).
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, storeTimeout)
}

func ms(t time.Time) uint64     { return uint64(t.UnixMilli()) }          //nolint:gosec // times after 1970
func fromMs(v uint64) time.Time { return time.UnixMilli(int64(v)).UTC() } //nolint:gosec // decoded from our own keys

// ttlMs is how long a message is kept after it was received, in ms: the
// TTL less the hour the maker of a time-limited thing leaves, and a post's own
// time (protocol.Retention).
var ttlMs = uint64(protocol.Retention / time.Millisecond)

func cloneMailbox(b *Mailbox) *Mailbox {
	c := *b
	c.Retired = slices.Clone(b.Retired)
	c.SenderKeyTypes = slices.Clone(b.SenderKeyTypes)
	c.RevokedCerts, c.RevokedCertsSig = slices.Clone(b.RevokedCerts), slices.Clone(b.RevokedCertsSig)
	c.ACL = cloneACL(b.ACL)
	if b.Prekey != nil {
		p := *b.Prekey
		c.Prekey = &p
	}
	return &c
}

// cloneACL copies an ACL, which a mailbox record holds and nothing changes in
// place: it is replaced whole.
func cloneACL(a *protocol.ACL) *protocol.ACL {
	if a == nil {
		return nil
	}
	c := *a
	c.Allow.Addrs, c.Deny.Addrs = slices.Clone(a.Allow.Addrs), slices.Clone(a.Deny.Addrs)
	return &c
}

// storedRecord is what a store keeps of b as its record: none of what its
// identity revoked, which is kept apart, and the state the record says.
func storedRecord(b *Mailbox) *Mailbox {
	c := cloneMailbox(b)
	c.Revocation, c.RevokedCerts, c.RevokedCertsSig = nil, nil, nil
	return c
}

func cloneAccount(a *Account) *Account {
	c := *a
	return &c
}

// Store is the server's state: mailbox records, message headers and bodies,
// and what a poll needs of them in memory. Its
// one implementation is Memory, over a Backend: DynamoDB and S3 Express
// (NewDynamoStore), or maps in this process (NewMemStore, the dev server).
type Store interface {
	// Held returns the standing of a mailbox memory holds, with no read. ok is
	// false for a mailbox this process has not loaded, which only its record
	// answers for: Known, then Mailbox (ARCHITECTURE.md § Memory).
	Held(a protocol.Address) (st Standing, ok bool)
	// Changed returns a channel closed at mailbox a's next change in memory, by
	// a write of this process or one the streams bring: what a held list
	// waits on (PROTOCOL.md §11.11). It reads nothing.
	Changed(a protocol.Address) <-chan struct{}
	// NextExpiry returns when the first of mailbox a's messages in memory
	// expires, by the store's clock, with no read: past, for one that
	// expired since the mailbox was last read; zero for a mailbox with none, or one
	// memory has not loaded. An expiry is no change memory applies, so a
	// held list waits until it, and no longer (PROTOCOL.md §11.11).
	NextExpiry(a protocol.Address) time.Time
	// Mailbox returns what is held of an address (view): its mailbox's record and
	// its identity's revocations, or ErrNotFound if neither.
	Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error)
	// Known returns what memory holds of an address, with no read: what Mailbox
	// returns, or nil for an address it holds as missing. ok is false when
	// only a read can tell, which is what Mailbox then does.
	Known(a protocol.Address) (b *Mailbox, ok bool)
	// Begin returns a token of address a, which only grows: what Mailbox
	// answers once it is taken holds every write this process applied to a
	// before it.
	Begin(a protocol.Address) uint64
	// CreateMailbox stores a new mailbox's record at Rev 1, or returns ErrExists if
	// the address has one.
	CreateMailbox(ctx context.Context, b *Mailbox) error
	// UpdateMailbox stores b's record if the stored one is still at b.Rev, and
	// bumps b.Rev; otherwise ErrStale. It writes nothing of the revocations.
	UpdateMailbox(ctx context.Context, b *Mailbox) error
	// DeleteMailbox deletes a's record, and keeps its revocations.
	DeleteMailbox(ctx context.Context, a protocol.Address) error
	// Revoke keeps what the identity of address a revoked, mailbox or none, in
	// the address's revocations item: rv's revocation of the address, kept
	// once, and its revocation of certificates, which only one through a
	// higher serial replaces: ErrStale if one through as high a serial was
	// stored first, or if the address's revocations are not what want asks
	// of them, some held or none.
	Revoke(ctx context.Context, a protocol.Address, rv *Revocations, want Expect) error

	// Dedupe returns the header of the live message mailbox holds with this
	// id, or ErrNotFound: nothing is kept of one acked or expired.
	Dedupe(ctx context.Context, mailbox protocol.Address, id [32]byte) (*Header, error)
	// PutMessage stores a message: its body, then its header. If a live
	// message of the id appeared first, it returns that one's header
	// instead.
	PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error)
	// List returns up to limit live headers, oldest first by (ReceivedAt,
	// ID), after the given key (nil: from the start). Consistent reads them
	// strongly consistent: every write applied to memory before the read is
	// in the page.
	List(ctx context.Context, mailbox protocol.Address, after *Cursor, limit int, consistent bool) ([]Header, error)
	// Message returns a live message and its body, or ErrNotFound: the body
	// from byte from on where from is inside it, above 0 and below its Size,
	// and otherwise whole, as a fetch answers a range (PROTOCOL.md §11.12).
	// So a fetch that resumes reads only the rest from where a body is kept.
	Message(ctx context.Context, mailbox protocol.Address, id [32]byte, from int64) (*Header, []byte, error)
	// DeleteMessage acks a message: its body goes, then its item, and
	// nothing of it is kept (PROTOCOL.md §13). ErrNotFound if it is not
	// live.
	DeleteMessage(ctx context.Context, mailbox protocol.Address, id [32]byte) error
	// DeleteMessages deletes every live message in a mailbox, as acks do (a
	// revocation of its address). A message already gone is no error.
	DeleteMessages(ctx context.Context, mailbox protocol.Address) error

	// Account returns an account's record, or ErrNotFound: read on its
	// first use, then answered from memory.
	Account(ctx context.Context, id string) (*Account, error)
	// CreateAccount stores a new account at Rev 1, or returns ErrExists.
	CreateAccount(ctx context.Context, a *Account) error
	// PutAdoptKey stores a new adopt key's state, or returns ErrExists.
	PutAdoptKey(ctx context.Context, k *AdoptKey) error
	// AdoptKey returns the state of account's adopt key whose hash is given,
	// or ErrNotFound. It reads it strongly consistent, so a key just made is
	// found.
	AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error)
	// Adopt moves mailbox b, as read, into account, spending a use of account's
	// adopt key whose hash is given, in one write: ErrStale if the record
	// changed, ErrKeyRefused if the key is spent, expired or gone. It sets
	// b.Account and bumps b.Rev.
	Adopt(ctx context.Context, b *Mailbox, account string, key [32]byte) error
	// Leave takes mailbox b, as read, out of its account, or returns ErrStale.
	// It clears b.Account and bumps b.Rev.
	Leave(ctx context.Context, b *Mailbox) error

	// Count returns the number of live messages in a mailbox, from memory: the
	// mailbox is loaded on its first use, and answered from memory after that.
	Count(ctx context.Context, mailbox protocol.Address) (n int, err error)
	// After returns how many live messages a mailbox holds past a list position,
	// from memory as Count does: what a list from that cursor would return.
	After(ctx context.Context, mailbox protocol.Address, c *Cursor) (int, error)
	// Holds reports whether a mailbox holds a live message with this id, from
	// memory as Count does. False is certain; true may be another message
	// whose id starts alike, so the caller still reads it.
	Holds(ctx context.Context, mailbox protocol.Address, id [32]byte) (bool, error)
	// Fetched is Holds for a fetch: it also reports whether this process has
	// served the message before, and counts this serving. The count lives
	// with the message in memory, so a restart forgets it.
	Fetched(ctx context.Context, mailbox protocol.Address, id [32]byte) (held, again bool, err error)
}

// Cursor is a position in a mailbox's list: the last key returned.
type Cursor struct {
	ReceivedAt time.Time
	ID         [32]byte
}
