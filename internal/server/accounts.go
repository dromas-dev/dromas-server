package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Accounts (PROTOCOL.md §11.16): a box may belong to one account, which
// may lift its limits. A box joins with an adopt key the account minted, and
// leaves on its own, or the account drops it.

// accountID is an account id: a minted one is 32 hex characters, and a few
// names are ours (echo).
var accountID = regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{0,31}\z`)

func validAccountID(s string) bool { return accountID.MatchString(s) }

// NewAccountID returns a minted account id: 16 random bytes, in hex.
func NewAccountID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewAccount checks an account id and returns its record.
func NewAccount(id string, unmetered bool) (*Account, error) {
	if !validAccountID(id) {
		return nil, errors.New("an account id is 1-32 of a-z, 0-9 and -, starting with a letter or digit")
	}
	return &Account{ID: id, Unmetered: unmetered}, nil
}

func keyRefused() *problem {
	return fail(protocol.CodeAdoptKeyRefused, "ask the account for a new adopt key", "the adopt key is spent, expired, revoked or not this server's")
}

// adopt is PUT /v1/<address>/account (with the pass): the box joins the account its
// adopt key names, spending one of the key's uses. Naming the account the
// box is already in spends none, so a retry whose answer was lost is 200
// even once the key is spent.
func (s *Server) adopt(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	var req protocol.AdoptRequest
	if err := decodeBody(w, r, 4<<10, &req); err != nil {
		return err
	}
	// None, null (PROTOCOL.md §3.3) or empty is a missing member, as a
	// parameter sent without a value is an omitted one (RFC 6749 §3.1): the
	// request is wrong, not the key.
	if req.Key == "" {
		return fail(protocol.CodeBadRequest, "irongall account adopt sends the key it reads on stdin", "missing field %q", memberValue("key"))
	}
	account, hash, ok := parseAdopt(req.Key)
	if !ok {
		return keyRefused()
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	// The target is the box's place in an account: there is one once it is
	// in any (precondition). The write holds what they held, the record at
	// the rev read.
	if err := precondition(r, targetState{exists: b.Account != "", hint: hintConditions}); err != nil {
		return err
	}
	// The key is read before anything is written, so one that is not ours
	// costs a read of the accounts table and no write of the box's record.
	k, err := s.store.AdoptKey(r.Context(), account, hash)
	if errors.Is(err, ErrNotFound) {
		return keyRefused()
	}
	if err != nil {
		return err
	}
	if b.Account != account {
		if !k.good(s.now()) {
			return keyRefused()
		}
		switch err := s.store.Adopt(detached(r.Context()), b, account, hash); {
		case errors.Is(err, ErrKeyRefused):
			return keyRefused()
		case errors.Is(err, ErrStale):
			return fail(protocol.CodeBoxChanged, "retry: irongall account adopt", "the box changed during the request")
		case err != nil:
			return err
		}
	}
	writeJSON(w, http.StatusOK, protocol.AccountResponse{Account: account})
	return nil
}

// leave is DELETE /v1/<address>/account (with the pass): the box leaves its
// account, and has the server's limits again. A box in no account is
// already there.
func (s *Server) leave(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	if err := precondition(r, targetState{exists: b.Account != "", hint: hintConditions}); err != nil {
		return err
	}
	if b.Account != "" {
		switch err := s.store.Leave(detached(r.Context()), b); {
		case errors.Is(err, ErrStale):
			return fail(protocol.CodeBoxChanged, "retry: irongall account leave", "the box changed during the request")
		case err != nil:
			return err
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// limitsFor returns the limits a box gets: the server's, unless it is in an
// unmetered account, whose boxes have no daily limit, the largest cap, no
// budget of calls or of mail drained, and new mail at ReceiveCeiling. A box
// whose account is gone has the server's. These are the volume levers
// (LIMITS.md): what an account may lift.
func (s *Server) limitsFor(ctx context.Context, b *Box) (Limits, error) {
	l := s.limits
	if b.Account == "" {
		return l, nil
	}
	acc, err := s.store.Account(ctx, b.Account)
	if errors.Is(err, ErrNotFound) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if acc.Unmetered {
		l.SendsPerDay, l.MaxSize, l.CallBurst, l.DrainBurst = 0, l.ceiling(), 0, 0
		l.ReceiveRefill = l.liftedReceives()
	}
	return l, nil
}

// receivesAt is the budget of new mail of a box with limits l: the server's,
// or the one an account lifts it to. Each refill has buckets of its own
// (LIMITS.md § Accounts).
func (s *Server) receivesAt(l Limits) *buckets {
	if l.ReceiveRefill == s.limits.ReceiveRefill {
		return s.receives
	}
	return s.lifted
}
