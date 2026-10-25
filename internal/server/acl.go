package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/dromas-dev/dromas-client/protocol"
)

// The bound on a PUT …/acl body, before it is parsed: each entry as JSON
// writes it, an address in quotes with a comma, and room for a client that
// indents its lists, plus the rest of the document. With no bound on the
// entries, the body is bounded so that the record stays one DynamoDB item,
// which holds at most 400 KB.
const (
	aclEntryBytes    = 96
	aclBodyAllowance = 1 << 10
	aclBodyUnbounded = 256 << 10
)

func (s *Server) aclBodyLimit() int64 {
	if s.limits.ACLEntries <= 0 {
		return aclBodyUnbounded
	}
	return int64(s.limits.ACLEntries)*aclEntryBytes + aclBodyAllowance
}

// hintACL names what writes an ACL: the client does, from its own lists.
const hintACL = "dromas peer allow and dromas peer block write this box's ACL from its own lists"

// aclTooLarge is the answer to an ACL over -acl-entries, by its entries or by
// the body bound drawn from them.
func (s *Server) aclTooLarge() *problem {
	return fail(protocol.CodeTooLarge, "list fewer addresses: "+hintACL, "an ACL here holds at most %d entries, its two lists together", limitValue(s.limits.ACLEntries))
}

// putACL is PUT /v1/<address>/acl (with the pass): the box's sender ACL,
// replaced whole (PROTOCOL.md §11.14). Its preconditions are evaluated against
// the ACL held, a box with none included, after the call's other checks and
// before its body is read, as RFC 9110 §13.2.1 has an origin server evaluate
// them (precondition): a false If-Match is 412, and so is an If-None-Match
// that is "*" or names the held ACL's tag, and nothing changes. The write is
// conditional on the record's revision, so the ACL the If-Match was held to
// is the one replaced. Then the box's unacked mail from every sender its deny
// list matches is deleted, as acks delete it. It answers the ACL as held with
// no ETag: the lists are sorted and each entry kept once, so what is held may
// not be what was sent, and RFC 9110 §9.3.4 lets a PUT's answer carry a
// validator only for content saved as it came.
func (s *Server) putACL(w http.ResponseWriter, r *http.Request) error {
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
	held, err := answerACL(b.ACL)
	if err != nil {
		return err
	}
	if err := precondition(r, targetState{exists: true, tag: held.tag, hint: "GET the same path for the ACL held and its ETag, or PUT without If-Match: " + hintACL}); err != nil {
		return err
	}
	var doc protocol.ACLDocument
	if err := decodeBody(w, r, s.aclBodyLimit(), &doc); err != nil {
		// The bound is drawn from the entries, so a body over it is answered
		// for them: an ACL's limit is in entries (PROTOCOL.md §11.3). With
		// them unbounded, the body's bytes are the one limit there is.
		var p *problem
		if errors.As(err, &p) && p.code == protocol.CodeTooLarge && s.limits.ACLEntries > 0 {
			return s.aclTooLarge()
		}
		return err
	}
	acl, err := protocol.CheckACL(&doc, s.limits.ACLEntries)
	switch {
	case errors.Is(err, protocol.ErrACLTooLarge):
		return s.aclTooLarge()
	case err != nil:
		return failErr(protocol.CodeBadRequest, hintACL, err)
	}
	body, err := jsonBytes(acl.Document())
	if err != nil {
		return err
	}
	b.ACL = acl
	ctx := detached(r.Context())
	if err := s.store.UpdateBox(ctx, b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeBoxChanged, "retry", "the box changed during the request")
		}
		return err
	}
	// After the record holds the ACL, so the sends it refuses are refused
	// from here on. Memory says first whether the box holds any mail.
	if acl.Deny.Len() > 0 {
		if n, err := s.store.Count(ctx, a); err != nil {
			return err
		} else if n > 0 {
			if err := s.store.DeleteFrom(ctx, a, acl.Deny.Has); err != nil {
				return err
			}
		}
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return nil
}

// getACL is GET /v1/<address>/acl (with the pass): the box's ACL as it was
// put, or, for a box that has put none, the one allowing everyone, with its
// ETag. Its preconditions are evaluated as every route's are (precondition),
// once the answer without them would be 200 (RFC 9110 §13.2.1), and in
// §13.2.2's order: an If-Match, compared strongly, that is false is 412; then
// an If-None-Match that names the tag, compared weakly, is 304 with the ETag
// and no body.
func (s *Server) getACL(w http.ResponseWriter, r *http.Request) error {
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
	got, err := answerACL(b.ACL)
	if err != nil {
		return err
	}
	if err := precondition(r, targetState{exists: true, tag: got.tag, hint: "GET the same path without If-Match: " + hintACL}); err != nil {
		return err
	}
	h := w.Header()
	h.Set("ETag", got.tag)
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(got.body)
	return nil
}

// aclAnswer is the ACL's document as GET and PUT …/acl answer it, and its
// ETag, entityTag of those bytes, so the tag is a strong validator of what
// GET answers (RFC 9110 §8.8.1). It changes whenever the lists do, needs
// nothing stored, and every process makes the same one; an ACL put back as
// it was has its old tag again, and a box with none has the tag of the ACL
// it answers.
type aclAnswer struct {
	body []byte
	tag  string
}

// entityTag is a strong ETag of b: its hash.
func entityTag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// answerACL is the answer for an ACL held, nil for none.
func answerACL(acl *protocol.ACL) (aclAnswer, error) {
	body, err := jsonBytes(acl.Document())
	if err != nil {
		return aclAnswer{}, err
	}
	return aclAnswer{body: body, tag: entityTag(body)}, nil
}
