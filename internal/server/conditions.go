package server

import (
	"errors"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// targetState is what a route knows of its target when it evaluates its
// preconditions (precondition).
type targetState struct {
	exists bool     // the target has a current representation
	tag    string   // its entity-tag, "" where it carries none
	hint   string   // a 412's hint
	also   []string // the fields of the 200 a 304 carries too, name and value pairs
	// spend is the call's own budget, where its route has spent none of it
	// before reading its target: what a false precondition spends, as any
	// call does. Nil where the call has paid already.
	spend func() error
}

// precondition is every route's one step for its If-Match and
// If-None-Match: taken once the route has read its target, after the call's
// own budget, and before any of its work, the work's budgets, a cursor
// taken or put, a mark, a write (PROTOCOL.md §11.4; the client repo's
// #412). It evaluates them as conditions does, against t. A false one does
// nothing but count as a call (LIMITS.md, rule 1): where the route has spent
// none of the call's budget, t.spend spends it, and a refusal of that is
// the answer; otherwise the 412, or the 304.
func precondition(r *http.Request, t targetState) error {
	err := conditions(r, t.exists, t.tag, t.hint, t.also...)
	if err == nil || t.spend == nil {
		return err
	}
	if serr := t.spend(); serr != nil {
		return serr
	}
	return err
}

// expected is what a write must still find of a target that carries no tag,
// once its request's preconditions held at its read (precondition;
// PROTOCOL.md §11.2): an If-Match held, so the target exists (a list of tags
// is never true of one with none); an If-None-Match of "*" held, so it does
// not (one of tags is true of it whatever it holds, so it asks nothing);
// and neither asks nothing. A target with a tag, an ACL, is written under
// its record's rev, which asks more.
func expected(r *http.Request) Expect {
	switch {
	case len(r.Header.Values("If-Match")) > 0:
		return ExpectHeld
	case protocol.IfNoneMatch(r.Header.Values("If-None-Match"), ""): // true of no tag but "*"
		return ExpectNone
	}
	return ExpectAnything
}

// conditions evaluates a request's If-Match and If-None-Match for its target,
// as RFC 9110 §13.1.1 and §13.1.2 have an origin server evaluate each it
// receives, in §13.2.2's order (IronGall-dev/irongall-server#86), for
// precondition, the one step every route takes for them: so whatever the
// route answers before that point, a refusal of the pass, a box that does
// not exist, a body it reads first that is refused, is answered as without
// them (§13.2.1). PROTOCOL.md §11.2 has the rule.
//
// exists is whether the target has a current representation, and tag its
// entity-tag, "" where it carries none. If-Match is false for a target that
// does not exist, and otherwise read as protocol.IfMatch reads it: "*" true,
// a list true when one of its tags is tag, compared strongly, and so false
// for a target with no tag. If-None-Match is false only for a target that
// exists, where it names tag or is "*", as protocol.IfNoneMatch reads it. The
// conditions on dates (If-Unmodified-Since, If-Modified-Since) are not
// evaluated: no answer here carries a Last-Modified (§13.1.3, §13.1.4). An
// If-Range is read beside a fetch's Range alone, by protocol.RangeAsked, and
// is false there, since a fetch carries no validator (§13.1.5).
//
// It returns nil to go on; a false If-Match, or a false If-None-Match on any
// method but GET or HEAD, as 412 precondition_failed with hint; and a false
// If-None-Match on a GET or HEAD as notModified, which handle answers 304
// with tag as its ETag, and also's fields, name and value pairs: those of the
// 200 that RFC 9110 §15.4.5 has a 304 carry too.
func conditions(r *http.Request, exists bool, tag, hint string, also ...string) error {
	if lines := r.Header.Values("If-Match"); len(lines) > 0 && (!exists || !protocol.IfMatch(lines, tag)) {
		return fail(protocol.CodePreconditionFailed, hint, "the request's If-Match is false for what this server holds")
	}
	if !exists || !protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
		return nil
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return fail(protocol.CodePreconditionFailed, hint, "the request's If-None-Match is false for what this server holds")
	}
	return &notModified{etag: tag, also: also}
}

// hintConditions is a 412's hint where no irongall client sends a condition.
const hintConditions = "read what the server holds again, then send it with conditions that hold, or with none: irongall sends none here"

// notModified is the answer to a GET whose If-None-Match is false: 304, with
// no content.
type notModified struct {
	etag string
	also []string
}

func (n *notModified) Error() string { return "not modified" }

// writeConditions answers what conditions returned, for a handler that
// writes its own answers: the 304, or the 412.
func writeConditions(w http.ResponseWriter, err error) {
	if n, ok := errors.AsType[*notModified](err); ok {
		n.write(w)
		return
	}
	if p, ok := errors.AsType[*problem](err); ok {
		writeProblem(w, p)
	}
}

// write answers 304 with n's fields.
func (n *notModified) write(w http.ResponseWriter) {
	h := w.Header()
	if n.etag != "" {
		h.Set("ETag", n.etag)
	}
	for i := 0; i+1 < len(n.also); i += 2 {
		h.Set(n.also[i], n.also[i+1])
	}
	w.WriteHeader(http.StatusNotModified)
}
