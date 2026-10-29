package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// pageSize is the list page: up to 50 messages (the delivery contract).
const pageSize = 50

// list is GET /v1/<address>/messages (PROTOCOL.md §11.11): metadata only,
// oldest first, pages of 50. Every answer is a page with the count, and
// carries the poll interval in Retry-After; a first page carries its ETag
// too, and a poll that sends it back is 304 while the page is unchanged
// (listTag). The poll rate applies to every poll, empty ones and 304s
// included, and is taken before a 304 or a 412 is answered: a box that
// polls too often is told 429, never 304. A page after the first is a
// continuation, not a poll, with an allowance of its own
// (Limits.continuations), where it is a GET whose preconditions hold and
// that presents the cursor the box was handed last; a cursor with nothing
// after it continues nothing, so it is a poll. Only a GET's 200 spends the
// cursor and hands out the next (the client repo's #412 item 2): a HEAD, a
// false precondition or a refusal leaves the box holding the one it was
// handed. Only a list with something to return reads storage.
func (s *Server) list(w http.ResponseWriter, r *http.Request) error {
	// The path and the query first, the cursor's decode among them, before
	// the pass (PROTOCOL.md §11.11).
	if _, err := pathAddr(r, cursorParam, waitParam); err != nil {
		return err
	}
	cursor, hasCursor := r.URL.Query()[cursorParam]
	wait, err := listWait(r, hasCursor)
	if err != nil {
		return err
	}
	var after *Cursor
	if hasCursor {
		var err error
		if after, err = parseCursor(cursor[0]); err != nil {
			return err
		}
	}
	box, err := s.owner(r, cursorParam, waitParam)
	if err != nil {
		return err
	}
	poll := strconv.Itoa(s.limits.PollAfter)
	// A page after the first exists and carries no tag, so its
	// preconditions are known before its page is read, and before its
	// cursor is looked at: a false one is a poll like any other (PROTOCOL.md
	// §11.11), which takes no cursor.
	if hasCursor {
		if err := precondition(r, targetState{exists: true, hint: hintList, also: []string{"Retry-After", poll}, spend: func() error { return s.spendPoll(box) }}); err != nil {
			return err
		}
	}
	more := 0 // live messages past the cursor
	// The cursor this process handed the box last, a GET's, is taken for
	// the call and given back unless the call is answered 200: so of the
	// calls in flight at once that present it, one continues the drain.
	held := false
	if hasCursor {
		if more, err = s.store.After(r.Context(), box, after); err != nil {
			return err
		}
		held = r.Method == http.MethodGet && s.drains.take(box, cursor[0])
	}
	answered := false
	defer func() {
		if held && !answered {
			s.drains.giveBack(box, cursor[0])
		}
	}()
	// A page after the first is a continuation only when it presents the
	// cursor of the page served last: a made-up, replayed or retried cursor
	// is answered all the same, and charged as a poll
	// (dromas-dev/dromas-server#5).
	if more == 0 || !held {
		if err := s.spendPoll(box); err != nil {
			return err
		}
	} else if ok, wait := s.pages.take(box.String(), s.now()); !ok {
		return rateLimited(protocol.QuotaPages, wait, "too many list pages at once")
	} else {
		s.metrics.list(true)
	}
	// A first page asked to wait is held while the If-None-Match names it
	// (PROTOCOL.md §11.11): read, held until the box changes, its first
	// message expires, the wait passes or the server stops, and read again;
	// then answered as any list. The box's change is taken before each read,
	// so none is missed between; and the page of a list asked to wait is read
	// strongly consistent, so it holds every change memory applied before
	// the read, and the next change wakes it: an eventually consistent page
	// that missed one could be held on, and no later change would come.
	asked := wait > 0 && !hasCursor
	var until time.Time
	if asked {
		until = time.Now().Add(min(wait, s.limits.MaxWait))
	}
	// A list held is counted once, by how its hold ended, however often it
	// woke to the same page and was held again.
	holding, ended := false, ""
	defer func() {
		if holding {
			s.unhold()
			s.metrics.heldEnded(ended)
		}
	}()
again:
	var changed <-chan struct{}
	if !until.IsZero() {
		changed = s.store.Changed(box)
	}
	n, err := s.store.Count(r.Context(), box)
	if err != nil {
		return err
	}
	resp := protocol.MessageList{Count: int64(n), Messages: []protocol.MessageInfo{}}
	if n > 0 && (after == nil || more > 0) {
		page, err := s.store.List(r.Context(), box, after, pageSize+1, asked)
		if err != nil {
			return err
		}
		if len(page) > pageSize {
			page = page[:pageSize]
			next := formatCursor(page[pageSize-1])
			resp.NextCursor = &next
		}
		for _, h := range page {
			resp.Messages = append(resp.Messages, protocol.MessageInfo{
				ID:         hexID(h.ID),
				Size:       int64(h.Size),
				ReceivedAt: formatTime(h.ReceivedAt),
				ExpiresAt:  formatTime(h.ExpiresAt),
			})
		}
	}
	body, err := jsonBytes(resp)
	if err != nil {
		return err
	}
	// A first page's tag is that of its body, so its preconditions are
	// evaluated once the page is read: an If-Match first, compared strongly,
	// and a false one is 412 (dromas-dev/dromas-server#71); then an
	// If-None-Match that names the tag, compared weakly, or is "*", is 304
	// with no body, its ETag, its Retry-After and the headers every answer
	// carries (RFC 9110 §15.4.5). A page after the first, which has none,
	// matches no tag but "*".
	var tag string
	if !hasCursor {
		tag = listTag(body)
		if !until.IsZero() && time.Now().Before(until) && protocol.IfMatch(r.Header.Values("If-Match"), tag) && protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
			if !holding {
				if holding = s.hold(); !holding {
					s.metrics.heldEnded("refused")
					p := fail(protocol.CodeUnavailable, "retry later", "this server holds as many lists as it may")
					p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
					return p
				}
			}
			// An expiry is no change memory applies: the hold's timer ends
			// at the box's first, by the store's clock, if it comes before
			// the wait's end.
			d := time.Until(until)
			if next := s.store.NextExpiry(box); !next.IsZero() {
				d = min(d, next.Sub(s.now()))
			}
			t := time.NewTimer(d)
			select {
			case <-changed:
				ended = "changed"
			case <-t.C:
				if time.Now().Before(until) {
					ended = "changed" // its first message expired
				} else {
					ended, until = "waited", time.Time{}
				}
			case <-s.stopping:
				ended, until = "stopped", time.Time{}
			case <-r.Context().Done():
				t.Stop()
				ended = "gone"
				return r.Context().Err()
			}
			t.Stop()
			goto again
		}
		if err := precondition(r, targetState{exists: true, tag: tag, hint: hintList, also: []string{"Retry-After", poll}}); err != nil {
			return err
		}
	}
	if r.Method == http.MethodGet && resp.NextCursor != nil {
		s.drains.put(box, *resp.NextCursor)
	}
	answered = true
	writeList(w, body, tag, poll)
	return nil
}

// waitParam is a list's long poll (PROTOCOL.md §11.11).
const waitParam = "wait"

// listWait reads a list's wait: zero for none, and a refusal for one that
// is not delay-seconds or that comes with a cursor (PROTOCOL.md §11.11).
func listWait(r *http.Request, hasCursor bool) (time.Duration, error) {
	v, ok := r.URL.Query()[waitParam]
	if !ok {
		return 0, nil
	}
	n, err := protocol.Wait(v[0])
	if err != nil || hasCursor {
		return 0, fail(protocol.CodeBadRequest, "send the wait as whole seconds, on a list without a cursor", "the query parameter %s is not delay-seconds on a first page", memberValue(waitParam))
	}
	if n >= uint64(waitReadBound/time.Second) {
		return waitReadBound, nil
	}
	return time.Duration(n) * time.Second, nil
}

// waitReadBound bounds a wait as read, far past any MaxWait.
const waitReadBound = 24 * time.Hour

// hold counts one more list held, and reports false, counting nothing, at
// Limits.MaxHeldLists.
func (s *Server) hold() bool {
	if s.holding.Add(1) > int64(s.limits.MaxHeldLists) {
		s.holding.Add(-1)
		return false
	}
	s.metrics.holding(1)
	return true
}

// unhold counts one list held fewer.
func (s *Server) unhold() {
	s.holding.Add(-1)
	s.metrics.holding(-1)
}

// StopHolds answers every list held, now and from now on, at once: for
// http.Server.RegisterOnShutdown, so the clients list again at once and
// Shutdown waits for none of them.
func (s *Server) StopHolds() { s.stopOnce.Do(func() { close(s.stopping) }) }

// spendPoll spends one of box a's polls (Limits.PollBurst): every list that
// does not continue a drain, a 304 among them.
func (s *Server) spendPoll(a protocol.Address) error {
	if ok, wait := s.polls.take(a.String(), s.now()); !ok {
		return rateLimited(protocol.QuotaPolls, wait, "this box has polled as often as it may for now: poll again after Retry-After")
	}
	s.metrics.list(false)
	return nil
}

// hintList is a list's 412's hint.
const hintList = "list again without If-Match: dromas recv does"

// listTag is a first page's ETag: the first 16 bytes of the SHA-256 of its
// body, in hex. It is a strong validator that every process computes alike
// with no key, and it changes with any message that enters or leaves the
// page or the count. A page that holds mail cannot be made to share an
// empty box's tag, the one a client keeps: that is a second preimage of 128
// bits. A page after the first has none.
func listTag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// writeList writes a list answer, body, with the poll interval in
// Retry-After, as RFC 9773 §4.3 uses the field, and a first page's tag.
func writeList(w http.ResponseWriter, body []byte, tag, poll string) {
	h := w.Header()
	h.Set("Retry-After", poll)
	if tag != "" {
		h.Set("ETag", tag)
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// drains remembers, for each box with a drain open, the one next_cursor this
// process last handed it. Serving that cursor's page replaces it with the
// next, and the last page of a drain clears it. It is this process's alone,
// as every count is: a page that lands on another process is charged as a
// poll there.
type drains struct {
	mu   sync.Mutex
	next map[protocol.Address]string
}

// take reports whether cursor is the one box a was handed last, and takes it
// for the call: it is spent unless the call gives it back (giveBack).
func (d *drains) take(a protocol.Address, cursor string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ok := d.next[a] == cursor
	if ok {
		delete(d.next, a)
	}
	return ok
}

// giveBack gives box a the cursor a call took and did not spend, unless the
// box was handed another meanwhile.
func (d *drains) giveBack(a protocol.Address, cursor string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.next[a]; !ok {
		if d.next == nil {
			d.next = map[protocol.Address]string{}
		}
		d.next[a] = cursor
	}
}

// put remembers the cursor just handed to box a.
func (d *drains) put(a protocol.Address, cursor string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.next == nil {
		d.next = map[protocol.Address]string{}
	}
	d.next[a] = cursor
}

// cursorParam is the list's one query parameter: the next_cursor of the
// page before.
const cursorParam = "cursor"

// A cursor is the last key listed, opaque to clients: base64url of the
// receipt time in milliseconds (u64, big endian) and the id, unpadded, so
// one or more of [A-Za-z0-9_-] as a cursor is (protocol.CheckCursor).
func formatCursor(h Header) string {
	b := binary.BigEndian.AppendUint64(nil, uint64(h.ReceivedAt.UnixMilli())) //nolint:gosec // receipt times are after 1970
	return base64.RawURLEncoding.EncodeToString(append(b, h.ID[:]...))
}

func parseCursor(s string) (*Cursor, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 8+32 {
		return nil, fail(protocol.CodeBadRequest, "pass next_cursor exactly as received", "the query parameter %s is not a cursor this server handed out", memberValue(cursorParam))
	}
	c := &Cursor{ReceivedAt: time.UnixMilli(int64(binary.BigEndian.Uint64(b))).UTC()} //nolint:gosec // decoded from our own cursor
	copy(c.ID[:], b[8:])
	return c, nil
}

// gone is the answer for a message the box does not hold.
func gone() *problem {
	return fail(protocol.CodeNoSuchMessage, "treat it as gone", "no message has this id: acked or expired")
}

// held answers gone, from memory, for an id the box does not hold: a fetch
// or an ack reads or writes storage only for a message that is there.
func (s *Server) held(r *http.Request, box protocol.Address, id [32]byte) error {
	ok, err := s.store.Holds(r.Context(), box, id)
	if err != nil {
		return err
	}
	if !ok {
		return s.notHeld(r, box)
	}
	return nil
}

// notHeld answers a fetch or an ack of an id box a does not hold. A held
// message's first fetch spends the box's budget of mail taken out
// (Limits.DrainBurst), and its ack is paid for by its receive; anything else
// is a call, spent from the box's budget (Limits.CallBurst): this, a false
// precondition (precondition) and a message's HEAD.
func (s *Server) notHeld(r *http.Request, a protocol.Address) error {
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	return gone()
}

// fetch is GET /v1/<address>/messages/<id>: the ciphertext's bytes and
// nothing else, read through this endpoint, never a redirect. Who sent it,
// on this server's word, and when, are in the list. A Range of one
// open-ended byte range that begins inside the ciphertext is answered 206,
// the bytes from there on, read from the store with the same range, and any
// other with the whole body (PROTOCOL.md §11.12; protocol.RangeAsked): a fetch
// that was cut resumes so. A ranged fetch is counted as any fetch is. A
// HEAD is no fetch (PROTOCOL.md §11.2): it reads only whether the box holds
// the message, takes no token of new mail and marks nothing, spends one of
// the box's calls, and carries no Content-Length and reads no Range.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	id, err := pathID(r)
	if err != nil {
		return s.notHeld(r, box)
	}
	// Its target, from memory: whether the box holds the message. Its
	// preconditions are evaluated for one it holds, before anything is
	// counted for it, and a false one is a call, the box's (precondition).
	if err := s.held(r, box, id); err != nil {
		return err
	}
	owner := func() error { return s.spendOwner(r.Context(), box) }
	if err := precondition(r, targetState{exists: true, hint: hintConditions, spend: owner}); err != nil {
		return err
	}
	if r.Method == http.MethodHead {
		if err := owner(); err != nil {
			return err
		}
		w.Header().Set("Content-Type", protocol.CiphertextContentType)
		w.WriteHeader(http.StatusOK)
		return nil
	}
	// A first fetch of a held message is new mail drained, and spends the
	// box's budget of it (Limits.DrainBurst): how much mail a box takes out,
	// whoever sent it, which only the box's own calls spend. Whether a fetch
	// is a first one is known only once memory counts it, so a token is
	// reserved before and given back if it was not.
	lim, err := s.limitsOf(r.Context(), box)
	if err != nil {
		return err
	}
	var drain *reservation
	if lim.DrainBurst > 0 {
		var ok bool
		var wait time.Duration
		if drain, ok, wait = s.drained.reserve(r.Context(), box.String(), s.now); !ok {
			return spent(protocol.CodeFetchPaced, wait, "this box has taken out as much new mail as it may for now: the rest waits on the server")
		}
	}
	defer func() { drain.release(s.now()) }() // settled below, but for a panic
	held, again, err := s.store.Fetched(r.Context(), box, id)
	if err != nil || !held || again {
		drain.release(s.now())
	} else {
		drain.keep()
	}
	if err != nil {
		return err
	}
	if !held {
		return s.notHeld(r, box)
	}
	// A message is fetched once and kept by its reader. Fetching it again is
	// for catching up after a failure, so it has an allowance of its own, and
	// only a repeat ever touches it: PollBurst at once, one more each PollRefill.
	if again {
		if ok, wait := s.repeats.take(box.String(), s.now()); !ok {
			return fetchedAlready(wait)
		}
	}
	// Read after the preconditions, as RFC 9110 §14.2 has a Range read: a
	// false one answered above leaves it unread.
	from, ranged := protocol.RangeAsked(r.Header.Values("Range"), r.Header.Values("If-Range"))
	m, body, err := s.store.Message(r.Context(), box, id, from)
	if errors.Is(err, ErrNotFound) {
		return gone()
	}
	if err != nil {
		return err
	}
	size := int64(m.Size)
	ranged = ranged && from < size
	if ranged && int64(len(body)) != size-from {
		return fmt.Errorf("the store read %d bytes of a message of %d from byte %d", len(body), size, from)
	}
	s.metrics.fetch(again)
	h := w.Header()
	h.Set("Content-Type", protocol.CiphertextContentType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	status := http.StatusOK
	if ranged {
		h.Set("Content-Range", protocol.ContentRange(from, size))
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:gosec // an age file, as application/octet-stream, to the box that holds it: no page renders it
	return nil
}

// ack is DELETE /v1/<address>/messages/<id>. Reading does not delete; this
// does, and nothing of the message is kept (PROTOCOL.md §13). A held message's ack is paid
// for by its receive; one whose preconditions are false spends one of the
// box's calls (precondition). The delete is of a live message only, so an
// If-Match that held is held at it: one acked meanwhile is gone.
func (s *Server) ack(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	id, err := pathID(r)
	if err != nil {
		return s.notHeld(r, box)
	}
	if err := s.held(r, box, id); err != nil {
		return err
	}
	if err := precondition(r, targetState{exists: true, hint: hintConditions, spend: func() error { return s.spendOwner(r.Context(), box) }}); err != nil {
		return err
	}
	err = s.store.DeleteMessage(detached(r.Context()), box, id)
	if errors.Is(err, ErrNotFound) {
		return gone()
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
