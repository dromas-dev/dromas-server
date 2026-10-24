package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// send is POST /v1/<recipient>/messages (PROTOCOL.md §11.10, the server pipeline):
// cheapest check first, and only the last step writes. Every count is taken
// before the work it guards and given back if that work does not happen.
func (s *Server) send(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	now := s.now()

	// 1. Who is sending: the pass, before the body is read, and then the
	// sender's own budget for calls, which every send spends, a retry
	// included: it bounds everything after it, the dedupe's read among them.
	// The pre-auth rate is per IP, and comes before anything is checked.
	if ok, wait := s.sendIPs.take(ipKey(s.clientIP(r)), now); !ok {
		return rateLimited(protocol.QuotaSendsBeforePass, wait, "too many sends from this address")
	}
	from, err := s.sender(r)
	if err != nil {
		return err
	}
	// A refusal of the calls gives their wait alone. The sends a day are
	// behind the dedupe (step 6): only it shows whether the call is new mail
	// that spends them, and a retry spends none (PROTOCOL.md §11.5).
	if lim, err := s.limitsOf(ctx, from); err != nil {
		return err
	} else if err := s.spendCall(from, lim); err != nil {
		return err
	}
	// The pass showed the box exists, so reading its record is no guess at
	// an address: it is not a read lookup would count or refuse.
	// It is held to what the pass's check held the box to (sender), since
	// the box can be revoked, or its certificate revoked, between the two
	// reads.
	sender, err := s.box(ctx, from)
	if err != nil {
		return err
	}
	switch {
	case sender != nil && sender.State == Revoked:
		return fail(protocol.CodeSenderRevoked, "your box is revoked: make a new one, irongall init", "the sending box is revoked")
	case !sender.open():
		return fail(protocol.CodeUnknownSender, "register your own box first: irongall init", "the box the pass names is not registered")
	}
	if listed, err := sender.listed(sender.CertSerial); err != nil {
		return err
	} else if listed {
		return listedCertificate()
	}
	lim, err := s.limitsFor(ctx, sender)
	if err != nil {
		return err
	}

	// 2. The request's target, before the body is read: the recipient's
	// address, and in the query the two serials and nothing else, each once
	// and written as a statement writes one.
	to, err := pathAddr(r, protocol.PrekeySerialParam, protocol.CertificateSerialParam)
	if err != nil {
		return err
	}
	q, err := protocol.ParseSendQuery(r.URL.RawQuery)
	if err != nil {
		return queryProblem(err, "name the serials of the prekey the ciphertext is encrypted to, and of the certificate its statement is signed under: irongall send does")
	}

	// 3. The body is the ciphertext's bytes, whatever its Content-Type says,
	// read to the sender's own cap. Past the free cap's size, a read waits
	// for the one allowance for large reads, which only a sender whose cap is
	// larger ever takes.
	free, limit := int64(s.limits.MaxSize), int64(lim.MaxSize)
	tooLarge := fail(protocol.CodeTooLarge, "send less", "the ciphertext is over %d bytes", limitValue(lim.MaxSize))
	if r.ContentLength > limit {
		return tooLarge
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(io.LimitReader(body, free+1))
	if err != nil {
		return readProblem(err, tooLarge)
	}
	if int64(len(data)) > free {
		// The wait is bounded as a body is: a send that holds the one large
		// read is cut off by its own deadline (paced), and one waiting for
		// it gives up after BodyTimeout.
		var wait <-chan time.Time // nil, so never, with no bound set
		if s.limits.BodyTimeout > 0 {
			tm := time.NewTimer(s.limits.BodyTimeout)
			defer tm.Stop()
			wait = tm.C
		}
		select {
		case s.largeRead <- struct{}{}:
			s.metrics.large("taken")
			defer func() { <-s.largeRead }()
		case <-wait:
			s.metrics.large("timed_out")
			p := fail(protocol.CodeUnavailable, "retry later", "another large send is being read")
			p.retryAfter = retryLater
			return p
		case <-ctx.Done():
			s.metrics.large("gone")
			p := fail(protocol.CodeUnavailable, "retry later", "another large send is being read")
			p.retryAfter = retryLater
			return p
		}
		rest, err := io.ReadAll(body)
		if err != nil {
			return readProblem(err, tooLarge)
		}
		data = append(data, rest...)
	}
	ciphertext := data

	// 4. It is an age file: its stanzas read as a reader reads them.
	stanzas, err := protocol.ReadStanzas(ciphertext)
	if err != nil {
		return fail(protocol.CodeNotAge, "encrypt with age to the box's prekey", "the ciphertext is not an age file")
	}

	// 5. The recipient is registered and active.
	rcpt, err := s.lookup(r, to)
	if err != nil {
		return err
	}
	switch {
	case rcpt != nil && rcpt.State == Revoked:
		return revokedWith(rcpt)
	case !rcpt.open():
		return noSuchMailbox
	}
	// The target is the box's mailbox, which exists, and carries no tag
	// (precondition): here, before the dedupe, since steps 6 to 9 are shared by
	// the posts of the same bytes in flight at once, whatever conditions each
	// carries. So a retry whose If-Match is false is 412, not the receipt
	// step 6 would give it: RFC 9110 §13.1.1 lets a server answer 2xx there,
	// and this one does not.
	if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
		return err
	}

	// 6 to 9, one call for the posts of this ciphertext to this box from
	// this sender, naming the same serials, in flight at once
	// (IronGall-dev/irongall-server#76, #16): one that arrives while the
	// first is in them waits for it, and is answered as step 6 answers a
	// post of bytes the box holds, or with the first's own refusal, which it
	// would meet as well. The call runs apart from the request that leads
	// it, so its caller going fails none of the others, and each of its reads
	// is bounded (deliver).
	p := &post{from: from, to: to, id: sha256.Sum256(ciphertext), ciphertext: ciphertext, stanzas: stanzas, q: q, sender: sender, rcpt: rcpt, lim: lim, now: now}
	led := false
	v, err, _ := s.posts.Do(string(p.to[:])+string(p.id[:])+string(p.from[:])+p.q.Encode(), func() (any, error) {
		led = true
		return s.deliver(context.WithoutCancel(ctx), p)
	})
	if err != nil {
		return err
	}
	d := v.(delivered)
	if !d.fresh || !led {
		return s.duplicate(w, d.h, from)
	}
	// The message made, which only its recipient may fetch (RFC 9110 §15.3.2).
	w.Header().Set("Location", "/v1/"+to.String()+"/messages/"+hexID(d.h.ID))
	writeJSON(w, http.StatusCreated, receipt(d.h))
	return nil
}

// A post is a send past its step 5: what steps 6 to 9 read.
type post struct {
	from, to     protocol.Address
	id           [32]byte
	ciphertext   []byte
	stanzas      protocol.Stanzas
	q            protocol.SendQuery
	sender, rcpt *Box
	lim          Limits
	now          time.Time
}

// delivered is what steps 6 to 9 made of a post: the message's header, and
// fresh if this post stored it, where a duplicate's is the original's.
type delivered struct {
	h     *Header
	fresh bool
}

// deliver is steps 6 to 9 of a send (send): the dedupe, whether the box
// takes new mail, the counts, the write. It runs on a context apart from the
// request that leads it, and every post of its ciphertext waits on it, so no
// request's end cuts a read of it short: each read is bounded by
// storeTimeout (bounded), on any store, as a lookup's shared read is
// (Server.lead), and a read that never answers ends there. Its writes run to
// their end, each call to AWS bounded by the store.
func (s *Server) deliver(ctx context.Context, p *post) (delivered, error) {
	from, to, msgID, rcpt, now, q := p.from, p.to, p.id, p.rcpt, p.now, p.q

	// 6. Dedupe, before anything asks whether the box takes new mail: a
	// retry gets the original receipt, whatever has changed since it was
	// stored, a renewal of the box's prekey included. What those checks
	// keep from the box is new mail, and a retry is none.
	read, cancel := bounded(ctx)
	orig, err := s.store.Dedupe(read, to, msgID)
	cancel()
	if err == nil {
		return delivered{h: orig}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return delivered{}, err
	}

	// 7. The box takes new mail on this prekey, and from this sender.
	if rcpt.Prekey.Expired(now) {
		return delivered{}, fail(protocol.CodePrekeyExpired, "the box's owner must publish a new prekey (irongall prekey renew); retry later", "this box's prekey has expired")
	}
	// A prekey under a certificate the box's identity has revoked is one
	// nobody may encrypt to. The cure is an expired prekey's: the owner
	// publishes a new one, under a new certificate.
	if listed, err := rcpt.listed(rcpt.CertSerial); err != nil {
		return delivered{}, err
	} else if listed {
		return delivered{}, fail(protocol.CodePrekeyExpired, "the box's owner must publish a new prekey (irongall prekey renew); retry later", "this box's prekey is signed under a certificate its identity revoked")
	}
	// A box takes mail from a sender whose identity its client can verify:
	// one on an Ed25519 key always, and otherwise what it declared with its
	// prekey. Refused here, the sender has an error and no receipt for mail
	// the recipient would have refused on reading it.
	if t := identityType(p.sender.Identity); !protocol.AcceptsSender(rcpt.SenderKeyTypes, t) {
		return delivered{}, fail(protocol.CodeSenderKeyType, "a box whose identity is an ssh-ed25519 key, as irongall init makes one, can write to any box",
			"this box's client does not verify identities of your box's key type, %s", keyTypeValue(t))
	}
	// A prekey is named by both serials: its own, and its certificate's.
	if q.PrekeySerial != rcpt.Prekey.Serial || q.CertificateSerial != rcpt.CertSerial {
		return delivered{}, fail(protocol.CodeStalePrekey, "a newer prekey exists: read GET /v1/<address> again and re-encrypt the same envelope (irongall does this)", "the box's current prekey is serial %d, under certificate %d", prekeySerialValue(rcpt.Prekey.Serial), certificateSerialValue(rcpt.CertSerial))
	}
	if refused := checkStanzas(p.stanzas, rcpt); refused != nil {
		return delivered{}, refused
	}

	// 8. First the box's ACL (PROTOCOL.md §11.14): deny, then allow. It is
	// read before any quota is taken, so a refused send spends none of them.
	// One code and one wording whether the sender was denied or is not on an
	// allow list, so a sender cannot tell which.
	if !rcpt.ACL.Admits(from) {
		return delivered{}, fail(protocol.CodeSenderNotAllowed, "nothing the sender can change: its client moves the message to outbox/failed/", "this box's ACL does not let your box send to it")
	}
	// Then quotas, counted only for sends that carried their sender's pass,
	// each taken before the write and given back unless the send is stored,
	// or may have been (mayHaveApplied): sends in flight at once cannot all
	// pass on one count.
	stored := false
	for _, d := range s.sendsOf(p.lim) {
		sent, ok, wait := d.bs.reserve(ctx, from.String(), s.now)
		if !ok {
			return delivered{}, d.refusal(wait)
		}
		defer func() {
			if stored {
				sent.keep()
			} else {
				sent.release(s.now())
			}
		}()
	}
	read, cancel = bounded(ctx)
	release, refused, err := s.reserveCaps(read, to, from)
	cancel()
	if err != nil {
		return delivered{}, err
	}
	if refused != nil {
		return delivered{}, refused
	}
	defer release()
	// The box's own budget for new mail, from every sender together: what
	// keeps one box from taking mail at any rate however many boxes send.
	read, cancel = bounded(ctx)
	rlim, err := s.limitsFor(read, rcpt)
	cancel()
	if err != nil {
		return delivered{}, err
	}
	if rlim.ReceiveBurst > 0 {
		recv, ok, wait := s.receivesAt(rlim).reserve(ctx, to.String(), s.now)
		if !ok {
			busy := fail(protocol.CodeMailboxBusy, "the box takes only so much new mail at a time: post it again after Retry-After (irongall outbox flush does)", "the box has taken as much new mail as it takes for now")
			busy.retryAfter = wait
			return delivered{}, busy
		}
		defer func() {
			if stored {
				recv.keep()
			} else {
				recv.release(s.now())
			}
		}()
	}

	// 9. Write, and the counts above stand.
	h := &Header{
		ID:         msgID,
		From:       from,
		Size:       len(p.ciphertext),
		ReceivedAt: now.UTC().Truncate(time.Millisecond),
		ExpiresAt:  now.UTC().Truncate(time.Millisecond).Add(protocol.Retention), // the TTL less the hour and a post's own time (PROTOCOL.md §3.4, §13)
	}
	orig, err = s.store.PutMessage(ctx, to, h, p.ciphertext)
	if err != nil {
		stored = mayHaveApplied(err)
		return delivered{}, err
	}
	if orig != nil {
		return delivered{h: orig}, nil // a send of the same ciphertext from another process, or a stale dedupe read
	}
	stored = true
	// The box's address may have been revoked since step 5 read it: then
	// what this wrote is deleted, as the revocation deleted the rest, and the
	// send is answered as the box now stands (IronGall-dev/irongall-server#15).
	// One process has the change in memory at once; with more, this is to be
	// a strongly consistent read (ARCHITECTURE.md, stage 2).
	read, cancel = bounded(ctx)
	cur, err := s.box(read, to)
	cancel()
	if err != nil {
		return delivered{}, err
	} else if !cur.open() {
		if err := s.store.DeleteMessage(ctx, to, msgID); err != nil && !errors.Is(err, ErrNotFound) {
			return delivered{}, err
		}
		stored = false
		if cur != nil && cur.State == Revoked {
			return delivered{}, revokedWith(cur)
		}
		return delivered{}, noSuchMailbox
	}
	return delivered{h: h, fresh: true}, nil
}

// inFlight is, for each box, the sends this process has let past the pair
// and box caps and not yet stored, kept beside the store's counts and read
// with them under one lock, so sends in flight at once cannot all pass on
// the same counts (IronGall-dev/irongall-server#4). It is this process's
// alone, as every count is (LIMITS.md).
type inFlight struct {
	mu   sync.Mutex
	box  map[protocol.Address]int
	pair map[[2]protocol.Address]int
}

// reserveCaps checks the pair and box caps for one more message from from
// to box to, counting the sends in flight, and counts this one in. release
// takes it out once the send is over: by then a stored message is in the
// store's counts, so a send checked between the two sees both and is
// refused one early, never let past. A refusal is p.
func (s *Server) reserveCaps(ctx context.Context, to, from protocol.Address) (release func(), p *problem, err error) {
	if s.limits.PairCap == 0 && s.limits.BoxCap == 0 {
		return func() {}, nil, nil
	}
	// Load the box first, so what is read under the lock is memory.
	if _, err := s.store.Count(ctx, to); err != nil {
		return nil, nil, err
	}
	f := &s.inFlight[to[0]]
	pair := [2]protocol.Address{to, from}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.limits.PairCap > 0 {
		n, oldest, err := s.store.PairCount(ctx, to, from)
		if err != nil {
			return nil, nil, err
		}
		if n += f.pair[pair]; n >= s.limits.PairCap {
			p := fail(protocol.CodePairFull, "the box holds the most unacked mail it takes from you: retry after it reads some", "%d unacked messages from this sender, the oldest expiring %s", unackedValue(n), oldestValue(oldest))
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			return nil, p, nil
		}
	}
	if s.limits.BoxCap > 0 {
		n, err := s.store.Count(ctx, to)
		if err != nil {
			return nil, nil, err
		}
		if n += f.box[to]; n >= s.limits.BoxCap {
			p := fail(protocol.CodeMailboxFull, "the box is full: retry later", "the box holds %d messages", countValue(n))
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			return nil, p, nil
		}
	}
	if f.box == nil {
		f.box, f.pair = map[protocol.Address]int{}, map[[2]protocol.Address]int{}
	}
	f.box[to]++
	f.pair[pair]++
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.box[to]--; f.box[to] <= 0 {
			delete(f.box, to)
		}
		if f.pair[pair]--; f.pair[pair] <= 0 {
			delete(f.pair, pair)
		}
	}, nil, nil
}

// sendsOf is the sends a day of a sender with limits lim: none when its
// account lifts them.
func (s *Server) sendsOf(lim Limits) []perDay {
	if lim.SendsPerDay == 0 {
		return nil
	}
	return []perDay{s.sendsADay(lim.SendsPerDay)}
}

func receipt(h *Header) protocol.Receipt {
	return protocol.Receipt{ID: hexID(h.ID), ReceivedAt: formatTime(h.ReceivedAt), ExpiresAt: formatTime(h.ExpiresAt)}
}

// duplicate answers a send whose ciphertext the box already holds, acked or
// not (its dedupe record): the same sender's retry gets the original
// receipt, and another sender a conflict, which claims no delivery.
func (s *Server) duplicate(w http.ResponseWriter, orig *Header, from protocol.Address) error {
	if orig.From != from {
		return fail(protocol.CodeConflict, "", "this ciphertext was already sent by another box")
	}
	writeJSON(w, http.StatusOK, receipt(orig))
	return nil
}

// checkStanzas requires exactly one native stanza, of the current prekey's
// type, beside grease, the stanzas sorted by protocol.ReadStanzas, the one
// reading of them a reader shares, which refuses before any key agreement
// a file a server takes no send of (PROTOCOL.md §11.10 step 7, §12.3 check 1). A
// send names the current serial, so no retired prekey is live. Which KEY it
// is encrypted to cannot be checked, by design of native age. Each case has
// its own hint, in this order: a stanza of another type, none native, more
// than one, then the type.
func checkStanzas(st protocol.Stanzas, b *Box) *problem {
	switch {
	case st.Other:
		return fail(protocol.CodeWrongRecipientType, "encrypt to the box's prekey", "the file has a stanza of a type no prekey has")
	case len(st.Native) == 0:
		return fail(protocol.CodeWrongRecipientType, "the file has no recipient: encrypt to the box's prekey", "the file has no native stanza, only grease")
	case len(st.Native) > 1:
		return fail(protocol.CodeWrongRecipientType, "encrypt to one recipient only", "the file has more than one native stanza")
	case st.Native[0] == b.Prekey.Type():
		return nil
	case b.Prekey.Type() == protocol.PostQuantum:
		return fail(protocol.CodeWrongRecipientType, "this box needs age >= 1.3 or age-plugin-pq", "this box is post-quantum and the file is X25519 only")
	}
	return fail(protocol.CodeWrongRecipientType, "this box is --no-pq (X25519 only): re-fetch its prekey", "this box is --no-pq (X25519 only) and the file is post-quantum")
}
