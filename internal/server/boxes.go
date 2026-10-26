package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// registerLimit bounds a registration or prekey body: a post-quantum prekey
// statement is ~2 KB, so this is generous.
const registerLimit = 64 << 10

// hintDocument is what to do about an identity document the server does not
// take as one.
const hintDocument = "the identity document is \"dromas-v1\", LF, one SSH public key with no comment, LF: look for a comment, CRLF or a missing final newline"

// register is PUT /v1/<address> (PROTOCOL.md §11.7). It is a call of a box that
// does not exist yet, so its address pays for it: its body is read only once
// the call has spent one of its address's flood budget at the gate, as a
// revocation's is.
//
// Registration never changes a box, so what is kept of the address is read
// before any signature, and a box registered there, or an address revoked,
// is answered from it, held in memory or read, by one path (registered),
// spending none of the address's registrations (PROTOCOL.md §11.4, the order
// of refusals; dromas-dev/dromas-client#410), but for one that found nothing
// at its read and meets a box at its write (ErrExists), one an identical
// registration made meanwhile among them: it kept its counts before its
// signatures, and is answered as registered with them spent (registered's
// bounded; dromas-dev/dromas-client#443). Memory answers with
// nothing counted. A read is counted once, as what it turns out to be: the
// registrations it would spend, the address's and its /48's, are reserved
// before it, given back if it finds a box or a revocation, and kept if it
// finds nothing, when they bound the statement's signatures and the pass
// that follow. Where they are spent, the read is a lookup's, a miss of the
// caller's address reserved for it (lookup): nothing found is refused for
// the registrations, its miss kept, and a read the misses refuse is refused
// for them.
//
// A registration is held to what is kept of the address, box or none: 410
// while the address is revoked, and nothing under a certificate its identity
// revoked.
func (s *Server) register(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.RegisterRequest
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("identity", req.Identity, "prekey", req.Prekey, "prekey_signature", req.PrekeySignature); err != nil {
		return err
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != h {
		return fail(protocol.CodeIdentityMismatch, hintDocument, "the identity document does not hash to the address")
	}
	// The document's form, then its key's type, then its key (PROTOCOL.md §11.7).
	// A well-formed document of a type the protocol does not define, or that
	// this server does not register, is neither malformed nor a bad key.
	id, err := protocol.ParseIdentity(req.Identity)
	switch {
	case errors.Is(err, protocol.ErrIdentityFormat):
		return failErr(protocol.CodeIdentityMismatch, hintDocument, err)
	case errors.Is(err, protocol.ErrIdentityType), err == nil && !slices.Contains(s.identityTypes, id.Type()):
		return fail(protocol.CodeUnsupportedKeyType, "make a box whose identity is an ssh-ed25519 key, as dromas init does unless told otherwise",
			"this server registers identities of these key types: %s", keyTypesValue(s.identityTypes))
	case err != nil:
		return failErr(protocol.CodeBadKey, "make a new identity: dromas init in a new box", err)
	}
	// A box registered, or an address its identity revoked, is answered from
	// what is kept of the address, whatever the statement and however many
	// registrations the address has spent (PROTOCOL.md §11.4, the order of
	// refusals): from memory, with nothing counted, or from one read.
	cur, known := s.store.Known(h)
	if known && settled(cur) {
		return s.registered(w, r, id, cur, &req, false)
	}
	// The read is counted as what it turns out to be: under the
	// registrations it would spend, reserved before it, given back if it
	// finds a box or a revocation and kept if it finds nothing (LIMITS.md
	// rule 4). Where they are spent it is a lookup's, under a miss, and only
	// a box or a revocation it finds answers: nothing found is refused for
	// the registrations, and its miss is kept.
	g, refused := s.reserveRegistration(r, "")
	if refused != nil {
		read, err := s.lookup(r, h)
		switch {
		case err != nil:
			return err
		case settled(read):
			return s.registered(w, r, id, read, &req, false)
		}
		return refused
	}
	defer func() { g.release(s.now()) }() // settled below, but for a panic
	cur, err = s.box(r.Context(), h)
	if err != nil {
		return err
	}
	if settled(cur) {
		g.release(s.now())
		return s.registered(w, r, id, cur, &req, false)
	}
	// A registration that would make a box: the counts kept here bound the
	// signatures and the pass that follow, which reserve no miss of their own.
	g.keep()
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	if cur != nil { // an address with no box whose identity revoked certificates
		if listed, err := cur.listed(cert.Serial()); err != nil {
			return err
		} else if listed {
			return fail(protocol.CodeCertificateRevoked, "certify a new working key at a higher serial: dromas prekey renew", "the statement is signed under a certificate this address's identity revoked")
		}
	}
	// The pass, under the certificate the statement is signed under: the
	// certificate shows the identity chose this working key, and a pass
	// minutes old that its holder is here now.
	if err := s.checkPassBounded(r, h, string(id.PublicKey().Marshal()), certHash(cert), cert.Serial()); err != nil {
		return err
	}
	// No box is registered here: an If-Match is false, and If-None-Match: *
	// holds (precondition). The write holds it, a record created only where
	// the address has none: one registered meanwhile answers from its
	// record, below, where If-None-Match: * is false.
	if err := precondition(r, targetState{hint: hintConditions}); err != nil {
		return err
	}
	now := s.now()
	b := &Box{
		Addr:           h,
		Identity:       req.Identity,
		State:          Active,
		Statement:      req.Prekey,
		Signature:      req.PrekeySignature,
		Prekey:         p,
		CertSerial:     cert.Serial(),
		Cert:           certHash(cert),
		SenderKeyTypes: declared(req.SenderKeyTypes),
		Created:        now,
		Expires:        expiry(p, cert),
	}
	if cur != nil { // an address whose identity revoked certificates: what it revoked is kept with the box
		b.RevokedCerts, b.RevokedCertsSig = cur.RevokedCerts, cur.RevokedCertsSig
	}
	err = s.store.CreateBox(detached(r.Context()), b)
	if err == nil {
		writeJSON(w, http.StatusCreated, struct{}{})
		return nil
	}
	// The address has a record, or may have one this write made, whose
	// outcome is unknown: the record answers, as for a box registered
	// before (dromas-dev/dromas-client#411 item 2), and no count of the
	// client's retry depends on the write.
	exists := errors.Is(err, ErrExists)
	if !exists && !mayHaveApplied(err) {
		return err
	}
	read, rerr := s.box(r.Context(), h)
	switch {
	case rerr != nil:
		return rerr
	case settled(read):
		return s.registered(w, r, id, read, &req, true)
	case !exists:
		return err // the record does not hold it: its client sends it again
	}
	busy := fail(protocol.CodeUnavailable, "retry", "this box is being registered") // a read that does not see the record yet
	busy.retryAfter = time.Second
	return busy
}

// statementRevoked is the answer to a prekey statement signed under a
// certificate the box's identity revoked (PROTOCOL.md §10.2).
func statementRevoked() *problem {
	return fail(protocol.CodeCertificateRevoked, "certify a new working key at a higher serial: dromas prekey renew", "the statement is signed under a certificate this box's identity revoked")
}

// settled reports whether what is held of an address answers a registration
// from itself: a box that is registered, or an address that is revoked.
func settled(b *Box) bool { return b.open() || b != nil && b.State == Revoked }

// registered answers a registration of a box that is registered, or of an
// address that is revoked, from its record: registration never changes it.
// An identical retry is answered 200 once its pass, under the box's current
// certificate, is checked; nothing else is. A certificate the identity
// revoked signs nothing this server takes, the box's current statement sent
// again included, so it is refused before the pass, as a prekey upload's
// identical retry is (PROTOCOL.md §10.2).
//
// A registration answered from what is kept of its address, held in memory
// or read, spends no registrations count, so the retry is a renewal's
// identical retry in all but its route: a miss is reserved before its pass
// (checkPass), and the box's calls are spent once it passes. bounded is true
// for the one registration that meets a box at its write, registered by
// another request meanwhile or by its own write whose outcome is unknown:
// its registrations counts were taken, and they bound the pass's check
// (checkPassBounded), which its own statement's pass has passed already
// where the box is the one it sent.
func (s *Server) registered(w http.ResponseWriter, r *http.Request, id *protocol.Identity, cur *Box, req *protocol.RegisterRequest, bounded bool) error {
	switch {
	case cur.State == Revoked:
		return revokedWith(cur)
	case !bytes.Equal(cur.Identity, req.Identity) || !bytes.Equal(cur.Statement, req.Prekey) || !bytes.Equal(cur.Signature, req.PrekeySignature):
		return fail(protocol.CodeConflict, "registered: to replace its prekey, dromas prekey renew", "this address is registered with another prekey")
	}
	if listed, err := cur.listed(cur.CertSerial); err != nil {
		return err
	} else if listed {
		return statementRevoked()
	}
	key := string(id.PublicKey().Marshal())
	if bounded {
		if err := s.checkPassBounded(r, cur.Addr, key, cur.Cert, cur.CertSerial); err != nil {
			return err
		}
	} else {
		if err := s.checkPass(r, cur.Addr, key, cur.Cert, cur.CertSerial, nil); err != nil {
			return err
		}
		// The box's calls, with whatever its account lifts, read from the
		// record this answers from: the address is read no second time.
		lim, err := s.limitsFor(r.Context(), cur)
		if err != nil {
			return err
		}
		if err := s.spendCall(cur.Addr, lim); err != nil {
			return err
		}
	}
	if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, struct{}{}) // an identical retry
	return nil
}

// take makes p, under cert, box b's current prekey statement (PROTOCOL.md
// §11.9): a key the box published before, its current one or a live retired
// one, is refused; the statement it replaces retires while it is live, and
// only the newest retired are kept. The record's expiry moves to when
// nothing of the new statement is valid.
func (s *Server) take(b *Box, statement, sig []byte, p *protocol.Prekey, cert *protocol.Certificate, senders []string, now time.Time) error {
	keyHash := sha256.Sum256([]byte(p.Key))
	retired := slices.DeleteFunc(b.Retired, func(x Retired) bool { return !now.Before(x.NotAfter) })
	if keyHash == sha256.Sum256([]byte(b.Prekey.Key)) || slices.ContainsFunc(retired, func(x Retired) bool { return x.KeyHash == keyHash }) {
		return fail(protocol.CodePrekeyNotNew, "every prekey must be a NEW key: dromas prekey renew makes one", "this key was already published")
	}
	if now.Before(b.Prekey.NotAfter) {
		retired = append(retired, Retired{Type: b.Prekey.Type(), NotAfter: b.Prekey.NotAfter, KeyHash: sha256.Sum256([]byte(b.Prekey.Key))})
	}
	if n := s.limits.RetiredKept; n > 0 && len(retired) > n {
		retired = retired[len(retired)-n:]
	}
	b.Retired = retired
	b.Statement, b.Signature, b.Prekey = statement, sig, p
	b.CertSerial, b.Cert = cert.Serial(), certHash(cert)
	b.SenderKeyTypes = declared(senders) // the declaration that comes with this prekey, in place of the one before
	b.Expires = expiry(p, cert)
	return nil
}

// checkPrekey verifies a prekey statement: signed by a working key under a
// certificate of the identity that is valid now and began at least
// protocol.PassLifetime before now, and one that could be published now, not
// expired and ending at most protocol.MaxPrekeyLifetime from now, which is an
// hour past what a client asks for. It returns the certificate too.
//
// A certificate is taken only once it has begun by the clock of every box
// this server takes, and so of every reader of the mail signed under it: a
// box whose clock is less than PassLifetime behind this one (PROTOCOL.md §15.7).
// A client dates a certificate from MaxSkew before it makes it, so one made
// by a clock this server takes a pass from has always begun that long.
//
// A refusal for a time states what this clock reads: a client makes its
// certificate and its statement with an hour of room (PROTOCOL.md §3.4), so
// one of these is nearly always the caller's clock, and a new statement
// signed by the same clock would be refused the same way.
func (s *Server) checkPrekey(id *protocol.Identity, statement, sig []byte) (*protocol.Prekey, *protocol.Certificate, error) {
	const (
		check   = ": check it, then dromas init for a new box, dromas prekey renew for one in use"
		early   = "a certificate starts an hour before it is made, and a server takes one once it has begun for every box it takes, 10 minutes before its own clock, so this machine's clock reads more than 50 minutes ahead of the server's" + check
		tooLong = "a client signs a prekey for 33 days, so this machine's clock reads more than an hour ahead of the server's" + check
	)
	p, cert, err := protocol.VerifyPrekey(id, statement, sig, s.now())
	if err == nil {
		if began, berr := protocol.CertificateBegan(sig); berr != nil || began.After(s.now().Add(-protocol.PassLifetime)) {
			err = protocol.ErrCertificateNotBegun
		}
	}
	switch {
	case errors.Is(err, protocol.ErrCertificateNotBegun):
		return nil, nil, failErr(protocol.CodePrekeyTime, early, err)
	case errors.Is(err, protocol.ErrCertificateTime):
		return nil, nil, failErr(protocol.CodePrekeyTime, "sign a new prekey statement: dromas prekey renew", err)
	case err != nil:
		return nil, nil, failErr(protocol.CodeBadKey, "sign a new prekey statement: dromas prekey renew", err)
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		if p.Expired(s.now()) {
			return nil, nil, failErr(protocol.CodePrekeyTime, "sign a new prekey statement: dromas prekey renew", err)
		}
		return nil, nil, failErr(protocol.CodePrekeyTime, tooLong, err)
	}
	return p, cert, nil
}

// prekey is PUT /v1/<address>/prekey (PROTOCOL.md §11.9). The authority is a
// statement ordered after the current one, signed under a certificate of the
// identity, with a pass under that same certificate: no pass under the box's
// current one is needed, which is how a box that lost its working key comes
// back.
//
// A box's statements are ordered by their certificate's serial first and by
// their own serial second (PROTOCOL.md §5). So a prekey published at the
// highest serial there is, by whoever took a working key, holds nothing: the
// box's next certificate passes it.
//
// What could not be taken even if it verified is refused before any
// signature is checked: the statement's place in that order is read from it
// unverified (protocol.PrekeyOrder), and a statement the box holds already is
// answered from its record.
//
// The pass is read only after the body, so until then the call is its
// address's: it spends the address's flood budget at the gate, whatever it
// carries, as a registration and a revocation do, and none of the box's
// budgets until its pass is checked.
func (s *Server) prekey(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.PrekeyRequest
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("prekey", req.Prekey, "prekey_signature", req.PrekeySignature); err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b != nil && b.State == Revoked:
		return revokedWith(b)
	case !b.open(): // a box the server forgot comes back by a registration (PROTOCOL.md §12.4)
		return noSuchMailbox
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		return err
	}
	key := string(id.PublicKey().Marshal())
	refusedRevoked := statementRevoked()
	// An identical retry: it was verified when it was stored, so only its
	// pass is checked, and nothing changes. A certificate the identity has
	// revoked signs nothing this server takes, the box's current statement
	// sent again included (PROTOCOL.md §10.2).
	if bytes.Equal(req.Prekey, b.Statement) && bytes.Equal(req.PrekeySignature, b.Signature) {
		if listed, err := b.listed(b.CertSerial); err != nil {
			return err
		} else if listed {
			return refusedRevoked
		}
		if err := s.checkPass(r, h, key, b.Cert, b.CertSerial, nil); err != nil {
			return err
		}
		if err := s.spendOwner(r.Context(), h); err != nil {
			return err
		}
		if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, struct{}{})
		return nil
	}
	// Where it would stand, read before anything is verified. The box moves
	// to a later certificate, at any prekey serial, or stays under its
	// current one at a higher serial: never back to an older certificate,
	// never to another of the same serial, and never to one its identity
	// has revoked.
	o, err := protocol.PrekeyOrder(req.Prekey, req.PrekeySignature)
	if err != nil {
		if err := s.failed(r); err != nil {
			return err
		}
		return failErr(protocol.CodeBadKey, "sign a new prekey statement: dromas prekey renew", err)
	}
	if listed, err := b.listed(o.CertSerial); err != nil {
		return err
	} else if listed {
		return refusedRevoked
	}
	if o.CertSerial < b.CertSerial || (o.CertSerial == b.CertSerial && o.Cert != b.Cert) {
		return fail(protocol.CodeCertificateNotCurrent, "certify a new working key at a higher serial: dromas prekey renew", "the certificate's serial must be above %d, or the certificate be the box's current one", certificateSerialValue(b.CertSerial))
	}
	if o.CertSerial == b.CertSerial && o.Serial <= b.Prekey.Serial {
		return fail(protocol.CodeConflict, "a newer prekey is already published: dromas prekey renew takes the next serial", "under the box's current certificate the serial must be above %d", prekeySerialValue(b.Prekey.Serial))
	}
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	defer func() { m.release(s.now()) }() // settled below, but for a panic
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err == nil && (cert.Serial() != o.CertSerial || certHash(cert) != o.Cert || p.Serial != o.Serial) {
		err = fail(protocol.CodeBadKey, "sign a new prekey statement: dromas prekey renew", "the statement does not read the same verified as unverified")
	}
	if err != nil {
		m.keep()
		return err
	}
	m.release(s.now())
	under := certHash(cert)
	if err := s.checkPass(r, h, key, under, cert.Serial(), nil); err != nil {
		return err
	}
	// A renewal under the box's current certificate counts against the
	// box's renewals; one under a later certificate is its identity's act,
	// counted apart, so whoever holds the current working key and spends the
	// renewals does not hold back the identity's. The count is read with the
	// box's calls, so a refusal of either gives the longer wait (longest).
	// One while the box's current certificate is revoked spends none of the
	// box's counts, its calls among them: it replaces what the identity
	// revoked, each raise of which is counted (revoke), and whoever held the
	// taken working key may have spent the calls before the raise (#84). It
	// was counted at the gate, against its address's flood budget, as every
	// renewal is. Let's Encrypt exempts more renewals than this, from every
	// limit: why ours differs is PRECEDENTS.md in the client repo.
	var count []perDay
	replaces := false
	switch {
	case cert.Serial() == b.CertSerial:
		count = []perDay{s.renewalsADay()}
	default:
		if replaces, err = b.listed(b.CertSerial); err != nil {
			return err
		} else if !replaces {
			count = []perDay{s.certificatesADay()}
		}
	}
	if !replaces {
		if err := s.spendOwner(r.Context(), h, count...); err != nil {
			return err
		}
	}
	// The write holds what an If-Match held, the record at the rev read.
	if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
		return err
	}
	now := s.now()
	var counted *reservation // nil, so kept and given back as nothing, when the renewal is not counted
	if len(count) > 0 {
		var ok bool
		var wait time.Duration
		if counted, ok, wait = count[0].bs.reserve(r.Context(), h.String(), s.now); !ok {
			return count[0].refusal(wait)
		}
	}
	stored := false // or may have been: the count is kept then (mayHaveApplied)
	defer func() {
		if stored {
			counted.keep()
		} else {
			counted.release(s.now())
		}
	}()
	if err := s.take(b, req.Prekey, req.PrekeySignature, p, cert, req.SenderKeyTypes, now); err != nil {
		return err
	}
	if err := s.store.UpdateBox(detached(r.Context()), b); err != nil {
		stored = mayHaveApplied(err)
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeBoxChanged, "retry: dromas prekey renew", "the box changed during the request")
		}
		return err
	}
	stored = true
	writeJSON(w, http.StatusOK, struct{}{})
	return nil
}

// getBox is GET /v1/<address>, the one read of a box: everything a sender
// needs before it posts, which is the identity document, the current prekey
// statement with its signature, the key types the box declared with it, and
// the revocation of its certificates held (PROTOCOL.md §11.8). A revoked
// address is 410 with its record, which proves itself: a client takes
// "revoked" on nothing less, and needs no second call for it. An address
// with no box is 404, whatever its identity revoked of its certificates.
// It takes no pass: it is public, and the gate counts it by the address it
// comes from, whatever Authorization it carries, which nothing here reads
// (PROTOCOL.md §11.8, §11.5; dromas-dev/dromas-client#352). It is the one
// answer of the API that is gzipped, to a request that takes it.
func (s *Server) getBox(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b != nil && b.State == Revoked:
		return revokedWith(b)
	case !b.open():
		return noSuchMailbox
	}
	if err := precondition(r, targetState{exists: true, hint: hintConditions, also: []string{"Vary", "Accept-Encoding"}}); err != nil {
		return err
	}
	writeJSONCompressed(w, r, protocol.BoxResponse{
		Identity: b.Identity, Prekey: b.Statement, PrekeySignature: b.Signature, SenderKeyTypes: b.SenderKeyTypes,
		RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig,
	})
	return nil
}

// getRevocations is GET /v1/<address>/revocations (PROTOCOL.md §11.15): the
// record this server holds of the address, with a box here or none, or 404
// not_revoked. A box learns the same of the boxes it writes to from their read
// (getBox); this route is for its own, where this server holds no box for it.
// It takes no pass, as the PUT beside it takes none.
func (s *Server) getRevocations(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case !b.holdsRevocations():
		return fail(protocol.CodeNotRevoked, "nothing to do: this server holds no revocation of that address. That is its word, and the box's owner may hold a record of one", "no revocation of this address is held here")
	}
	if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, b.record())
	return nil
}

// What to do about a body that is not a revocation of the address, or not
// one of its certificates.
const (
	hintRevocation   = "a revocation is the identity key's own signature over its fixed statement, with the identity document: dromas revocation make prints the record"
	hintRevokedCerts = "a revocation of certificates is signed by the identity key itself, and sent with the identity document: dromas cert revoke-earlier makes and publishes one"
)

// revoke is PUT /v1/<address>/revocations: the identity document with what
// the identity itself has signed about the address. No pass: a working key
// can be stolen without the identity and must not be able to end the address
// or to revoke a certificate, and an owner who lost the box holds no working
// key at all. The signature is the whole authority, and it may have been made
// long ago. So the call is its address's to pay for, as every call with no
// pass is.
//
// What is revoked is kept with or without a box, in the address's
// revocations item, for good: for a box that is registered, swept by the
// TTL or never registered. Keeping it for an address this server
// holds nothing of is a record kept for good, so that one is counted as a
// registration is, against its caller's address.
//
// A revocation of the address (PROTOCOL.md §11.15): the address is revoked
// for good, its box's mail and record are deleted, and the signature is kept
// and served (revocations).
//
// A revocation of certificates (PROTOCOL.md §10.2): the address goes on.
// It revokes every certificate through a serial, and the highest stands: one
// through a lower serial than the one held is refused, and the same one again
// changes nothing. From then on no pass and no prekey statement under a
// revoked certificate is taken, and nobody is told to encrypt to a prekey
// under one. A raise of it is the identity's act, counted per box on its own
// (Limits.CertificateRevocationsPerDay), so no renewal holds it back; the
// renewal that replaces the certificate it revokes is then not counted
// (prekey). The revocation of the address is counted against no box.
//
// A body may carry both. What could change nothing is answered from the
// record before any signature is checked: anything for a box already
// revoked, and a revocation of certificates through a serial no higher than
// the one held. Both kinds of statement are public, and more than one set of
// bytes verifies for each, so one sent back must cost no signature check.
// Everything else in the body is checked before anything is changed, and a
// check that fails counts against the caller's address (s.miss).
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.Revocations
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("identity", req.Identity); err != nil {
		return err
	}
	hasCerts := req.RevokedCertificates != nil || req.RevokedCertificatesSignature != nil
	if hasCerts {
		err = required("revoked_certificates", req.RevokedCertificates, "revoked_certificates_signature", req.RevokedCertificatesSignature)
	} else {
		err = required("revocation_signature", req.Revocation)
	}
	if err != nil {
		return err
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != h {
		return fail(protocol.CodeIdentityMismatch, hintDocument, "the identity document does not hash to the address")
	}
	b, err := s.lookup(r, h)
	if err != nil {
		return err
	}
	// A revoked address takes nothing more: it is ended, and that says which
	// of its certificates still stand. Its box's mail and record are deleted
	// again while memory shows them, as they are when the first delete
	// failed: a revocation sent back must not draw a read of the messages
	// table each time.
	if b != nil && b.State == Revoked {
		if err := s.deleteHeld(detached(r.Context()), b); err != nil {
			return err
		}
		return revokedWith(b)
	}
	var held *protocol.RevokedCertificates
	if b != nil && len(b.RevokedCerts) > 0 {
		if held, err = protocol.ParseRevokedCertificates(b.RevokedCerts); err != nil {
			return fmt.Errorf("the stored revocation of certificates: %w", err)
		}
	}
	// A revocation of certificates that reaches no higher than the one held
	// changes nothing, whether or not it verifies: read before it is checked.
	if hasCerts && held != nil {
		if f, err := protocol.ParseRevokedCertificates(req.RevokedCertificates); err == nil && f.Address == h && f.Through <= held.Through {
			switch {
			case req.Revocation != nil:
				hasCerts = false // the revocation of the address is the body's one change
			case f.Through == held.Through:
				if err := precondition(r, targetState{exists: true, hint: hintConditions}); err != nil {
					return err
				}
				writeJSON(w, http.StatusOK, struct{}{})
				return nil
			default:
				return fail(protocol.CodeConflict, "GET the same path for the one held: it covers every certificate yours does", "a revocation of this address's certificates through serial %d is held, and nothing revokes fewer", throughValue(held.Through))
			}
		}
	}
	// What is held of the address is known here, before the counts and the
	// signatures: the revocations GET …/revocations would answer, or none.
	// The write holds what they held of it (expected).
	if err := precondition(r, targetState{exists: b.holdsRevocations(), hint: hintConditions}); err != nil {
		return err
	}
	if b == nil {
		if err := s.spendRegistration(r, ": keeping a revocation of an address this server holds nothing of is counted as one"); err != nil {
			return err
		}
	}
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	defer func() { m.release(s.now()) }() // settled below, but for a panic
	var certs *protocol.RevokedCertificates
	if hasCerts {
		if certs, err = protocol.VerifyRevokedCertificates(h, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature); err != nil {
			m.keep()
			return fail(protocol.CodeBadRevocation, hintRevokedCerts, "this is not a revocation of this address's certificates")
		}
	}
	if req.Revocation != nil {
		if _, err := protocol.VerifyRevocation(h, req.Identity, req.Revocation); err != nil {
			m.keep()
			return fail(protocol.CodeBadRevocation, hintRevocation, "this is not a revocation of this address")
		}
	}
	m.release(s.now())
	rv := &Revocations{Identity: req.Identity}
	status, raised := http.StatusOK, false
	if certs != nil && (held == nil || certs.Through > held.Through) {
		rv.Certs, rv.CertsSig, rv.Through, raised = req.RevokedCertificates, req.RevokedCertificatesSignature, certs.Through, true
	}
	var raise *reservation // nil, so kept and given back as nothing, unless a raise alone is counted
	if req.Revocation != nil {
		rv.Address, status = req.Revocation, http.StatusCreated
	} else if raised {
		var ok bool
		var wait time.Duration
		if raise, ok, wait = s.raises.reserve(r.Context(), h.String(), s.now); !ok {
			return s.raisesADay().refusal(wait)
		}
	}
	defer func() { raise.release(s.now()) }() // settled below, but for a panic
	if raised || req.Revocation != nil {
		if err := s.store.Revoke(detached(r.Context()), h, rv, expected(r)); err != nil {
			if mayHaveApplied(err) {
				raise.keep()
			} else {
				raise.release(s.now())
			}
			if errors.Is(err, ErrStale) {
				return fail(protocol.CodeBoxChanged, "retry", "the box changed during the request")
			}
			return err
		}
		raise.keep()
	}
	// Once the address is revoked: mail that arrived around the write is
	// never served, this deletes it sooner than its expiry would, and then
	// the box's record goes.
	if req.Revocation != nil && b.hasRecord() {
		if err := s.purge(detached(r.Context()), b); err != nil {
			return err
		}
	}
	writeJSON(w, status, struct{}{})
	return nil
}

// deleteHeld deletes what is left of revoked address b's box where memory
// holds the address (Store.Held), while memory shows the box holding mail or
// a record is left beside the revocation, by a delete that failed or a
// registration that raced it: by the one purge of the address in flight
// (purge). Its caller carries no pass, so elsewhere it
// loads nothing and changes nothing, and what is left waits for its expiry,
// served to nobody (ARCHITECTURE.md § Startup). The record stays there too:
// a load reads an address's mail only while its record is left, so deleting
// it would leave the mail where no process looks for it.
func (s *Server) deleteHeld(ctx context.Context, b *Box) error {
	if _, held := s.store.Held(b.Addr); !held {
		return nil
	}
	if n, err := s.store.Count(ctx, b.Addr); err != nil {
		return err
	} else if n == 0 && !b.hasRecord() {
		return nil
	}
	return s.purge(ctx, b)
}

// purge deletes what is left of revoked address b's box: its mail, then its
// record if one is left. One purge of an address is in flight at a time, on
// a context apart from any one request, and a call that comes meanwhile
// waits for it and gets its result, starting nothing
// (dromas-dev/dromas-server#29): a revocation sent for a revoked box
// carries no pass and costs no signature check, so anyone can send one, and
// each would otherwise start a whole delete of the box's mail of its own.
func (s *Server) purge(ctx context.Context, b *Box) error {
	_, err, _ := s.purges.Do(string(b.Addr[:]), func() (any, error) {
		ctx := context.WithoutCancel(ctx)
		if err := s.store.DeleteMessages(ctx, b.Addr); err != nil {
			return nil, err
		}
		if b.hasRecord() {
			return nil, s.store.DeleteBox(ctx, b.Addr)
		}
		return nil, nil
	})
	return err
}
