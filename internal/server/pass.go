package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A mailbox proves itself with a pass it signs for itself (PROTOCOL.md §8),
// by its identity, which is always taken, or by a working key under exactly
// the certificate of its current statement. The server issues nothing and
// stores nothing for it. A pass is checked in
// three steps, cheapest first: the signing key it carries against the hash
// of the mailbox's current signer's and of its identity's, which costs no
// signature check; the
// signature on the pass; and then the signer itself against the identity on
// record: for a certificate, the identity's signature on it, with every rule
// of a certificate, as when it was put on record, and for the identity, its
// key byte for byte. So a pass that is not the mailbox's costs at most one
// signature check to refuse, and one under a certificate costs two. A pass
// that passed is remembered until it runs out, and every later call that
// carries it is a lookup in memory.

// seenPass is a pass this process checked: the hash of its Authorization
// value in the one form a client writes it (Pass.Authorization) and in the
// form it was shown in, the signer it is signed by, and until when it is
// taken: the moment it runs out or its signer's certificate ends, whichever
// comes first.
type seenPass struct {
	sum    [32]byte
	raw    [32]byte
	signer [32]byte
	until  time.Time
}

// passes remembers, for each mailbox, the pass it showed last, and each such
// pass's two hashes with its mailbox, for the gate, which knows the pass only by
// its hash (known). An entry goes when its pass has run out, which is at
// most protocol.MaxPassLifetime after it was checked, so the maps hold only
// mailboxes that called within that time.
type passes struct {
	mu    sync.Mutex
	seen  map[protocol.Address]seenPass
	sums  map[[32]byte]knownPass // each seenPass's sum and raw
	sweep time.Time              // when prune next runs
}

// knownPass is whose a checked pass is, and until when it is taken.
type knownPass struct {
	mailbox protocol.Address
	until   time.Time
}

func newPasses() *passes {
	return &passes{seen: map[protocol.Address]seenPass{}, sums: map[[32]byte]knownPass{}}
}

// has reports whether the Authorization value hashing to sum is the pass mailbox
// a showed last, in either form, checked as signed by the signer whose hash is
// signer and not run out at now.
func (ps *passes) has(a protocol.Address, sum, signer [32]byte, now time.Time) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.seen[a]
	return ok && (p.sum == sum || p.raw == sum) && p.signer == signer && now.Before(p.until)
}

// known returns the mailbox whose pass the Authorization value hashing to sum
// is, in either form, if it is the pass that mailbox showed last and it has not
// run out at now.
func (ps *passes) known(sum [32]byte, now time.Time) (protocol.Address, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	k, ok := ps.sums[sum]
	if !ok || !now.Before(k.until) {
		return protocol.Address{}, false
	}
	return k.mailbox, true
}

// keep remembers a pass of mailbox a that was checked at now, in place of the
// one it showed before.
func (ps *passes) keep(a protocol.Address, p seenPass, now time.Time) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if !now.Before(ps.sweep) {
		for k, v := range ps.seen {
			if !now.Before(v.until) {
				ps.forget(k, v)
			}
		}
		ps.sweep = now.Add(protocol.MaxPassLifetime)
	}
	if old, ok := ps.seen[a]; ok {
		ps.forget(a, old)
	}
	ps.seen[a] = p
	ps.sums[p.sum], ps.sums[p.raw] = knownPass{a, p.until}, knownPass{a, p.until}
}

// forget drops mailbox a's pass p. The caller holds mu.
func (ps *passes) forget(a protocol.Address, p seenPass) {
	delete(ps.seen, a)
	delete(ps.sums, p.sum)
	delete(ps.sums, p.raw)
}

// standingOf returns what checking mailbox a's pass needs: from memory when this
// process holds the mailbox, so that a poll never leaves it, and otherwise from
// what is held of the address (lookup), which it returns as b. ok is false
// for an address with no mailbox.
func (s *Server) standingOf(r *http.Request, a protocol.Address) (st Standing, b *Mailbox, ok bool, err error) {
	if st, ok := s.store.Held(a); ok {
		return st, nil, true, nil
	}
	if b, err = s.lookup(r, a); err != nil || b == nil {
		return Standing{}, nil, false, err
	}
	st, ok, err = b.standing()
	return st, b, ok, err
}

// revokedAt is revoked for a call about revoked address a, which carries
// the record where it is at hand: in b, what standingOf read, or in memory
// (Known). A standing in memory alone holds no record, and a call that has
// shown no pass is never made to read one, so that a poll never leaves the
// process: then the answer carries none, and its client reads the mailbox
// (PROTOCOL.md §12.5).
func (s *Server) revokedAt(a protocol.Address, b *Mailbox) *problem {
	if b == nil {
		b, _ = s.store.Known(a)
	}
	if b == nil || b.State != Revoked {
		return revoked()
	}
	return revokedWith(b)
}

// serverName is the name the caller called this server by, if it is one of
// the server's own: the request's Host, lowercase, written as an origin is
// (PROTOCOL.md §8), with its port as a number and none at all when it is
// 443 or 80, either default taken as left unwritten, so that checking a pass
// never rests on which scheme a request came by: a server may learn that
// only from a forwarded header, and an authentication check does not hang
// on one. A client that calls https on port 80, or http on 443, names a port
// this drops, and its pass is refused. A pass names the server it was made for,
// and the name is not sent with it: checked against a name that is not ours,
// a pass made for another server would pass here.
func (s *Server) serverName(r *http.Request) (string, bool) {
	name := protocol.LowerASCII(r.Host)
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, ']') {
		switch n, err := strconv.ParseUint(name[i+1:], 10, 16); {
		case i == len(name)-1, err == nil && (n == 443 || n == 80):
			name = name[:i]
		case err == nil:
			name = name[:i+1] + strconv.FormatUint(n, 10)
		}
	}
	return name, len(s.names) == 0 || slices.Contains(s.names, name)
}

// authorization returns the call's Authorization value, "" when it has none.
// one is false for a call with two lines or more: which of them is the
// pass is not for the server to choose, so such a call carries no pass and
// is refused as one that is not a pass is.
func authorization(r *http.Request) (auth string, one bool) {
	switch v := r.Header.Values("Authorization"); len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], true
	}
	return "", false
}

func unauthorized(hint, detail string) *problem {
	return fail(protocol.CodeUnauthorized, hint, detail)
}

// listedCertificate refuses a pass of a mailbox whose current certificate its
// identity's revocation of certificates covers (PROTOCOL.md §10.2, §11.4 rule
// 1): no pass under that certificate is taken, nor one under any other but
// the next statement's, and only the identity's pass is, until the mailbox
// publishes a prekey under a certificate above it, which needs no pass under
// the old one.
func listedCertificate() *problem {
	return fail(protocol.CodeCertificateRevoked, "publish a new prekey under a new certificate: dromas prekey renew", "the mailbox's current certificate is one its identity's revocation of certificates covers")
}

// The hints of a 401: what a client does about it.
const (
	hintPass    = "send the mailbox's pass in Authorization, signed by its identity or the signer of its current prekey (dromas and dr_owner do this)" //nolint:gosec // a hint's words, not a credential
	hintNewPass = "sign a new pass and retry once (dromas and dr_owner do this)"                                                       //nolint:gosec // a hint's words, not a credential
)

// checkPass checks that the call carries the pass of mailbox a: made for this
// server, not run out, and signed by the identity, whose key in SSH wire form
// is key, or by the signer whose signing key's hash is signer, of rank rank:
// a working key under a certificate that identity made (PROTOCOL.md §8).
// The identity's pass is always taken. listed is true where the revocation of
// certificates held covers that signer, and then the identity's pass is the
// only one taken. p is the call's pass if the caller parsed it already, and
// otherwise nil.
//
// A pass by another key is certificate_revoked where listed, and otherwise
// certificate_not_current, naming the certificate's serial where the signer
// is one.
//
// A pass this process does not remember costs signature checks, and anyone
// can bring one: so its caller's address reserves a count under
// Limits.MissesPerMinute first, kept if the pass fails and given back if it
// passes (s.miss). One the process remembers is a lookup in memory.
func (s *Server) checkPass(r *http.Request, a protocol.Address, key string, signer [32]byte, rank uint64, listed bool, p *protocol.Pass) error {
	return s.passCheck(r, a, key, signer, rank, listed, p, true)
}

// checkPassBounded is checkPass for a call that a count taken before it
// already bounds, a registration's (Limits.RegistrationsPerHour): its pass
// is checked without a count of its own.
func (s *Server) checkPassBounded(r *http.Request, a protocol.Address, key string, signer [32]byte, rank uint64) error {
	return s.passCheck(r, a, key, signer, rank, false, nil, false)
}

func (s *Server) passCheck(r *http.Request, a protocol.Address, key string, signer [32]byte, rank uint64, listed bool, p *protocol.Pass, count bool) (err error) {
	auth, one := authorization(r)
	if !one || len(auth) > protocol.MaxPassAuthorization {
		if !count {
			return unauthorized(hintPass, "no pass, or not a pass")
		}
		return s.notAPass(r) // two lines, or longer than any pass can be: refused before it is hashed or parsed
	}
	now := s.now()
	sum := sha256.Sum256([]byte(auth))
	identity := sha256.Sum256([]byte(key))
	remembered := func(sum [32]byte) bool {
		return s.passes.has(a, sum, identity, now) || !listed && s.passes.has(a, sum, signer, now)
	}
	if remembered(sum) {
		s.metrics.pass(true, nil)
		return nil
	}
	if p == nil {
		var err error
		if p, err = protocol.ParsePass(auth); err != nil {
			err = unauthorized(hintPass, "no pass, or not a pass")
			if count {
				err = s.notAPass(r)
			}
			s.metrics.pass(false, err)
			return err
		}
	}
	// A pass is remembered in the one form a client writes it, its signature
	// as a verifier reads it, so the same pass written in another form a
	// server reads (PROTOCOL.md §8, §3.2) is answered from memory too, and
	// its many spellings cost one check (dromas-dev/dromas-server#69).
	raw := sum
	if one := sha256.Sum256([]byte(p.Authorization())); one != sum {
		if remembered(one) {
			s.metrics.pass(true, nil)
			return nil
		}
		sum = one
	}
	defer func() { s.metrics.pass(false, err) }()
	if count {
		var m *reservation
		if m, err = s.miss(r); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				m.keep()
			} else {
				m.release(s.now())
			}
		}()
	}
	if p.Address != a {
		return unauthorized(hintPass, "the pass is another mailbox's")
	}
	name, ours := s.serverName(r)
	if !ours {
		return unauthorized("call the server by the name in its URL", "this server does not take a pass made for the name this request names")
	}
	// Run out, or running out too far ahead: either way the mailbox signs another.
	// A new pass cures neither if the caller's clock is off, so each says
	// what this clock reads and which way the caller's is likely wrong.
	if !now.Before(p.NotAfter) {
		return fail(protocol.CodePassExpired, fmt.Sprintf("%s; refused again, this machine's clock reads %d minutes or more behind the server's: check it", hintNewPass, protocol.PassLifetime/time.Minute),
			"the pass has run out")
	}
	if p.NotAfter.After(now.Add(protocol.MaxPassLifetime)) {
		return fail(protocol.CodePassExpired, fmt.Sprintf("%s; refused again, this machine's clock reads more than %d minutes ahead of the server's: check it", hintNewPass, (protocol.MaxPassLifetime-protocol.PassLifetime)/time.Minute),
			fmt.Sprintf("the pass runs out more than %d minutes from now", protocol.MaxPassLifetime/time.Minute))
	}
	// The signing key's hash, then the signature: what refuses a pass that
	// is not the mailbox's, for one signature check at most. The pass is held
	// to the one key its signature names (protocol.Pass.VerifyUnder): the
	// signer's, unless the revocation held covers it, else the identity's.
	by := identity
	err = protocol.ErrCertificate
	var under ssh.PublicKey
	if !listed && signer != identity {
		by = signer
		under, err = p.VerifyUnder(signer, name, now)
	}
	if errors.Is(err, protocol.ErrCertificate) {
		by = identity
		under, err = p.VerifyUnder(identity, name, now)
	}
	switch {
	case errors.Is(err, protocol.ErrCertificate):
		return otherSigner(rank, listed)
	case errors.Is(err, protocol.ErrCertificateNotBegun):
		return fail(protocol.CodePassExpired, "a certificate starts an hour before it is made: check this machine's clock, then dromas prekey renew", "the certificate the pass is signed under has not begun")
	case errors.Is(err, protocol.ErrCertificateTime):
		return fail(protocol.CodePassExpired, "publish a new prekey, which comes with a new certificate: dromas prekey renew", "the certificate the pass is signed under has ended")
	case err != nil:
		return unauthorized(hintNewPass, "the pass is not this mailbox's for this server")
	}
	// Then the signer itself, against the mailbox's identity, as when it was
	// put on record: a certificate by the identity's signature and every rule
	// of a certificate, the identity by its key, byte for byte. It is a
	// second check of what was checked then, and it is reached only by a pass
	// that signer's key signed. If it fails, the record is wrong, and a new
	// prekey, which is checked in full, puts it right.
	until, err := checkSigner(key, under, a, now)
	if err != nil {
		if s.log != nil {
			s.log.Printf("mailbox %s: the signer on record does not verify against the identity on record: %v", a, err) // the address redacted, as every line is
		}
		return wrongRecord(rank)
	}
	// A pass is never good for longer than the certificate it is under.
	if until.IsZero() || p.NotAfter.Before(until) {
		until = p.NotAfter
	}
	s.passes.keep(a, seenPass{sum: sum, raw: raw, signer: by, until: until}, now)
	return nil
}

// otherSigner refuses a pass signed by neither the identity nor the signer
// the call takes a pass by, of rank rank: certificate_revoked where the
// revocation of certificates held covers that signer, and otherwise
// certificate_not_current, naming no certificate where the signer is the
// identity. No signature was checked.
func otherSigner(rank uint64, listed bool) error {
	switch {
	case listed:
		return listedCertificate()
	case rank == 0:
		return fail(protocol.CodeCertificateNotCurrent, "sign the pass with the mailbox's identity, the signer of its current prekey: dromas does", "the pass is not signed by the mailbox's identity, which signs its current prekey")
	}
	return fail(protocol.CodeCertificateNotCurrent, "sign the pass with the identity, or the working key of the mailbox's newest prekey: dromas does", "the pass is signed by neither the identity nor certificate %d, the one this call takes a pass under", certificateSerialValue(rank))
}

// wrongRecord is the answer to a pass whose signer on record, of rank rank,
// does not verify against the mailbox's identity on record.
func wrongRecord(rank uint64) *problem {
	const hint = "publish a new prekey: dromas prekey renew"
	if rank == 0 {
		return fail(protocol.CodeCertificateNotCurrent, hint, "the mailbox's signer on record is not its identity")
	}
	return fail(protocol.CodeCertificateNotCurrent, hint, "the mailbox's certificate on record, %d, does not verify against its identity", certificateSerialValue(rank))
}

// notAPass refuses a call whose Authorization holds no pass, and counts it
// against the caller's address as a check that failed.
func (s *Server) notAPass(r *http.Request) error {
	if err := s.failed(r); err != nil {
		return err
	}
	return unauthorized(hintPass, "no pass, or not a pass")
}

// failed counts a check that failed against the caller's address, for one
// refused before a reservation was taken (s.miss). Past the count it is
// refused as such instead.
func (s *Server) failed(r *http.Request) error {
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	m.keep()
	return nil
}

// checkSigner holds the signing key a pass verified under to the identity
// whose key, in SSH wire form, is key, and whose address is a: a certificate
// by protocol.CheckCertificate, for an identity rebuilt from its key with
// every check its document had, and the identity's own key byte for byte.
// It returns when a certificate ends, and the zero time for the identity.
func checkSigner(key string, under ssh.PublicKey, a protocol.Address, now time.Time) (time.Time, error) {
	pub, err := ssh.ParsePublicKey([]byte(key))
	if err != nil {
		return time.Time{}, err
	}
	id, err := protocol.IdentityOf(pub)
	if err != nil {
		return time.Time{}, err
	}
	if id.Address() != a {
		return time.Time{}, errors.New("the identity on record is not this address's")
	}
	if _, ok := under.(*ssh.Certificate); !ok {
		if string(under.Marshal()) != key {
			return time.Time{}, errors.New("the signer on record is neither a certificate nor the identity's key")
		}
		return time.Time{}, nil
	}
	c, err := protocol.CheckCertificate(id, under, now)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter(), nil
}

// owner authenticates a call a mailbox makes about itself: it returns the
// address in the path, once the call has shown that mailbox's pass. A mailbox this
// process holds is checked from memory; any other costs a read of its
// record, which lookup limits for an address that names no mailbox. params are
// the query parameters the call takes (pathAddr).
func (s *Server) owner(r *http.Request, params ...string) (protocol.Address, error) {
	a, err := pathAddr(r, params...)
	if err != nil {
		return a, err
	}
	st, b, ok, err := s.standingOf(r, a)
	switch {
	case err != nil:
		return a, err
	case st.State == Revoked:
		return a, s.revokedAt(a, b)
	case !ok, st.State != Active: // no mailbox, or none in the state that takes calls
		return a, noSuchMailbox
	case st.Listed:
		// Its current certificate is revoked: the state is answered before the
		// pass, and only a pass that parses goes on, for the identity's alone
		// to be taken (PROTOCOL.md §11.4 rule 1, §8).
		auth, one := authorization(r)
		p, err := protocol.ParsePass(auth)
		if !one || err != nil {
			return a, listedCertificate()
		}
		return a, s.checkPass(r, a, st.Key, st.Signer, st.Rank, true, p)
	}
	return a, s.checkPass(r, a, st.Key, st.Signer, st.Rank, false, nil)
}

// sender authenticates a send: the sender is the mailbox the call's pass names
// (PROTOCOL.md §11.10, step 1).
func (s *Server) sender(r *http.Request) (protocol.Address, error) {
	auth, one := authorization(r)
	p, err := protocol.ParsePass(auth)
	if !one || err != nil {
		return protocol.Address{}, s.notAPass(r)
	}
	a := p.Address
	st, _, ok, err := s.standingOf(r, a)
	switch {
	case err != nil:
		return a, err
	case st.State == Revoked:
		return a, fail(protocol.CodeSenderRevoked, "your mailbox is revoked: make a new one, dromas init", "the sending mailbox is revoked")
	case !ok, st.State != Active:
		return a, fail(protocol.CodeUnknownSender, "register your own mailbox first: dromas init", "the mailbox the pass names is not registered")
	}
	return a, s.checkPass(r, a, st.Key, st.Signer, st.Rank, st.Listed, p)
}
