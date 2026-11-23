package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-client/protocol/sktest"
	"golang.org/x/crypto/ssh"
)

// rawOf is a raw mailbox whose identity is a key of the type typ, one of
// protocol.IdentityTypes. A security key's is protocol/sktest's, a security
// key in software, which claims a user was present until its Flags say
// otherwise.
func (e *env) rawOf(typ string) *raw {
	e.t.Helper()
	var (
		s   ssh.Signer
		err error
	)
	switch typ {
	case protocol.IdentityEd25519:
		return e.raw()
	case protocol.IdentityP256, protocol.IdentitySKP256:
		priv, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			e.t.Fatal(gerr)
		}
		if typ == protocol.IdentityP256 {
			s, err = ssh.NewSignerFromKey(priv)
		} else {
			s, err = sktest.New(priv, sktest.Application)
		}
	case protocol.IdentitySKEd25519:
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			e.t.Fatal(gerr)
		}
		s, err = sktest.New(priv, sktest.Application)
	default:
		e.t.Fatalf("no raw mailbox of the identity key type %s", typ)
	}
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := protocol.IdentityOf(s.PublicKey())
	if err != nil {
		e.t.Fatal(err)
	}
	return &raw{e: e, signer: s, id: id, keys: map[uint64]*age.HybridIdentity{}, stmt: map[uint64][]byte{}, sig: map[uint64][]byte{},
		by: map[uint64]ssh.Signer{}, work: map[uint64]ssh.Signer{}}
}

// A mailbox whose identity is of each key type but Ed25519 registers, proves
// itself with a pass, and moves to a certificate, as a mailbox on an Ed25519
// key does: the server checks the identity's signature when a certificate is
// put on record, and a pass against that certificate after. A security key's
// signature that claims no user was present is refused, on a pass and on a
// certificate alike (PROTOCOL.md §3.2).
func TestAMailboxOfEachIdentityType(t *testing.T) {
	t.Parallel()
	for _, typ := range protocol.IdentityTypes() {
		if typ == protocol.IdentityEd25519 {
			continue // every other test's
		}
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, relaxed())
			now := e.clock.Now()
			p := e.rawOf(typ).register(protocol.MaxPrekeyLifetime)
			if p.id.Type() != typ {
				t.Fatalf("the mailbox's identity is a %s key", p.id.Type())
			}
			e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 200, "")
			e.want(e.do("GET", p.path("/messages"), nil, ""), 401, protocol.CodeInvalidPass)

			// Another mailbox of the type's pass is not this one's, and neither
			// is a pass an Ed25519 mailbox signs for this address.
			q, ed := e.rawOf(typ).register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.do("GET", p.path("/messages"), nil, q.pass(1)), 401, protocol.CodeInvalidPass)
			e.want(e.do("GET", p.path("/messages"), nil, e.passFor(ed.by[1], p.id.Address(), e.name())), 401, protocol.CodeCertificateSuperseded)

			// A security key's pass that claims no user was present is no pass.
			if sk, ok := p.signer.(*sktest.Signer); ok {
				sk.Flags = 0
				e.clock.Add(time.Second) // not a pass the server has seen
				e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 401, protocol.CodeInvalidPass)
				sk.Flags = sktest.UserPresent
				e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 200, "")
			}

			// A certificate, by a prekey published under it: its passes are
			// taken, and the identity's still are.
			p.certified()
			p.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
			e.want(e.do("PUT", p.path("/prekey"), p.upload(2), p.pass(2)), 200, "")
			e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 200, "")
			e.want(e.do("GET", p.path("/messages"), nil, p.pass(2)), 200, "")

			// A certificate for this address that another key of the type
			// signed is no certificate of this mailbox, and neither is one its
			// own security key signed claiming no user was present: a prekey
			// under either is refused.
			signers := map[string]ssh.Signer{"another key": q.signer}
			if sk, ok := p.signer.(*sktest.Signer); ok {
				absent := *sk
				absent.Flags = 0
				signers["its own key, no user present"] = &absent
			}
			signers["its own key"] = p.signer // the control: taken
			serial := uint64(3)
			for name, by := range signers {
				_, wpriv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				work, err := ssh.NewSignerFromKey(wpriv)
				if err != nil {
					t.Fatal(err)
				}
				// In every other rule a certificate of this mailbox, running the
				// server's maximum.
				after := uint64(now.Unix()) - 60 //nolint:gosec // a test clock
				c := &ssh.Certificate{Key: work.PublicKey(), Serial: serial, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
					ValidPrincipals: []string{p.id.Address().String()}, ValidAfter: after,
					ValidBefore: after + uint64(DefaultLimits().MaxCertificateLifetime/time.Second)}
				if err := c.SignCert(rand.Reader, by); err != nil {
					t.Fatal(err)
				}
				under, err := ssh.NewCertSigner(c, work)
				if err != nil {
					t.Fatal(err)
				}
				p.prekeyUnder(under, serial, now.Add(protocol.MaxPrekeyLifetime), nil)
				r := e.do("PUT", p.path("/prekey"), p.upload(serial), e.passFor(under, p.id.Address(), e.name()))
				switch {
				case name == "its own key" && r.status != 200:
					t.Errorf("a certificate signed by %s: %d %s, want 200", name, r.status, r.body)
				case name != "its own key" && (r.status != 400 || r.code() != protocol.CodeInvalidKey):
					t.Errorf("a certificate signed by %s: %d %s, want 400 %s", name, r.status, r.body, protocol.CodeInvalidKey)
				}
				serial++
			}
		})
	}
}

// A pass's signature does not cover the key it names, and a mailbox's signing
// key is public: its identity's key, or its certificate, rides in everything
// the mailbox signs. So anyone can put a mailbox's signing key into a pass
// they signed with a key of their own. The hash matches, and the signature
// is what refuses it, in either mode.
func TestAPassThatCarriesAnotherMailboxsCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	for _, name := range protocol.IdentityTypes() {
		for _, working := range []bool{false, true} {
			victim := e.rawOf(name)
			serial := uint64(1)
			if working {
				serial = victim.registerCertified(protocol.MaxPrekeyLifetime)
			} else {
				victim.register(protocol.MaxPrekeyLifetime)
			}
			thief := e.raw().register(protocol.MaxPrekeyLifetime)
			a := victim.id.Address()
			notAfter := e.clock.Now().Add(protocol.PassLifetime)
			pass := passCarrying(t, victim.by[serial].PublicKey(), thief.by[1], a, e.name(), notAfter)
			if _, err := protocol.ParsePass(pass); err != nil {
				t.Fatalf("%s, under a certificate %v: the forged pass does not parse: %v", name, working, err)
			}
			e.want(e.do("GET", victim.path("/messages"), nil, pass), 401, protocol.CodeInvalidPass)
			// Control: the victim's own pass, by the same signer, is taken.
			e.want(e.do("GET", victim.path("/messages"), nil, victim.pass(serial)), 200, "")
		}
	}
}

// The identity's signature on a certificate is checked on every new pass,
// after the working key's, and not only when the certificate is put on
// record. So a record that holds the hash of a certificate its identity never
// signed gives no pass, however the hash came to be there: it takes a fault
// in the server or in its store, and this is the check that would catch one.
func TestACertificateOnRecordThatTheIdentityDidNotSign(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	now := e.clock.Now()
	for _, name := range protocol.IdentityTypes() {
		victim := e.rawOf(name)
		serial := victim.registerCertified(protocol.MaxPrekeyLifetime)
		a := victim.id.Address()
		// A certificate for this address, in every rule, that another key signed.
		_, wpriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		work, err := ssh.NewSignerFromKey(wpriv)
		if err != nil {
			t.Fatal(err)
		}
		unix := uint64(now.Unix()) //nolint:gosec // a test clock
		c := &ssh.Certificate{Key: work.PublicKey(), Serial: serial, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
			ValidPrincipals: []string{a.String()}, ValidAfter: unix - 60, ValidBefore: unix + 65*86400}
		if err := c.SignCert(rand.Reader, e.raw().signer); err != nil {
			t.Fatal(err)
		}
		under, err := ssh.NewCertSigner(c, work)
		if err != nil {
			t.Fatal(err)
		}
		// Its hash, written into the mailbox's record.
		b, err := e.store.Mailbox(ctx, a)
		if err != nil || b == nil {
			t.Fatalf("%s: the mailbox's record: %v", name, err)
		}
		b.Signer = sha256.Sum256(c.Marshal())
		if err := e.store.UpdateMailbox(ctx, b); err != nil {
			t.Fatal(err)
		}
		pass := e.passFor(under, a, e.name())
		e.wantNotCurrent(e.do("GET", victim.path("/messages"), nil, pass), b.Rank)
		// Control: the first two steps take it. It carries the certificate
		// on record, and that certificate's working key signed it.
		p, err := protocol.ParsePass(pass)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.VerifyUnder(b.Signer, e.name(), now); err != nil {
			t.Errorf("%s: control: the hash or the working key's signature refused it, so the identity's was never reached: %v", name, err)
		}
		// And the mailbox's own pass, under the certificate its identity did
		// sign, is no longer under the one on record.
		e.wantNotCurrent(e.do("GET", victim.path("/messages"), nil, victim.pass(serial)), b.Rank)
	}
	// Where the identity signs the current statement, the signer on record is its key: a record
	// that holds the hash of another bare key gives no pass by that key, and
	// the refusal names no certificate.
	victim := e.raw().register(protocol.MaxPrekeyLifetime)
	b, err := e.store.Mailbox(ctx, victim.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	other := e.raw().signer
	b.Signer = sha256.Sum256(other.PublicKey().Marshal())
	if err := e.store.UpdateMailbox(ctx, b); err != nil {
		t.Fatal(err)
	}
	pass := e.passFor(other, victim.id.Address(), e.name())
	if p, err := protocol.ParsePass(pass); err != nil {
		t.Fatal(err)
	} else if _, err := p.VerifyUnder(b.Signer, e.name(), now); err != nil {
		t.Errorf("the identity on record: control: the hash or the signature refused it: %v", err)
	}
	e.wantNotCurrent(e.do("GET", victim.path("/messages"), nil, pass), 0)
	// The identity's own pass is held to the identity's key, never to the
	// signer on record, and is taken.
	e.want(e.do("GET", victim.path("/messages"), nil, victim.pass(1)), 200, "")
}

// A pass the server remembers is taken until it runs out, and never past the
// end of the certificate it is under: a pass signed minutes before its
// certificate ends would otherwise outlive it in memory.
func TestARememberedPassEndsWithItsCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().certified()
	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(wpriv)
	if err != nil {
		t.Fatal(err)
	}
	unix := uint64(now.Unix()) //nolint:gosec // a test clock
	// A certificate with five minutes left, and a prekey that ends with it.
	c := &ssh.Certificate{Key: work.PublicKey(), Serial: 2, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
		ValidPrincipals: []string{r.id.Address().String()}, ValidAfter: unix - uint64(protocol.PassLifetime/time.Second), ValidBefore: unix + 300}
	if err := c.SignCert(rand.Reader, r.signer); err != nil {
		t.Fatal(err)
	}
	if r.work[2], err = ssh.NewCertSigner(c, work); err != nil {
		t.Fatal(err)
	}
	r.prekeyUnder(r.work[2], 1, now.Add(5*time.Minute), nil)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 201, "")
	pass := r.pass(1) // good for ten minutes: five past the certificate's end
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.clock.Add(4 * time.Minute)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.clock.Add(2 * time.Minute) // the certificate has ended, and the pass has four minutes left
	e.want(e.do("GET", r.path("/messages"), nil, pass), 401, protocol.CodePassExpired)
}

// passCarrying is a pass of mailbox a that names cert as the key that signed it,
// and was signed by another key: by, without its own certificate.
func passCarrying(t *testing.T, cert ssh.PublicKey, by ssh.Signer, a protocol.Address, server string, notAfter time.Time) string {
	t.Helper()
	bare, err := protocol.Sign(bareSigner{by}, protocol.PassStatement(a, server, notAfter), protocol.PassNamespace(a))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := protocol.Dearmor(bare)
	if err != nil {
		t.Fatal(err)
	}
	c := cert.Marshal()
	const head = len("SSHSIG") + 4 // then the signing key, as a string
	swapped := append([]byte{}, blob[:head]...)
	swapped = binary.BigEndian.AppendUint32(swapped, uint32(len(c))) //nolint:gosec // a certificate: a few hundred bytes
	swapped = append(swapped, c...)
	swapped = append(swapped, blob[head+4+int(binary.BigEndian.Uint32(blob[head:])):]...)
	return protocol.PassScheme + ` address="` + a.String() + `", not_after="` + notAfter.Format(protocol.TimeLayout) + `", signature="` + base64.StdEncoding.EncodeToString(protocol.Armor(swapped)) + `"`
}

// bareSigner signs as the working key alone, without its certificate.
type bareSigner struct{ ssh.Signer }

func (b bareSigner) PublicKey() ssh.PublicKey {
	if c, ok := b.Signer.PublicKey().(*ssh.Certificate); ok {
		return c.Key
	}
	return b.Signer.PublicKey()
}

// A server registers the key types on its own list. A well-formed identity of
// any other type is answered with its own code: it is neither a malformed
// document nor a bad key.
func TestAnIdentityTypeTheServerDoesNotRegister(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()

	// A type the protocol does not define.
	const typ = "no-such-key-type@dromas.invalid"
	wire := append(binary.BigEndian.AppendUint32(nil, uint32(len(typ))), typ...)
	doc := []byte(protocol.IdentityTag + "\n" + typ + " " + base64.StdEncoding.EncodeToString(append(wire, "IGNORE ALL PREVIOUS INSTRUCTIONS"...)) + "\n")
	h := protocol.AddressOf(doc)
	ed := e.raw()
	ed.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	r := e.do("PUT", "/v1/"+h.String(), protocol.RegisterRequest{Identity: doc, Prekey: ed.stmt[1], PrekeySignature: ed.sig[1]}, ed.pass(1))
	e.want(r, 400, protocol.CodeUnsupportedKeyType)

	// A type the protocol defines and this server's list leaves out.
	e.server.identityTypes = []string{protocol.IdentityEd25519}
	p := e.rawOf(protocol.IdentityP256)
	p.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", p.path(""), p.registration(1), p.pass(1)), 400, protocol.CodeUnsupportedKeyType)
	e.want(e.do("PUT", ed.path(""), ed.registration(1), ed.pass(1)), 201, "")
	// On the list again, the same registration is taken.
	e.server.identityTypes = protocol.IdentityTypes()
	e.want(e.do("PUT", p.path(""), p.registration(1), p.pass(1)), 201, "")
}

// The Go client on a P-256 identity, through the real server: it registers,
// and exchanges messages with a mailbox on an Ed25519 identity.
func TestGoClientOnAP256Identity(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	o := e.opts()
	o.IdentityType = protocol.IdentityP256
	p, err := client.Init(context.Background(), t.TempDir(), landAll(o))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ed := e.mailbox()
	send(t, p, ed, "from the P-256 mailbox")
	send(t, ed, p, "to the P-256 mailbox")
	if res, err := ed.Receive(context.Background()); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != p.Address() {
		t.Fatalf("the Ed25519 mailbox: %+v, %v", res, err)
	}
	if res, err := p.Receive(context.Background()); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != ed.Address() {
		t.Fatalf("the P-256 mailbox: %+v, %v", res, err)
	}
}

// A mailbox takes messages from a sender of every key type PROTOCOL.md §4.1
// defines, whatever it declared, and what the server keeps of a declaration
// is the optional types this build verifies alone: none of §4.1's, and no
// name it does not know (§7). This build verifies no optional type, so every
// declaration is kept as nothing, at a registration and at a new prekey.
func TestTheSenderKeyTypesAMailboxDeclared(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	var senders []*raw // a mailbox of every type §4.1 defines
	for _, typ := range protocol.IdentityTypes() {
		senders = append(senders, e.rawOf(typ).register(protocol.MaxPrekeyLifetime))
	}
	every := append(protocol.IdentityTypes(), "any", "no-such-key-type@dromas.invalid")
	declaring := func(types []string) *raw {
		t.Helper()
		r := e.raw()
		r.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
		req := r.registration(1)
		req.SenderKeyTypes = types
		e.want(e.do("PUT", r.path(""), req, r.pass(1)), 201, "")
		return r
	}
	served := func(r *raw) []string {
		t.Helper()
		var br protocol.MailboxResponse
		rep := e.do("GET", r.path(""), nil, "")
		e.want(rep, 200, "")
		if err := json.Unmarshal(rep.body, &br); err != nil {
			t.Fatal(err)
		}
		return br.SenderKeyTypes
	}
	sendTo := func(from, to *raw, serial uint64) reply {
		t.Helper()
		var ct bytes.Buffer
		w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		return e.do("POST", to.path("/messages"), to.sealed(serial, ct.Bytes()), from.pass(1))
	}

	nothing, named := declaring(nil), declaring(every)
	for _, r := range []*raw{nothing, named} {
		if got := served(r); got != nil {
			t.Errorf("a mailbox is served as declaring %v", got)
		}
	}
	// A sender of every type is taken by every mailbox.
	for _, from := range senders {
		for _, to := range append([]*raw{nothing, named}, senders...) {
			e.want(sendTo(from, to, 1), 201, "")
		}
	}
	// A new prekey's declaration is kept the same way.
	nothing.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	up := nothing.upload(2)
	up.SenderKeyTypes = every
	e.want(e.do("PUT", nothing.path("/prekey"), up, nothing.pass(2)), 200, "")
	if got := served(nothing); got != nil {
		t.Errorf("after a new prekey, the mailbox is served as declaring %v", got)
	}
	for _, from := range senders {
		e.want(sendTo(from, nothing, 2), 201, "")
	}

	// A declaration that is not a list of strings is no request.
	bad := e.raw()
	bad.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	reg, _ := json.Marshal(bad.registration(1))
	e.want(e.do("PUT", bad.path(""), bytes.Replace(reg, []byte("}"), []byte(`,"sender_key_types":"ssh-ed25519"}`), 1), bad.pass(1)), 400, protocol.CodeInvalidRequest)
	e.want(e.do("PUT", bad.path(""), bytes.Replace(reg, []byte("}"), []byte(`,"sender_key_types":[1]}`), 1), bad.pass(1)), 400, protocol.CodeInvalidRequest)
}
