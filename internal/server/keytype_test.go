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
	"golang.org/x/crypto/ssh"
)

// rawP256 is a raw mailbox whose identity is a P-256 key.
func (e *env) rawP256() *raw {
	e.t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
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

// A mailbox whose identity is of the optional type registers, proves itself with
// a pass, and moves to a certificate, as a mailbox on an
// Ed25519 key does: the server checks the identity's signature when a
// certificate is put on record, and a pass against that certificate after.
func TestAMailboxOfTheOptionalKeyType(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	p := e.rawP256().register(protocol.MaxPrekeyLifetime)
	if p.id.Type() != protocol.IdentityP256 {
		t.Fatalf("the mailbox's identity is a %s key", p.id.Type())
	}
	e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 200, "")
	e.want(e.do("GET", p.path("/messages"), nil, ""), 401, protocol.CodeUnauthorized)

	// Another P-256 mailbox's pass is not this one's, and neither is a pass an
	// Ed25519 mailbox signs for this address.
	q, ed := e.rawP256().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("GET", p.path("/messages"), nil, q.pass(1)), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", p.path("/messages"), nil, e.passFor(ed.by[1], p.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)

	// A certificate, by a prekey published under it: its passes are taken,
	// and the identity's still are.
	p.certified()
	p.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", p.path("/prekey"), p.upload(2), p.pass(2)), 200, "")
	e.want(e.do("GET", p.path("/messages"), nil, p.pass(1)), 200, "")
	e.want(e.do("GET", p.path("/messages"), nil, p.pass(2)), 200, "")

	// A certificate another P-256 key signed for this address is no
	// certificate of this mailbox: a prekey under it is refused.
	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(wpriv)
	if err != nil {
		t.Fatal(err)
	}
	unix := uint64(now.Unix()) //nolint:gosec // a test clock
	c := &ssh.Certificate{Key: work.PublicKey(), Serial: 3, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
		ValidPrincipals: []string{p.id.Address().String()}, ValidAfter: unix - 60, ValidBefore: unix + 65*86400}
	if err := c.SignCert(rand.Reader, q.signer); err != nil {
		t.Fatal(err)
	}
	under, err := ssh.NewCertSigner(c, work)
	if err != nil {
		t.Fatal(err)
	}
	p.prekeyUnder(under, 3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", p.path("/prekey"), p.upload(3), e.passFor(under, p.id.Address(), e.name())), 400, protocol.CodeBadKey)
}

// A pass's signature does not cover the key it names, and a mailbox's signing
// key is public: its identity's key, or its certificate, rides in everything
// the mailbox signs. So anyone can put a mailbox's signing key into a pass
// they signed with a key of their own. The hash matches, and the signature
// is what refuses it, in either mode.
func TestAPassThatCarriesAnotherMailboxsCertificate(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	for name, victim := range map[string]*raw{"ssh-ed25519": e.raw(), "ecdsa-sha2-nistp256": e.rawP256()} {
		for _, working := range []bool{false, true} {
			victim := victim
			if working {
				victim = e.raw()
				if name != "ssh-ed25519" {
					victim = e.rawP256()
				}
			}
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
			e.want(e.do("GET", victim.path("/messages"), nil, pass), 401, protocol.CodeUnauthorized)
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
	for name, victim := range map[string]*raw{"ssh-ed25519": e.raw(), "ecdsa-sha2-nistp256": e.rawP256()} {
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
	p := e.rawP256()
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
	p, err := client.Init(context.Background(), t.TempDir(), o)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	landAll(t, p)
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
	p256, ed := e.rawP256().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	every := []string{protocol.IdentityEd25519, protocol.IdentityP256, "any", "no-such-key-type@dromas.invalid"}
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
	// A sender of either type is taken by every mailbox.
	for _, from := range []*raw{p256, ed} {
		for _, to := range []*raw{nothing, named, p256, ed} {
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
	e.want(sendTo(p256, nothing, 2), 201, "")

	// A declaration that is not a list of strings is no request.
	bad := e.raw()
	bad.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	reg, _ := json.Marshal(bad.registration(1))
	e.want(e.do("PUT", bad.path(""), bytes.Replace(reg, []byte("}"), []byte(`,"sender_key_types":"ssh-ed25519"}`), 1), bad.pass(1)), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", bad.path(""), bytes.Replace(reg, []byte("}"), []byte(`,"sender_key_types":[1]}`), 1), bad.pass(1)), 400, protocol.CodeBadRequest)
}
