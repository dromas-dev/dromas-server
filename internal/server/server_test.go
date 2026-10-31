package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The server's answers, checked over raw HTTP, against the status map
// (PROTOCOL.md §11.3) and the mailbox states (§11.6).

type reply struct {
	status int
	header http.Header
	body   []byte
}

// codeOf is the code of the API error a client's one call met.
func codeOf(err error) protocol.Code {
	if e, ok := errors.AsType[*client.APIError](err); ok {
		return e.Problem.Code
	}
	return ""
}

// tooLarge reports whether err is a too_large refusal whose limit is limit.
func tooLarge(err error, limit uint64) bool {
	e, ok := errors.AsType[*client.APIError](err)
	return ok && e.Problem.Code == protocol.CodeTooLarge && e.Problem.Limit != nil && *e.Problem.Limit == limit
}

// clockGap is how far the mailbox's clock read from the date on the server's
// answer, when err is a refusal the client read one on.
func clockGap(err error) time.Duration {
	if e, ok := errors.AsType[*client.APIError](err); ok && !e.Dated.IsZero() && !e.Read.IsZero() {
		return e.Read.Sub(e.Dated)
	}
	return 0
}

func (r reply) code() protocol.Code {
	return r.problem().Code
}

// problem is the reply's body read as an error's.
func (r reply) problem() protocol.Problem {
	var p protocol.Problem
	_ = json.Unmarshal(r.body, &p)
	return p
}

// quota is the limit a rate_limited answer names, and whom it says that
// limit counted the call against.
func (r reply) quota() (protocol.Quota, protocol.Subject) {
	var p protocol.Problem
	_ = json.Unmarshal(r.body, &p)
	return p.QuotaID, p.Subject
}

// limited checks that r is a 429 rate_limited naming the limit q, counted
// against q's subject.
func (e *env) limited(r reply, q protocol.Quota) {
	e.t.Helper()
	e.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if got, by := r.quota(); got != q || by != q.Subject() {
		e.t.Fatalf("got the limit %q counted against %q, want %q: %s", got, by, q, r.body)
	}
}

// limitedBy reports whether err is a rate_limited naming the limit q.
func limitedBy(err error, q protocol.Quota) bool {
	var ae *client.APIError
	return errors.As(err, &ae) && ae.Problem.Code == protocol.CodeRateLimited && ae.Problem.QuotaID == q
}

// sealed is a send as the server reads one (PROTOCOL.md §11.10): the
// ciphertext, which is the body, and the serials of the prekey it is sealed
// to, which are the query.
type sealed struct {
	protocol.SendQuery
	ciphertext []byte
}

// sealedTo is a send of ciphertext to the prekey statement statement.
func sealedTo(statement, ciphertext []byte) sealed {
	return sealed{protocol.SendQuery{Statement: protocol.StatementHash(statement)}, ciphertext}
}

// do calls the server. A body of []byte is sent as it is, a sealed as a
// send sends it, and anything else as JSON.
func (e *env) do(method, path string, body any, pass string) reply {
	e.t.Helper()
	return e.doAs("", method, path, body, pass)
}

// doWith is do with header fields of its own, as name and value pairs.
func (e *env) doWith(method, path string, body any, pass string, headers ...string) reply {
	e.t.Helper()
	return e.doAs("", method, path, body, pass, headers...)
}

// doAs is do, calling the server by the name host when one is given, with
// any header fields as name and value pairs.
func (e *env) doAs(host, method, path string, body any, pass string, headers ...string) reply {
	e.t.Helper()
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case sealed:
		rd, ctype, path = bytes.NewReader(b.ciphertext), protocol.CiphertextContentType, path+"?"+b.Encode()
	default:
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if host != "" {
		req.Host = host
	}
	if pass != "" {
		req.Header.Set("Authorization", pass)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, header: resp.Header, body: b}
	if resp.StatusCode >= 400 {
		var p protocol.Problem
		if err := json.Unmarshal(b, &p); err != nil || resp.Header.Get("Content-Type") != protocol.ProblemContentType ||
			p.Status != int64(resp.StatusCode) || p.Type != p.Code.TypeURI() || p.Code.Status() != resp.StatusCode {
			e.t.Fatalf("%s %s: %d is not a problem+json body matching the status map: %s", method, path, resp.StatusCode, b)
		}
		if got := resp.Header.Get("WWW-Authenticate"); (got == protocol.PassScheme) != (resp.StatusCode == http.StatusUnauthorized) {
			e.t.Fatalf("%s %s: %d with WWW-Authenticate %q", method, path, resp.StatusCode, got)
		}
	}
	return r
}

func (e *env) want(r reply, status int, code protocol.Code) {
	e.t.Helper()
	if r.status != status || (code != "" && r.code() != code) {
		e.t.Fatalf("got %d %s, want %d %s: %s", r.status, r.code(), status, code, r.body)
	}
}

// wantNotCurrent is want of a pass refused as under another certificate than
// the one the call takes a pass under, serial n, which the answer names
// (dromas-dev/dromas-server#66); n of 0 is the identity, and the answer
// names no certificate.
func (e *env) wantNotCurrent(r reply, n uint64) {
	e.t.Helper()
	e.want(r, http.StatusUnauthorized, protocol.CodeCertificateNotCurrent)
	switch p := r.problem(); {
	case n == 0 && p.CertificateSerial != nil:
		e.t.Fatalf("certificate_not_current names certificate %d of a mailbox in identity mode: %s", *p.CertificateSerial, r.body)
	case n != 0 && (p.CertificateSerial == nil || *p.CertificateSerial != n):
		e.t.Fatalf("certificate_not_current names certificate %v, want %d: %s", p.CertificateSerial, n, r.body)
	}
}

// name is the name the tests call the server by: the host of its URL.
func (e *env) name() string { return strings.TrimPrefix(e.srv.URL, "http://") }

// passFor is a pass of mailbox a for the server called name, signed at the
// test's clock by signer: the identity, or a working key under its
// certificate.
func (e *env) passFor(signer ssh.Signer, a protocol.Address, name string) string {
	e.t.Helper()
	auth, _, err := protocol.NewPass(signer, a, name, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return auth
}

// numbers returns the serials a mailbox stands at in the store: its prekey's and
// its signer's rank, 0 for the identity. A client takes them from its clock,
// so a test reads them and never assumes one.
func (e *env) numbers(a protocol.Address) (prekey, cert uint64) {
	e.t.Helper()
	b, err := e.store.Mailbox(context.Background(), a)
	if err != nil || b == nil {
		e.t.Fatalf("the mailbox's record: %v", err)
	}
	return b.Prekey.Serial, b.Rank
}

// statement returns the prekey statement a mailbox stands at in the store, as
// a send names it.
func (e *env) statement(a protocol.Address) []byte {
	e.t.Helper()
	b, err := e.store.Mailbox(context.Background(), a)
	if err != nil || b == nil {
		e.t.Fatalf("the mailbox's record: %v", err)
	}
	return b.Statement
}

// mustMailbox is what the store holds of address a.
func mustMailbox(t *testing.T, e *env, a protocol.Address) *Mailbox {
	t.Helper()
	b, err := e.store.Mailbox(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// worker loads the working key of a client's mailbox, under its certificate:
// the one made with the prekey it published last.
func worker(t *testing.T, b *client.Mailbox) ssh.Signer {
	t.Helper()
	st, err := b.Status(t.Context())
	if err != nil || st.PrekeySerial == 0 {
		t.Fatalf("the mailbox's status: %+v, %v", st, err)
	}
	stem := filepath.Join(b.Dir(), "work", strconv.FormatUint(st.PrekeySerial, 10))
	k, err := os.ReadFile(stem)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(stem + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(key.(*ssh.Certificate), work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pass is a new pass of a client's mailbox, as the mailbox would sign it now.
func (e *env) pass(b *client.Mailbox) string {
	e.t.Helper()
	return e.passFor(worker(e.t, b), b.Address(), e.name())
}

// raw is a mailbox built by hand, for requests the client would never make. It
// is in identity mode, its identity signing its statements and passes,
// until trip publishes its revocation of certificates through tripAt; from
// then on each statement is signed by a working key under a certificate of
// the statement's serial, and certificates and statements are kept by the
// number they were made under.
type raw struct {
	e       *env
	signer  ssh.Signer // the identity
	id      *protocol.Identity
	keys    map[uint64]*age.HybridIdentity
	stmt    map[uint64][]byte
	sig     map[uint64][]byte
	by      map[uint64]ssh.Signer // the signer of each statement, by its serial
	work    map[uint64]ssh.Signer // a working key under its certificate, by the certificate's serial
	tripped bool
}

// tripAt is the serial a raw mailbox's trip revokes certificates through: a
// mailbox in working-key mode signs under certificates above it.
const tripAt = 1

func (e *env) raw() *raw {
	e.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		e.t.Fatal(err)
	}
	return &raw{e: e, signer: s, id: id, keys: map[uint64]*age.HybridIdentity{}, stmt: map[uint64][]byte{}, sig: map[uint64][]byte{},
		by: map[uint64]ssh.Signer{}, work: map[uint64]ssh.Signer{}}
}

func (r *raw) path(rest string) string { return "/v1/" + r.id.Address().String() + rest }

// certify makes a new working key and its certificate, of the given serial,
// running the server's maximum, and replaces any the mailbox holds at that
// serial.
func (r *raw) certify(serial uint64) ssh.Signer {
	r.e.t.Helper()
	return r.certifyFor(serial, DefaultLimits().MaxCertificateLifetime)
}

// certifyFor is certify, of a certificate running lifetime.
func (r *raw) certifyFor(serial uint64, lifetime time.Duration) ssh.Signer {
	r.e.t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	work, _ := ssh.NewSignerFromKey(priv)
	cert, err := protocol.NewCertificate(r.id, r.signer, work.PublicKey(), serial, r.e.clock.Now(), lifetime)
	if err != nil {
		r.e.t.Fatal(err)
	}
	s, err := cert.Signer(work)
	if err != nil {
		r.e.t.Fatal(err)
	}
	r.work[serial] = s
	return s
}

// trip publishes the mailbox's revocation of certificates through tripAt,
// the trip to working-key mode, and signs every statement after it under a
// certificate.
func (r *raw) trip() *raw {
	r.e.t.Helper()
	if got := r.e.do("PUT", r.path("/revocations"), r.certs(tripAt), ""); got.status != 200 && got.status != 201 {
		r.e.t.Fatalf("the trip: %d %s", got.status, got.body)
	}
	r.tripped = true
	return r
}

// prekey makes statement serial, with a new key unless key is given: signed
// by the identity in identity mode, and by a new working key under a new
// certificate of the same serial once the mailbox has made its trip.
func (r *raw) prekey(serial uint64, notAfter time.Time, key *age.HybridIdentity) {
	r.e.t.Helper()
	signer := r.signer
	if r.tripped {
		signer = r.certify(serial)
	}
	r.prekeyUnder(signer, serial, notAfter, key)
}

// prekeyUnder makes statement serial, signed by signer.
func (r *raw) prekeyUnder(signer ssh.Signer, serial uint64, notAfter time.Time, key *age.HybridIdentity) {
	r.e.t.Helper()
	if signer == nil {
		r.e.t.Fatalf("statement %d: no signer", serial)
	}
	if key == nil {
		key, _ = age.GenerateHybridIdentity()
	}
	r.keys[serial] = key
	p := &protocol.Prekey{Address: r.id.Address(), Serial: serial, Key: key.Recipient().String(), NotAfter: notAfter}
	sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(r.id.Address()))
	if err != nil {
		r.e.t.Fatal(err)
	}
	r.stmt[serial], r.sig[serial], r.by[serial] = p.Statement(), sig, signer
}

func (r *raw) registration(serial uint64) protocol.RegisterRequest {
	return protocol.RegisterRequest{Identity: r.id.Document(), Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}
}

func (r *raw) upload(serial uint64) protocol.PrekeyRequest {
	return protocol.PrekeyRequest{Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}
}

// pass is a new pass by the signer of statement serial, or, where the
// mailbox made no statement of that serial, under its certificate of that
// serial.
func (r *raw) pass(serial uint64) string {
	r.e.t.Helper()
	s := r.by[serial]
	if s == nil {
		s = r.work[serial]
	}
	if s == nil {
		r.e.t.Fatalf("no statement and no certificate of serial %d", serial)
	}
	return r.e.passFor(s, r.id.Address(), r.e.name())
}

// sealed is a send of ciphertext to statement serial.
func (r *raw) sealed(serial uint64, ciphertext []byte) sealed {
	return sealedTo(r.stmt[serial], ciphertext)
}

// register registers the mailbox with a new prekey 1, valid for d.
func (r *raw) register(d time.Duration) *raw {
	r.e.t.Helper()
	return r.registerAt(1, d)
}

// registerAt registers the mailbox with a new prekey serial, valid for d.
func (r *raw) registerAt(serial uint64, d time.Duration) *raw {
	r.e.t.Helper()
	r.prekey(serial, r.e.clock.Now().Add(d), nil)
	r.e.want(r.e.do("PUT", r.path(""), r.registration(serial), r.pass(serial)), 201, "")
	return r
}

// registerWorking makes the trip, then registers the mailbox in working-key
// mode with a new prekey just above it, under the certificate of its serial,
// valid for d. It returns the serial.
func (r *raw) registerWorking(d time.Duration) uint64 {
	r.e.t.Helper()
	r.trip().registerAt(tripAt+1, d)
	return tripAt + 1
}

// A signature is at most protocol.MaxSignature bytes as it arrives (PROTOCOL.md
// §3.2), what follows its END line included, and is kept and served as it was
// sent (§13). A pass is at most protocol.MaxPassAuthorization.
func TestASignatureIsBounded(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	pad := func(sig []byte, to int) []byte {
		return append(append([]byte{}, sig...), bytes.Repeat([]byte{'.'}, to-len(sig))...)
	}

	r := e.raw()
	r.prekey(1, now.Add(protocol.PrekeyLifetime), nil)
	r.sig[1] = pad(r.sig[1], protocol.MaxSignature)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 201, "")
	var got protocol.MailboxResponse
	if err := json.Unmarshal(e.do("GET", r.path(""), nil, "").body, &got); err != nil || !bytes.Equal(got.PrekeySignature, r.sig[1]) {
		t.Errorf("the signature is not served as it was sent: %v", err)
	}

	over := e.raw()
	over.prekey(1, now.Add(protocol.PrekeyLifetime), nil)
	pass := over.pass(1)
	over.sig[1] = pad(over.sig[1], protocol.MaxSignature+1)
	e.want(e.do("PUT", over.path(""), over.registration(1), pass), 400, protocol.CodeBadKey)

	// A renewal is held to it too.
	r.prekey(2, now.Add(protocol.PrekeyLifetime), nil)
	r.sig[2] = pad(r.sig[2], protocol.MaxSignature+1)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 400, protocol.CodeBadKey)

	e.want(e.do("GET", r.path("/messages"), nil, strings.Repeat("x", protocol.MaxPassAuthorization+1)), 401, protocol.CodeUnauthorized)
}

// A prekey that is no prekey's type, an X25519 recipient or one of a type
// nobody defines, is bad_key at a registration and at a renewal (PROTOCOL.md
// §6, §11.7 step 6).
func TestAPrekeyOfAnotherTypeIsBadKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	x25519, _ := age.GenerateX25519Identity()
	unknown := strings.Split(string(clientFile(t, "testdata/vectors/prekey/unsupported-type.txt")), "\n")[3]
	for _, key := range []string{x25519.Recipient().String(), unknown} {
		other := func(r *raw, serial uint64) {
			signer := r.certify(serial)
			p := &protocol.Prekey{Address: r.id.Address(), Serial: serial, Key: key, NotAfter: e.clock.Now().Add(protocol.PrekeyLifetime)}
			sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(r.id.Address()))
			if err != nil {
				t.Fatal(err)
			}
			r.stmt[serial], r.sig[serial] = p.Statement(), sig
		}
		fresh := e.raw()
		other(fresh, 1)
		e.want(e.do("PUT", fresh.path(""), fresh.registration(1), fresh.pass(1)), 400, protocol.CodeBadKey)
		r := e.raw().register(protocol.PrekeyLifetime)
		other(r, 2)
		e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 400, protocol.CodeBadKey)
	}
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw()
	r.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	reg, pass := r.registration(1), r.pass(1)

	e.want(e.do("PUT", "/v1/nope", reg, pass), 400, protocol.CodeBadAddress)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":"","extra":1}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":""}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":null}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"not base64!","prekey":"","prekey_signature":""}`), pass), 400, protocol.CodeBadEncoding)
	e.want(e.do("PUT", r.path(""), []byte(`not json`), pass), 400, protocol.CodeBadRequest)
	// A body is read as every reader reads JSON (PROTOCOL.md §3.3): names
	// exactly, none twice, one value, and each byte field in its one
	// encoding.
	rj, _ := json.Marshal(reg)
	for name, body := range map[string][]byte{
		"a name in another case": bytes.Replace(rj, []byte(`"identity"`), []byte(`"IDENTITY"`), 1),
		"a long s for an s":      bytes.Replace(rj, []byte(`"prekey_signature"`), []byte(`"prekey_\u017fignature"`), 1),
		"a name twice":           bytes.Replace(rj, []byte(`{`), []byte(`{"identity":"",`), 1),
		"a bracket after it":     append(append([]byte{}, rj...), ']'),
		"a brace after it":       append(append([]byte{}, rj...), '}'),
		"a byte-order mark":      append([]byte("\xef\xbb\xbf"), rj...),
		"NaN beside it":          bytes.Replace(rj, []byte(`{`), []byte(`{"x":NaN,`), 1),
	} {
		if got := e.do("PUT", r.path(""), body, pass); got.status != 400 || got.code() != protocol.CodeBadRequest {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeBadRequest)
		}
	}
	for name, body := range map[string][]byte{
		"base64 with no padding": bytes.Replace(rj, []byte(`="`), []byte(`"`), 1),
		"base64 wrapped":         bytes.Replace(rj, []byte(`","prekey"`), []byte(`\n","prekey"`), 1),
		"its unused bits set":    unusedBitsSet(t, rj),
	} {
		if got := e.do("PUT", r.path(""), body, pass); got.status != 400 || got.code() != protocol.CodeBadEncoding {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeBadEncoding)
		}
	}

	other := e.raw()
	e.want(e.do("PUT", other.path(""), reg, pass), 400, protocol.CodeIdentityMismatch)

	// A document that hashes to its address but breaks the grammar.
	commented := append(bytes.TrimSuffix(r.id.Document(), []byte("\n")), []byte(" comment\n")...)
	h := protocol.AddressOf(commented)
	e.want(e.do("PUT", "/v1/"+h.String(), protocol.RegisterRequest{Identity: commented, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, pass), 400, protocol.CodeIdentityMismatch)

	// A small-order key: the grammar holds, the key check fails.
	small := clientFile(t, "testdata/vectors/identity/small-order-1.doc")
	h = protocol.AddressOf(small)
	e.want(e.do("PUT", "/v1/"+h.String(), protocol.RegisterRequest{Identity: small, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, pass), 400, protocol.CodeBadKey)

	// A prekey statement under another identity's certificate; one the
	// identity signed itself; one a working key signed with no certificate;
	// one valid for too long; one expired.
	other.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: other.sig[1]}, pass), 400, protocol.CodeBadKey)
	byIdentity, _ := protocol.Sign(r.signer, reg.Prekey, protocol.PrekeyNamespace(r.id.Address()))
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: byIdentity}, pass), 400, protocol.CodeBadKey)
	_, bare, _ := ed25519.GenerateKey(rand.Reader)
	bareSigner, _ := ssh.NewSignerFromKey(bare)
	byBare, _ := protocol.Sign(bareSigner, reg.Prekey, protocol.PrekeyNamespace(r.id.Address()))
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: byBare}, pass), 400, protocol.CodeBadKey)
	long := e.raw()
	long.prekey(1, now.Add(protocol.MaxPrekeyLifetime+time.Second), nil)
	e.want(e.do("PUT", long.path(""), long.registration(1), long.pass(1)), 400, protocol.CodePrekeyTime)
	expired := e.raw()
	expired.prekey(1, now, nil)
	e.want(e.do("PUT", expired.path(""), expired.registration(1), expired.pass(1)), 400, protocol.CodePrekeyTime)

	// The pass: there must be one, this mailbox's, for this server, not run out,
	// and under the certificate the statement is signed under. A statement
	// that leaked registers nothing for whoever found it.
	e.want(e.do("PUT", r.path(""), reg, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, "Bearer drt1_abc"), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, other.pass(1)), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, e.passFor(r.by[1], r.id.Address(), "another.example")), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, e.passFor(r.certify(2), r.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)
	e.clock.Add(-protocol.PassLifetime)
	ranOut := r.pass(1)
	e.clock.Add(protocol.PassLifetime)
	e.want(e.do("PUT", r.path(""), reg, ranOut), 401, protocol.CodePassExpired)
	e.clock.Add(protocol.MaxPassLifetime)
	tooFar := r.pass(1)
	e.clock.Add(-protocol.MaxPassLifetime)
	e.want(e.do("PUT", r.path(""), reg, tooFar), 401, protocol.CodePassExpired)
	if _, err := e.store.Mailbox(context.Background(), r.id.Address()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused registration left a mailbox: %v", err)
	}

	// Registered: 201, then an identical retry is 200, and anything else is
	// a conflict. Neither answer carries anything.
	first := e.do("PUT", r.path(""), reg, pass)
	e.want(first, 201, "")
	again := e.do("PUT", r.path(""), reg, pass)
	e.want(again, 200, "")
	for _, rep := range []reply{first, again} {
		if string(bytes.TrimSpace(rep.body)) != "{}" {
			t.Fatalf("a registration answered %s", rep.body)
		}
	}
	e.want(e.do("PUT", r.path(""), reg, ""), 401, protocol.CodeUnauthorized) // a retry needs its pass too
	r2 := e.raw()
	r2.signer, r2.id = r.signer, r.id
	r2.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r2.registration(1), r2.pass(1)), 409, protocol.CodeConflict)

	// In use at once: it takes messages, and its owner's calls are served.
	a := e.mailbox()
	if _, err := a.Send(context.Background(), r.id.Address(), "at once"); err != nil {
		t.Fatalf("send to a mailbox just registered: %v", err)
	}
	list := e.do("GET", r.path("/messages"), nil, pass)
	e.want(list, 200, "")
	if !bytes.Contains(list.body, []byte(`"count":1`)) {
		t.Fatalf("the new mailbox's list: %s", list.body)
	}

	// The registration limit, per IP.
	l := relaxed()
	l.RegistrationsPerHour = 1
	e2 := newEnv(t, l)
	e2.raw().register(time.Hour)
	y := e2.raw()
	y.prekey(1, now.Add(time.Hour), nil)
	rl := e2.do("PUT", y.path(""), y.registration(1), y.pass(1))
	e2.want(rl, 429, protocol.CodeRateLimited)
	if rl.header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

// A registration of a registered mailbox, or of a revoked address, is answered
// from what is held of it before anything below is checked (PROTOCOL.md §11.7
// step 5), whether this process's memory holds the mailbox or it reads the
// record, under the count of registrations (dromas-dev/dromas-server#94):
// another statement is 409 whatever pass it carries and however it is
// signed, the mailbox's current statement under its revoked current certificate
// is certificate_revoked with no pass read, and a revoked address is 410.
// Control: an address with no mailbox has its statement and its pass read.
func TestARegistrationOfARegisteredMailboxIsAnsweredFromItsRecordFirst(t *testing.T) {
	t.Parallel()
	for name, with := range map[string][]func(*Config){
		"a mailbox this process holds":         nil,
		"a mailbox this process does not hold": {func(c *Config) { c.Store = unknownStore{c.Store} }},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, relaxed(), with...)
			c := e.raw()
			c.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			c.certify(1)
			e.want(e.do("PUT", c.path(""), c.registration(5), e.passFor(c.work[1], c.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)
			bad := c.registration(5)
			bad.PrekeySignature = c.sig[1]
			e.want(e.do("PUT", c.path(""), bad, c.pass(5)), 400, protocol.CodeBadKey)

			r := at3(e)
			r.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			for what, pass := range map[string]string{"no pass": "", "a pass under certificate 2": r.pass(2), "a pass under its certificate": r.pass(5)} {
				if got := e.do("PUT", r.path(""), r.registration(5), pass); got.status != 409 || got.code() != protocol.CodeConflict {
					t.Errorf("another statement, %s: %d %s, want 409 conflict", what, got.status, got.body)
				}
			}
			bad = r.registration(5)
			bad.PrekeySignature = r.sig[3]
			r.prekey(6, e.clock.Now(), nil) // expired as it is made
			for what, req := range map[string]protocol.RegisterRequest{"whose signature does not verify": bad, "that has expired": r.registration(6)} {
				if got := e.do("PUT", r.path(""), req, r.pass(5)); got.status != 409 || got.code() != protocol.CodeConflict {
					t.Errorf("a statement %s: %d %s, want 409 conflict", what, got.status, got.body)
				}
			}

			e.want(e.do("PUT", r.path("/revocations"), r.certs(3), ""), 200, "")
			e.want(e.do("PUT", r.path(""), r.registration(3), ""), 401, protocol.CodeCertificateRevoked)
			rev, err := protocol.SignRevocation(r.signer, r.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), 201, "")
			e.want(e.do("PUT", r.path(""), bad, r.pass(5)), 410, protocol.CodeRevoked)
		})
	}
}

// mailboxReads counts the reads of address a's record.
type mailboxReads struct {
	Store
	a protocol.Address
	n atomic.Int32
}

func (s *mailboxReads) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.a {
		s.n.Add(1)
	}
	return s.Store.Mailbox(ctx, a)
}

// readOnce is an env with limits l whose memory holds no mailbox, and a call of
// it that wants a registration answered with status and code, and its
// address read once.
func readOnce(t *testing.T, l Limits) (*env, func(what string, r *raw, req protocol.RegisterRequest, pass string, status int, code protocol.Code)) {
	t.Helper()
	reads := &mailboxReads{}
	e := newEnv(t, l, func(c *Config) { reads.Store, c.Store = c.Store, unknownStore{reads} })
	return e, func(what string, r *raw, req protocol.RegisterRequest, pass string, status int, code protocol.Code) {
		t.Helper()
		reads.a = r.id.Address()
		reads.n.Store(0)
		e.want(e.do("PUT", r.path(""), req, pass), status, code)
		if n := reads.n.Load(); n != 1 {
			t.Errorf("%s: %d reads of its address, want 1", what, n)
		}
	}
}

// A registration that memory cannot answer reads what is kept of its address
// once, under the registrations it would spend, reserved before the read, and
// no more: one that makes a mailbox, one of an address whose identity revoked
// certificates before it had a mailbox, and one answered from a registered mailbox's
// record (register; dromas-dev/dromas-server#94,
// dromas-dev/dromas-client#410).
func TestARegistrationReadsItsAddressOnce(t *testing.T) {
	t.Parallel()
	e, once := readOnce(t, relaxed())
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("a new mailbox", r, r.registration(1), r.pass(1), 201, "")
	once("a registered mailbox, its statement again", r, r.registration(1), r.pass(1), 200, "")
	r.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("a registered mailbox, another statement", r, r.registration(2), r.pass(2), 409, protocol.CodeConflict)

	m := e.raw()
	e.want(e.do("PUT", m.path("/revocations"), m.certs(2), ""), 200, "")
	m.prekey(5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("an address whose identity revoked certificates", m, m.registration(5), m.pass(5), 201, "")
}

// So it is where its address's registrations are spent, when the read is a
// lookup's, under a miss (register; dromas-dev/dromas-client#450 item 3):
// the mailbox's identical retry, another statement, and a registration of a new
// address, refused for the registrations, each read the address once.
func TestARegistrationReadsItsAddressOnceWithItsRegistrationsSpent(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RegistrationsPerHour = 1
	e, once := readOnce(t, l)
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("a new mailbox, the address's one registration", r, r.registration(1), r.pass(1), 201, "")
	once("a registered mailbox, its statement again", r, r.registration(1), r.pass(1), 200, "")
	r.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("a registered mailbox, another statement", r, r.registration(2), r.pass(2), 409, protocol.CodeConflict)
	n := e.raw()
	n.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	once("a new address", n, n.registration(1), n.pass(1), 429, protocol.CodeRateLimited)
}

func TestOwnerCalls(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)

	e.want(e.do("GET", r.path("/messages"), nil, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, "Bearer "+strings.Repeat("a", 50)), 401, protocol.CodeUnauthorized)
	// One character of the signature changed, in a pass not yet shown and in
	// one the server has already taken.
	flip := func(p string) string {
		i := strings.Index(p, `signature="`) + 200
		c := "A"
		if p[i] == 'A' {
			c = "B"
		}
		return p[:i] + c + p[i+1:]
	}
	e.want(e.do("GET", r.path("/messages"), nil, flip(pass)), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, flip(pass)), 401, protocol.CodeUnauthorized)
	// Another mailbox's pass is not this mailbox's, and neither is this mailbox's pass
	// made for another server.
	o := e.raw().register(time.Hour)
	e.want(e.do("GET", r.path("/messages"), nil, o.pass(1)), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, e.passFor(r.by[1], r.id.Address(), "another.example")), 401, protocol.CodeUnauthorized)
	// A working key the identity certified, which the server never saw a
	// prekey under, is not the mailbox's current one.
	e.want(e.do("GET", r.path("/messages"), nil, e.passFor(r.certify(2), r.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)

	empty := e.do("GET", r.path("/messages"), nil, pass)
	e.want(empty, 200, "")
	if string(bytes.TrimSpace(empty.body)) != `{"count":0,"messages":[],"next_cursor":null}` || empty.header.Get("Retry-After") != "60" {
		t.Fatalf("empty list %s", empty.body)
	}
	e.want(e.do("GET", r.path("/messages?cursor=zzz"), nil, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages?limit=5"), nil, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages/"+strings.Repeat("a", 64)), nil, pass), 404, protocol.CodeNoSuchMessage)
	e.want(e.do("DELETE", r.path("/messages/"+strings.Repeat("a", 64)), nil, pass), 404, protocol.CodeNoSuchMessage)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+r.path("/token"), nil)
	req.Header.Set("Authorization", pass)
	if resp, err := http.DefaultClient.Do(req); err != nil || (resp.StatusCode != 404 && resp.StatusCode != 405) {
		t.Fatalf("POST …/token is still a route: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	// A pass is taken until it runs out, and not a second longer, whether or
	// not the server has taken it before; then the mailbox signs another.
	e.clock.Add(protocol.PassLifetime - time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.clock.Add(time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 401, protocol.CodePassExpired)
	pass = r.pass(1)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	// One that runs out more than an hour ahead is refused as one run out is.
	e.clock.Add(protocol.MaxPassLifetime - protocol.PassLifetime + time.Second)
	ahead := r.pass(1)
	e.clock.Add(-(protocol.MaxPassLifetime - protocol.PassLifetime + time.Second))
	e.want(e.do("GET", r.path("/messages"), nil, ahead), 401, protocol.CodePassExpired)
	e.clock.Add(time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, ahead), 200, "")
}

// An address in a path is 77 characters of lowercase base32, so a mailbox has one URL:
// the same address in uppercase is no address, on every route that names
// one, whoever calls (PROTOCOL.md §2.2).
func TestAnAddressInAPathIsLowercase(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)
	upper := "/v1/" + strings.ToUpper(r.id.Address().String())
	lower := r.id.Address().String()
	i := strings.IndexAny(lower, "abcdef") // one letter in uppercase
	mixed := "/v1/" + lower[:i] + strings.ToUpper(lower[i:i+1]) + lower[i+1:]
	for _, c := range []struct{ method, path, pass string }{
		{"GET", upper, ""},
		{"GET", mixed, ""},
		{"GET", upper + "/messages", pass},
		{"GET", upper + "/messages/" + strings.Repeat("a", 64), pass},
		{"DELETE", upper + "/messages/" + strings.Repeat("a", 64), pass},
		{"GET", upper + "/acl", pass},
		{"DELETE", upper + "/account", pass},
	} {
		e.want(e.do(c.method, c.path, nil, c.pass), 400, protocol.CodeBadAddress)
	}
	e.want(e.do("PUT", upper+"/prekey", r.upload(1), pass), 400, protocol.CodeBadAddress)
	e.want(e.do("GET", r.path(""), nil, ""), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
}

// A query parameter a call does not take, and one given twice, is refused
// as a member a body should not hold is: 400 bad_request, naming it in
// member (PROTOCOL.md §11.2). A cursor not of a cursor's form is named too.
// The send's own parameters are TestSendPipeline's.
func TestAQueryHoldsOnlyTheCallsParameters(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)
	id := strings.Repeat("a", 64)
	for _, c := range []struct {
		method, path string
		body         any
		pass, member string
	}{
		{"GET", r.path("/messages?limit=5"), nil, pass, "limit"},
		{"GET", r.path("/messages?cursor=x&limit=5"), nil, pass, "limit"},
		{"GET", r.path("/messages?cursor=zzz&cursor=zzz"), nil, pass, "cursor"},
		{"GET", r.path("/messages?cursor=zzz"), nil, pass, "cursor"},
		{"GET", r.path("/messages?cursor="), nil, pass, "cursor"},
		{"GET", r.path("/messages?cursor=" + url.QueryEscape(strings.Repeat("A", 52)+"/a")), nil, pass, "cursor"},
		{"GET", r.path("/messages?Cursor=x"), nil, pass, "Cursor"},
		{"GET", r.path("?x=1"), nil, "", "x"},
		{"GET", r.path("?prekey_serial=1"), nil, pass, "prekey_serial"},
		{"PUT", r.path("/prekey?x"), r.upload(1), pass, "x"},
		{"GET", r.path("/acl?x=1"), nil, pass, "x"},
		{"GET", r.path("/messages/" + id + "?x=1"), nil, pass, "x"},
		{"DELETE", r.path("/messages/" + id + "?x=1"), nil, pass, "x"},
	} {
		got := e.do(c.method, c.path, c.body, c.pass)
		var p protocol.Problem
		_ = json.Unmarshal(got.body, &p)
		if got.status != 400 || p.Code != protocol.CodeBadRequest || p.Member != c.member || !strings.Contains(p.Detail, c.member) {
			t.Errorf("%s %s: %d %s, member %q; want 400 %s naming %s", c.method, c.path, got.status, p.Code, p.Member, protocol.CodeBadRequest, c.member)
		}
	}
	// A query that does not parse names nothing.
	e.want(e.do("GET", r.path("/messages?%zz"), nil, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
}

// A list's query is read before its pass, the cursor's decode included
// (PROTOCOL.md §11.11): a cursor that is empty, not of a cursor's form, or not
// one this server could have made is 400 naming cursor, with a pass or none.
func TestACursorIsReadBeforeThePass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	for _, q := range []string{"?cursor=", "?cursor=a%2Fb", "?cursor=zzz"} {
		for _, pass := range []string{"", r.pass(1)} {
			got := e.do("GET", r.path("/messages"+q), nil, pass)
			if got.status != 400 || got.code() != protocol.CodeBadRequest || got.problem().Member != "cursor" {
				t.Errorf("%s, pass %v: %d %s, member %q; want 400 bad_request naming cursor", q, pass != "", got.status, got.code(), got.problem().Member)
			}
		}
	}
}

// A call with two Authorization lines carries no pass, whatever each holds:
// which of them is the pass is not the server's to choose. It is refused as
// a call that carries no pass is. The read of a mailbox reads none, so it is
// answered with two as with none (dromas-dev/dromas-client#352).
func TestTwoAuthorizationLinesAreNoPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	a, b := e.mailbox(), e.mailbox()
	pass := e.pass(b)
	twice := func(method, path string, body []byte, lines ...string) reply {
		t.Helper()
		req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
		for _, l := range lines {
			req.Header.Add("Authorization", l)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		return reply{status: resp.StatusCode, header: resp.Header, body: got}
	}
	messages := "/v1/" + b.Address().String() + "/messages"
	e.want(e.do("GET", messages, nil, pass), 200, "") // taken, and remembered
	for _, lines := range [][]string{{pass, pass}, {pass, "x"}, {"x", pass}, {pass, ""}} {
		got := twice("GET", messages, nil, lines...)
		e.want(got, 401, protocol.CodeUnauthorized)
		if got.header.Get("WWW-Authenticate") != protocol.PassScheme {
			t.Errorf("WWW-Authenticate %q", got.header.Get("WWW-Authenticate"))
		}
	}
	seal := e.sealTo(b)
	e.want(twice("POST", messages+"?"+seal.Encode(), seal.ciphertext, e.pass(a), e.pass(a)), 401, protocol.CodeUnauthorized)
	e.want(twice("GET", "/v1/"+b.Address().String(), nil, e.pass(a), e.pass(a)), 200, "")
	e.want(e.do("POST", messages, seal, e.pass(a)), 201, "")
	e.want(e.do("GET", messages, nil, pass), 200, "")
}

// A pass is made for one server, by the name the mailbox calls it. A server
// takes one only on a request that calls it by a name of its own: the name
// is not sent with the pass, so checked against whatever name a request
// gives, a pass made for another server would pass here.
func TestAPassIsForOneServer(t *testing.T) {
	t.Parallel()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	e := &env{t: t, clock: clk, store: NewMemStore(clk.Now)}
	e.srv = httptest.NewServer(apitest.Handler(t, New(Config{Store: e.store, Limits: relaxed(), Now: clk.Now, Names: []string{"mail.example", "mail.example:8443"}}).Handler()))
	t.Cleanup(e.srv.Close)
	r := e.raw()
	r.prekey(1, clk.Now().Add(time.Hour), nil)
	ours := e.passFor(r.by[1], r.id.Address(), "mail.example")
	theirs := e.passFor(r.by[1], r.id.Address(), "another.example")

	// Called by a name that is not its own, the server takes no pass: not
	// one made for that name, and not one made for its own.
	e.want(e.doAs("another.example", "PUT", r.path(""), r.registration(1), theirs), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("another.example", "PUT", r.path(""), r.registration(1), ours), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), r.registration(1), e.passFor(r.by[1], r.id.Address(), e.name())), 401, protocol.CodeUnauthorized)
	// Called by its own name: the pass made for that name, and no other.
	e.want(e.doAs("mail.example", "PUT", r.path(""), r.registration(1), theirs), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("mail.example", "PUT", r.path(""), r.registration(1), ours), 201, "")
	e.want(e.doAs("MAIL.example", "GET", r.path("/messages"), nil, ours), 200, "")
	e.want(e.doAs("mail.example:8443", "GET", r.path("/messages"), nil, e.passFor(r.by[1], r.id.Address(), "mail.example:8443")), 200, "")
	e.want(e.doAs("mail.example", "GET", r.path("/messages"), nil, theirs), 401, protocol.CodeUnauthorized)
	// A pass the server has taken is taken again only as that pass: the
	// same mailbox's pass for another server stays refused.
	e.want(e.doAs("mail.example", "GET", r.path("/messages"), nil, ours), 200, "")
	e.want(e.doAs("another.example", "GET", r.path("/messages"), nil, theirs), 401, protocol.CodeUnauthorized)
}

// The server writes the Host a request names as an origin is written, as a
// client writes the server's name in its pass (PROTOCOL.md §8): its port as
// a number, and none at all for 443 or 80, whichever scheme the client
// called it by, which TLS ending in front of the server hides. So a mailbox whose
// URL is https://mail.example:443 signs its pass for mail.example, and its
// call names mail.example:443. Each pass here is a new one, a second later:
// one the server has taken is taken again without its name being read.
func TestTheServerReadsItsHostAsAnOrigin(t *testing.T) {
	t.Parallel()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	e := &env{t: t, clock: clk, store: NewMemStore(clk.Now)}
	e.srv = httptest.NewServer(apitest.Handler(t, New(Config{Store: e.store, Limits: relaxed(), Now: clk.Now, Names: []string{"mail.example", "mail.example:8443"}}).Handler()))
	t.Cleanup(e.srv.Close)
	r := e.raw()
	r.prekey(1, clk.Now().Add(time.Hour), nil)
	pass := func(name string) string {
		clk.Add(time.Second)
		return e.passFor(r.by[1], r.id.Address(), name)
	}
	// A pass that names the default port is not for the name the server
	// writes, which leaves it out.
	e.want(e.doAs("mail.example:443", "PUT", r.path(""), r.registration(1), pass("mail.example:443")), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("mail.example:443", "PUT", r.path(""), r.registration(1), pass("mail.example")), 201, "")
	for host, name := range map[string]string{
		"mail.example:80":    "mail.example",
		"MAIL.example:0443":  "mail.example",
		"mail.example:08443": "mail.example:8443",
	} {
		e.want(e.doAs(host, "GET", r.path("/messages"), nil, pass(name)), 200, "")
	}
	// A port that is no default stays, and must be the pass's.
	e.want(e.doAs("mail.example:8443", "GET", r.path("/messages"), nil, pass("mail.example")), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("mail.example:80", "GET", r.path("/messages"), nil, pass("mail.example:80")), 401, protocol.CodeUnauthorized)
}

func TestPrekeyRenewal(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	put := func(serial, by uint64) reply {
		return e.do("PUT", r.path("/prekey"), r.upload(serial), r.pass(by))
	}
	poll := func(pass string) reply { return e.do("GET", r.path("/messages"), nil, pass) }
	identityPass := func() string { return e.passFor(r.signer, r.id.Address(), e.name()) }

	unknown := e.raw()
	unknown.prekey(2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", unknown.path("/prekey"), unknown.upload(2), unknown.pass(2)), 404, protocol.CodeNoSuchMailbox)

	// In identity mode the identity signs every statement and every pass.
	e.want(put(1, 1), 200, "") // an identical retry of the current statement
	r.prekey(2, now.Add(time.Hour), r.keys[1])
	e.want(put(2, 2), 400, protocol.CodePrekeyNotNew) // the same key again
	r.prekey(2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), unknown.pass(2)), 401, protocol.CodeUnauthorized)
	e.want(put(2, 2), 200, "")
	r.prekey(1, now.Add(2*time.Hour), nil)
	e.want(put(1, 1), 409, protocol.CodeConflict) // under the same signer the serial must rise
	// A certificate takes nothing from an address in identity mode: its
	// statement is identity_mode, and a pass under it is not the identity's,
	// which certificate_not_current says naming no certificate.
	r.prekeyUnder(r.certify(5), 3, now.Add(time.Hour), nil)
	e.want(put(3, 3), 409, protocol.CodeIdentityMode)
	e.wantNotCurrent(poll(r.pass(3)), 0)
	e.want(poll(identityPass()), 200, "")

	// The trip: from it on, the identity's statements and passes are
	// refused, as is a certificate at or below it.
	r.trip()
	e.want(poll(identityPass()), 401, protocol.CodeCertificateRevoked)
	r.prekeyUnder(r.signer, 3, now.Add(time.Hour), nil)
	e.want(put(3, 3), 401, protocol.CodeCertificateRevoked)
	r.prekeyUnder(r.certify(tripAt), 3, now.Add(time.Hour), nil)
	e.want(put(3, 3), 401, protocol.CodeCertificateRevoked)
	// A certificate above it passes the identity's statement at any serial.
	r.prekeyUnder(r.certify(2), 1, now.Add(time.Hour), nil)
	e.want(put(1, 1), 200, "")
	old := r.pass(1)
	e.want(poll(old), 200, "")
	e.want(poll(identityPass()), 401, protocol.CodeCertificateRevoked)

	// A statement under the next certificate, with a pass under the
	// mailbox's current certificate and not its own.
	r.prekeyUnder(r.certify(3), 2, now.Add(time.Hour), nil)
	e.wantNotCurrent(e.do("PUT", r.path("/prekey"), r.upload(2), old), 3) // the statement's certificate, which an upload's pass is under
	e.want(put(2, 2), 200, "")
	// The mailbox is now known by certificate 3: the pass under 2, taken a
	// moment ago, is refused, and so is a statement under 2.
	e.wantNotCurrent(poll(old), 3)
	e.want(poll(r.pass(2)), 200, "")
	r.prekeyUnder(r.work[2], 9, now.Add(time.Hour), nil)
	e.want(put(9, 9), 401, protocol.CodeCertificateNotCurrent)
	// Another certificate of the current serial is not the current one.
	current := r.work[3]
	r.prekeyUnder(r.certify(3), 3, now.Add(time.Hour), nil)
	e.want(put(3, 3), 401, protocol.CodeCertificateNotCurrent)
	// A higher serial under the current certificate is taken.
	r.work[3] = current
	r.prekeyUnder(current, 3, now.Add(time.Hour), nil)
	e.want(put(3, 3), 200, "")
	e.want(poll(r.pass(3)), 200, "")
	r.prekeyUnder(current, 4, now.Add(time.Hour), r.keys[2])
	e.want(put(4, 4), 400, protocol.CodePrekeyNotNew) // a live retired key
	// Under the mailbox's current certificate the serial must rise.
	r.prekeyUnder(current, 3, now.Add(2*time.Hour), nil)
	e.want(put(3, 3), 409, protocol.CodeConflict)

	// A certificate that has ended signs nothing, exact at the server's
	// clock: no statement and no pass.
	e.clock.Add(DefaultLimits().MaxCertificateLifetime)
	r.prekeyUnder(current, 5, e.clock.Now().Add(time.Hour), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(5), ""), 400, protocol.CodePrekeyTime)
	e.want(poll(e.passFor(current, r.id.Address(), e.name())), 401, protocol.CodePassExpired)
	// The mailbox comes back with a prekey under a new one.
	r.prekeyUnder(r.certify(5), 5, e.clock.Now().Add(time.Hour), nil)
	e.want(put(5, 5), 200, "")
	e.want(poll(r.pass(5)), 200, "")

	// A mailbox's statements are ordered by rank first. A later certificate
	// passes any serial under an earlier one: the mailbox moves to
	// certificate 6 at prekey serial 1, below the 5 it stood at, and the
	// serial rises from there. An earlier certificate is refused whatever
	// serial comes under it.
	r.prekeyUnder(r.certify(6), 1, e.clock.Now().Add(time.Hour), nil)
	e.want(put(1, 1), 200, "")
	e.want(poll(r.pass(1)), 200, "")
	e.want(poll(r.pass(5)), 401, protocol.CodeCertificateNotCurrent)
	r.prekeyUnder(r.work[6], 1, e.clock.Now().Add(2*time.Hour), nil)
	e.want(put(1, 1), 409, protocol.CodeConflict)
	r.prekeyUnder(r.work[5], 9, e.clock.Now().Add(time.Hour), nil)
	e.want(put(9, 9), 401, protocol.CodeCertificateNotCurrent)
	r.prekeyUnder(r.work[6], 2, e.clock.Now().Add(time.Hour), nil)
	e.want(put(2, 2), 200, "")
}

func TestSendPipeline(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	bMailbox, _ := e.store.Mailbox(ctx, b.Address())
	pqRecipient, _ := bMailbox.Prekey.Recipient()

	// seal encrypts to the given recipients. What is inside is the
	// recipient's to judge: the server sees an age file and a pass.
	seal := func(rs ...age.Recipient) sealed {
		var ct bytes.Buffer
		w, err := age.Encrypt(&ct, rs...)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		return sealedTo(e.statement(b.Address()), ct.Bytes())
	}
	to := "/v1/" + b.Address().String()
	ok := seal(pqRecipient)
	classic, _ := age.GenerateX25519Identity()
	pass := e.pass(a)

	// The pass comes first: with none, nothing of the request is judged,
	// its query and its address included.
	e.want(e.do("POST", to+"/messages", ok, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("POST", to+"/messages?statement=0", ok.ciphertext, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("POST", "/v1/nope/messages", ok, ""), 401, protocol.CodeUnauthorized)

	// Then the address, then the query: the statement's hash, once, 64
	// lowercase hex digits, and nothing else. What is wrong is named in
	// member. The sender is the mailbox the pass names, so the query names
	// none.
	e.want(e.do("POST", "/v1/nope/messages?x=1", ok.ciphertext, pass), 400, protocol.CodeBadAddress)
	e.want(e.do("POST", "/v1/"+strings.ToUpper(b.Address().String())+"/messages", ok, pass), 400, protocol.CodeBadAddress)
	serials := ok.Encode()
	hash := ok.Statement
	for query, member := range map[string]string{
		"":                                        protocol.StatementParam,
		"statement=":                              protocol.StatementParam,
		"statement=" + strings.ToUpper(hash):      protocol.StatementParam,
		"statement=" + hash[:63]:                  protocol.StatementParam,
		"statement=" + hash + "0":                 protocol.StatementParam,
		"statement=" + hash[:63] + "g":            protocol.StatementParam,
		"prekey_serial=1&certificate_serial=1":    "certificate_serial",
		serials + "&prekey_serial=1":              "prekey_serial",
		serials + "&" + serials:                   protocol.StatementParam,
		serials + "&from=" + a.Address().String(): "from",
		serials + "&STATEMENT=" + hash:            "STATEMENT",
	} {
		got := e.do("POST", to+"/messages?"+query, ok.ciphertext, pass)
		var p protocol.Problem
		_ = json.Unmarshal(got.body, &p)
		if got.status != 400 || p.Code != protocol.CodeBadRequest || p.Member != member || !strings.Contains(p.Detail, member) {
			t.Errorf("?%s: %d %s, member %q; want 400 %s naming %s", query, got.status, p.Code, p.Member, protocol.CodeBadRequest, member)
		}
	}
	e.want(e.do("POST", to+"/messages?statement="+strings.Repeat("0", 64), ok.ciphertext, pass), 409, protocol.CodeStalePrekey)

	// The body is the ciphertext's bytes, whatever its Content-Type says. A
	// body that is no age file, a JSON object of a send's fields among them, is
	// refused as no age file.
	j, _ := json.Marshal(map[string]any{"statement": ok.Statement, "ciphertext": ok.ciphertext})
	for name, body := range map[string][]byte{"no body": nil, "a JSON object": j, "text": []byte("not an age file")} {
		if got := e.do("POST", to+"/messages?"+serials, body, pass); got.status != 400 || got.code() != protocol.CodeNotAge {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeNotAge)
		}
	}
	e.want(e.do("POST", to+"/messages", seal(classic.Recipient()), pass), 400, protocol.CodeWrongRecipientType)
	two, _ := age.GenerateHybridIdentity()
	e.want(e.do("POST", to+"/messages", seal(pqRecipient, two.Recipient()), pass), 400, protocol.CodeWrongRecipientType)
	// The statement's hash is the current one's: of its bytes as served,
	// never of its signature, and of no other statement.
	cur := mustMailbox(t, e, b.Address())
	for name, named := range map[string][]byte{
		"another statement":               append(slices.Clone(cur.Statement), 'x'),
		"the statement's signature":       cur.Signature,
		"the statement and its signature": append(slices.Clone(cur.Statement), cur.Signature...),
	} {
		stale := ok
		stale.Statement = protocol.StatementHash(named)
		got := e.do("POST", to+"/messages", stale, pass)
		e.want(got, 409, protocol.CodeStalePrekey)
		if p := got.problem(); p.PrekeySerial != nil || p.CertificateSerial != nil {
			t.Errorf("%s: stale_prekey carries members: %s", name, got.body)
		}
	}

	big := relaxed()
	big.MaxSize = 100
	small := newEnv(t, big)
	sa, sb := small.mailbox(), small.mailbox()
	if _, err := sa.Send(ctx, sb.Address(), strings.Repeat("x", 200)); codeOf(err) != protocol.CodeTooLarge {
		t.Fatalf("send over the cap: %v", err)
	}
	// The body is read to the sender's cap, the ciphertext's bytes, and no
	// further: past it is too_large with the cap in limit, whether a
	// Content-Length says so before the body is read or the body runs past
	// it as it arrives. The address and the query are judged first.
	sto, spass := "/v1/"+sb.Address().String()+"/messages", small.pass(sa)
	tooLarge := func(r reply) {
		t.Helper()
		var p protocol.Problem
		if err := json.Unmarshal(r.body, &p); err != nil || r.status != 413 || p.Code != protocol.CodeTooLarge || p.Limit == nil || *p.Limit != 100 {
			t.Fatalf("over the cap: %d %s", r.status, r.body)
		}
	}
	small.want(small.do("POST", sto+"?x=1", make([]byte, 101), spass), 400, protocol.CodeBadRequest)
	small.want(small.do("POST", "/v1/nope/messages?"+serials, make([]byte, 101), spass), 400, protocol.CodeBadAddress)
	tooLarge(small.do("POST", sto+"?"+serials, make([]byte, 101), spass))
	small.want(small.do("POST", sto+"?"+serials, make([]byte, 100), spass), 400, protocol.CodeNotAge)
	// A body of no known length goes chunked, with no Content-Length.
	chunked, _ := http.NewRequest(http.MethodPost, small.srv.URL+sto+"?"+serials, io.MultiReader(bytes.NewReader(make([]byte, 101))))
	chunked.Header.Set("Authorization", spass)
	resp, err := http.DefaultClient.Do(chunked)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	tooLarge(reply{status: resp.StatusCode, header: resp.Header, body: body})

	// A pass that names no mailbox here, and a recipient that is none.
	unregistered := e.raw()
	unregistered.prekey(1, e.clock.Now().Add(time.Hour), nil)
	e.want(e.do("POST", to+"/messages", ok, unregistered.pass(1)), 403, protocol.CodeUnknownSender)
	e.want(e.do("POST", "/v1/"+unregistered.id.Address().String()+"/messages", ok, pass), 404, protocol.CodeNoSuchMailbox)
	// A pass that is not the mailbox's it names: under a certificate the server
	// never saw, and with its signature changed.
	other := e.raw()
	other.signer, other.id = signer(t, a), a.Identity()
	e.want(e.do("POST", to+"/messages", ok, e.passFor(other.certify(7), a.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)
	e.clock.Add(-protocol.PassLifetime)
	ranOut := e.pass(a)
	e.clock.Add(protocol.PassLifetime)
	e.want(e.do("POST", to+"/messages", ok, ranOut), 401, protocol.CodePassExpired)

	// A registered sender the server has since forgotten.
	c := e.raw().register(time.Hour)
	if err := e.store.DeleteMailbox(t.Context(), c.id.Address()); err != nil { // as the TTL deletes it
		t.Fatal(err)
	}
	e.want(e.do("POST", to+"/messages", ok, c.pass(1)), 403, protocol.CodeUnknownSender)

	first := e.do("POST", to+"/messages", ok, pass)
	e.want(first, 201, "")
	retry := e.do("POST", to+"/messages", ok, pass)
	e.want(retry, 200, "")
	if !bytes.Equal(first.body, retry.body) {
		t.Fatalf("a retry's receipt %s is not the original %s", retry.body, first.body)
	}
	// The same ciphertext under another mailbox's pass: the receipt held, as
	// for any post of bytes the mailbox holds unacked (PROTOCOL.md §11.10 step
	// 6), and nothing new stored.
	d := e.mailbox()
	again := e.do("POST", to+"/messages", ok, e.pass(d))
	e.want(again, 200, "")
	if !bytes.Equal(first.body, again.body) {
		t.Fatalf("another sender's post of the same bytes: receipt %s, not the original %s", again.body, first.body)
	}
	// What the recipient is handed: in the list, the id and the
	// ciphertext's size, and no sender (§11.11); on the fetch, the
	// ciphertext exactly as posted, and nothing else.
	var rcpt protocol.Receipt
	_ = json.Unmarshal(first.body, &rcpt)
	listed := e.do("GET", "/v1/"+b.Address().String()+"/messages", nil, e.pass(b))
	list := listOf(t, listed)
	if len(list.Messages) != 1 || list.Messages[0].ID != rcpt.ID || list.Messages[0].Size != int64(len(ok.ciphertext)) {
		t.Fatalf("the list: %+v", list)
	}
	if bytes.Contains(listed.body, []byte(`"from"`)) {
		t.Fatalf("the list names a sender: %s", listed.body)
	}
	fetched := e.do("GET", "/v1/"+b.Address().String()+"/messages/"+rcpt.ID, nil, e.pass(b))
	e.want(fetched, 200, "")
	if !bytes.Equal(fetched.body, ok.ciphertext) || fetched.header.Get("Content-Type") != protocol.CiphertextContentType ||
		fetched.header.Get("Content-Length") != strconv.Itoa(len(ok.ciphertext)) {
		t.Fatalf("a fetched message: %v, %d bytes", fetched.header, len(fetched.body))
	}

	// Revoked addresses, A a sender and F a recipient, each kept as the route
	// keeps it: by its identity's own signature, with the mailbox's record left
	// in place, which the revocation answers for. The route itself is
	// TestRevocation.
	f := e.mailbox()
	for _, mailbox := range []*client.Mailbox{a, f} {
		rv := record(t, mailbox)
		if err := e.store.Revoke(ctx, mailbox.Address(), &Revocations{Identity: rv.Identity, Address: rv.Revocation}, ExpectAnything); err != nil {
			t.Fatal(err)
		}
	}
	e.want(e.do("POST", to+"/messages", seal(pqRecipient), pass), 403, protocol.CodeSenderRevoked)
	e.want(e.do("POST", "/v1/"+f.Address().String()+"/messages", seal(pqRecipient), e.pass(d)), 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String(), nil, ""), 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, pass), 410, protocol.CodeRevoked)

	// An expired recipient prekey.
	e.clock.Add(protocol.MaxPrekeyLifetime)
	e.want(e.do("POST", to+"/messages", seal(pqRecipient), e.pass(d)), 409, protocol.CodePrekeyExpired)
}

// greaseRecipient adds a grease stanza, as rage and pyrage do.
type greaseRecipient struct{}

func (greaseRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "x-grease", Args: []string{"a", "b"}, Body: []byte("junk")}}, nil
}

func (g greaseRecipient) WrapWithLabels(k []byte) ([]*age.Stanza, []string, error) {
	return postQuantum{g}.WrapWithLabels(k)
}

// postQuantum is r, labelled post-quantum, as age requires of a recipient
// beside a post-quantum one: a stanza of r beside the mailbox's own.
type postQuantum struct{ r age.Recipient }

func (p postQuantum) Wrap(k []byte) ([]*age.Stanza, error) { return p.r.Wrap(k) }

func (p postQuantum) WrapWithLabels(k []byte) ([]*age.Stanza, []string, error) {
	s, err := p.r.Wrap(k)
	return s, []string{"postquantum"}, err
}

func TestGreaseIsIgnored(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	bMailbox, _ := e.store.Mailbox(ctx, b.Address())
	rcpt, _ := bMailbox.Prekey.Recipient()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rcpt, greaseRecipient{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "x")
	_ = w.Close()
	e.want(e.do("POST", "/v1/"+b.Address().String()+"/messages", sealedTo(e.statement(b.Address()), ct.Bytes()), e.pass(a)), 201, "")
}

// A file whose one stanza is grease has no native stanza: it is not said to
// have more than one (dromas-dev/dromas-client#417 item 4), and is told
// it has no recipient, as PROTOCOL.md §11.10 step 7 has it. Its stanzas are
// read as a reader reads them (protocol.ReadStanzas).
func TestAFileWithNoNativeStanzaIsNotSaidToHaveTwo(t *testing.T) {
	t.Parallel()
	var ct bytes.Buffer
	w, _ := age.Encrypt(&ct, greaseRecipient{})
	_ = w.Close()
	st, err := protocol.ReadStanzas(ct.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	p := checkStanzas(st, nil)
	if p == nil || strings.Contains(p.detail, "more than one") || p.hint == "encrypt to one recipient only" || p.hint != "the file has no recipient: encrypt to the mailbox's prekey" {
		t.Fatalf("%d native stanza(s): %+v", len(st.Native), p)
	}
}

// otherRecipient adds a stanza of a type that is neither native nor grease.
type otherRecipient struct{}

func (otherRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "x-other", Body: []byte("junk")}}, nil
}

func (o otherRecipient) WrapWithLabels(k []byte) ([]*age.Stanza, []string, error) {
	return postQuantum{o}.WrapWithLabels(k)
}

// A send whose stanzas a mailbox does not take is refused wrong_recipient_type
// with the hint of its case, in PROTOCOL.md §11.10 step 7's order: a stanza
// of another type first, an X25519 one among them, whatever else the file
// holds; then no native stanza; then more than one.
func TestEachWrongRecipientTypeIsToldItsOwnCase(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	mailbox, _ := e.store.Mailbox(ctx, b.Address())
	own, err := mailbox.Prekey.Recipient()
	if err != nil {
		t.Fatal(err)
	}
	stranger, _ := age.GenerateHybridIdentity()
	x25519, _ := age.GenerateX25519Identity()
	const another, none, two = "encrypt to the mailbox's prekey", "the file has no recipient: encrypt to the mailbox's prekey", "encrypt to one recipient only"
	for _, c := range []struct {
		name string
		rs   []age.Recipient
		hint string
	}{
		{"a stanza of another type beside the mailbox's own", []age.Recipient{own, otherRecipient{}}, another},
		{"a stanza of another type alone", []age.Recipient{otherRecipient{}}, another},
		{"a stanza of another type and two native", []age.Recipient{own, stranger.Recipient(), otherRecipient{}}, another},
		{"a stanza of another type and grease", []age.Recipient{greaseRecipient{}, otherRecipient{}}, another},
		{"an X25519 stanza alone", []age.Recipient{x25519.Recipient()}, another},
		{"an X25519 stanza beside the mailbox's own", []age.Recipient{own, postQuantum{x25519.Recipient()}}, another},
		{"grease alone", []age.Recipient{greaseRecipient{}}, none},
		{"two native", []age.Recipient{own, stranger.Recipient()}, two},
		{"two native beside grease", []age.Recipient{greaseRecipient{}, stranger.Recipient(), own}, two},
	} {
		var ct bytes.Buffer
		w, err := age.Encrypt(&ct, c.rs...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		_, _ = io.WriteString(w, "x")
		_ = w.Close()
		got := e.do("POST", "/v1/"+b.Address().String()+"/messages", sealedTo(e.statement(b.Address()), ct.Bytes()), e.pass(a))
		if p := got.problem(); got.status != 400 || p.Code != protocol.CodeWrongRecipientType || p.Hint != c.hint {
			t.Errorf("%s: %d %s, hint %q; want 400 %s, hint %q", c.name, got.status, p.Code, p.Hint, protocol.CodeWrongRecipientType, c.hint)
		}
	}
}

func TestPerIPLimits(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.SendsPerMinutePerIP = 1
	e := newEnv(t, l)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "1")
	_, err := a.Send(context.Background(), b.Address(), "2")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited {
		t.Fatalf("second send in a minute from one IP: %v", err)
	}
	if ae.RetryAfter <= 0 || !strings.Contains(err.Error(), "the server asks to wait "+strconv.Itoa(int(ae.RetryAfter/time.Second))+" seconds") {
		t.Fatalf("the error does not say the wait Retry-After gives (%s): %v", ae.RetryAfter, err)
	}
}

// Behind a proxy every request comes from the proxy's address: per-IP limits
// key on the last address of X-Forwarded-For from a trusted proxy, the one
// that proxy wrote, and on the peer otherwise, so no one outside can pick
// their own bucket. The limit read here is the one on sends, which is taken
// before a send's pass is looked at.
func TestClientIPFromTrustedProxy(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.SendsPerMinutePerIP = 1
	clk := time.Now()
	store := NewMemStore(func() time.Time { return clk })
	for _, c := range []struct {
		name    string
		trusted []netip.Prefix
		second  int // the status of a second call from another client
	}{
		{"trusted peer: one bucket per client", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, http.StatusUnauthorized},
		{"untrusted peer: the header is ignored", nil, http.StatusTooManyRequests},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: store, Limits: l, TrustedProxies: c.trusted}).Handler()))
			defer srv.Close()
			call := func(ip string) int {
				req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/"+protocol.Address{1}.String()+"/messages", nil)
				req.Header.Set("X-Forwarded-For", ip)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			if got := call("192.0.2.1"); got != http.StatusUnauthorized {
				t.Fatalf("first call: %d", got)
			}
			if got := call("192.0.2.2"); got != c.second {
				t.Fatalf("second call, another client: %d, want %d", got, c.second)
			}
			if c.trusted != nil {
				if got := call("192.0.2.1"); got != http.StatusTooManyRequests {
					t.Fatalf("the same client again: %d, want 429", got)
				}
			}
		})
	}
}

// The client is the LAST address of X-Forwarded-For from a trusted proxy,
// read across every line of it as one list: the entries before it are the
// caller's own words, and CF-Connecting-IP is no proxy's word here at all.
// An entry that is not an address leaves the peer, and so does every header
// from a peer that is not trusted.
func TestTheClientIsTheLastForwardedAddress(t *testing.T) {
	t.Parallel()
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	s := New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), TrustedProxies: loopback})
	other := New(Config{Store: NewMemStore(time.Now), Limits: relaxed()})
	for _, c := range []struct {
		name   string
		s      *Server
		header []string // name, value, …
		want   string
	}{
		{"one address", s, []string{"X-Forwarded-For", "203.0.113.9"}, "203.0.113.9"},
		{"the caller's own entries first", s, []string{"X-Forwarded-For", "192.0.2.1, 198.51.100.7,203.0.113.9"}, "203.0.113.9"},
		{"two lines, one list", s, []string{"X-Forwarded-For", "192.0.2.1", "X-Forwarded-For", "2001:db8::9"}, "2001:db8::9"},
		{"a zone is no part of it", s, []string{"X-Forwarded-For", "fe80::1%eth0"}, "fe80::1"},
		{"the last is not an address", s, []string{"X-Forwarded-For", "203.0.113.9, unknown"}, "127.0.0.1"},
		{"CF-Connecting-IP is not read", s, []string{"CF-Connecting-IP", "203.0.113.9"}, "127.0.0.1"},
		{"no header", s, nil, "127.0.0.1"},
		{"an untrusted peer", other, []string{"X-Forwarded-For", "203.0.113.9"}, "127.0.0.1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:4321"
		for i := 0; i+1 < len(c.header); i += 2 {
			r.Header.Add(c.header[i], c.header[i+1])
		}
		if got := c.s.clientIP(r); got != c.want {
			t.Errorf("%s: the client is %q, want %q", c.name, got, c.want)
		}
	}
}

// A send must name the mailbox's current prekey statement, so after a renewal
// no message is taken for the retired key: a send naming its statement is
// stale, and the refusal carries no members. The mailbox may then delete the
// key.
func TestSendNamesTheCurrentPrekey(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.mailbox(), e.mailbox()
	old, _ := e.store.Mailbox(ctx, b.Address())
	oldRecipient, _ := old.Prekey.Recipient()
	e.clock.Add(20 * 24 * time.Hour) // a renewal well before not_after
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	// sealOld seals to the retired key, naming its statement.
	sealOld := func(body string) sealed {
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, oldRecipient)
		_, _ = io.WriteString(w, body)
		_ = w.Close()
		return sealedTo(old.Statement, ct.Bytes())
	}
	to := "/v1/" + b.Address().String()
	stale := e.do("POST", to+"/messages", sealOld("named the retired statement"), e.pass(a))
	e.want(stale, 409, protocol.CodeStalePrekey)
	if p := stale.problem(); p.PrekeySerial != nil || p.CertificateSerial != nil {
		t.Errorf("stale_prekey carries members: %s", stale.body)
	}
	send(t, a, b, "after the renewal") // to the new key
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want 1", len(res.Delivered))
	}
}

// A mailbox renews its prekey RenewalsPerDay times at once, then is told to wait
// for the next, which comes back a day divided by that number later; an identical retry of the current statement
// is not a renewal. Its record keeps only the RetiredKept newest retired
// prekeys, so a mailbox that renews often cannot grow it.
func TestRenewalLimits(t *testing.T) {
	t.Parallel()
	l := relaxed()
	// The Go client certifies a new working key with each prekey, so each of
	// its renewals is its identity's act, counted under that limit: a
	// renewal under the current certificate counts under the other
	// (TestTheRemedyRenewsWhenATakerSpentTheDaysRenewals).
	l.RenewalsPerDay, l.CertificatesPerDay, l.RetiredKept = 3, 3, 2
	e := newEnv(t, l)
	ctx := context.Background()
	b := e.mailbox()
	var renewed []*protocol.Prekey
	for i := range 3 {
		p, err := b.Rekey(ctx)
		if err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
		renewed = append(renewed, p)
	}
	_, err := b.Rekey(ctx)
	var ae *client.APIError
	if !limitedBy(err, protocol.QuotaCertificates) || !errors.As(err, &ae) || ae.RetryAfter != 8*time.Hour || ae.Problem.Limit == nil || *ae.Problem.Limit != 3 {
		t.Fatalf("a fourth renewal at once, of three a day: %v", err)
	}
	cur, _ := e.store.Mailbox(ctx, b.Address())
	e.want(e.do("PUT", "/v1/"+b.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: cur.Statement, PrekeySignature: cur.Signature}, e.pass(b)), 200, "")
	if len(cur.Retired) != 2 {
		t.Fatalf("the record keeps %d retired prekeys, want 2", len(cur.Retired))
	}
	for i, p := range renewed[:2] { // the first two renewals: the third is current
		if cur.Retired[i].KeyHash != sha256.Sum256([]byte(p.Key)) {
			t.Fatalf("retired[%d] is not prekey %d: the newest are not the ones kept", i, p.Serial)
		}
	}
	e.clock.Add(8*time.Hour - time.Second)
	if _, err := b.Rekey(ctx); !limitedBy(err, protocol.QuotaCertificates) {
		t.Fatalf("a renewal a second before the next comes back: %v", err)
	}
	e.clock.Add(time.Second)
	if _, err := b.Rekey(ctx); err != nil {
		t.Fatalf("a renewal once the next came back: %v", err)
	}
}

// unusedBitsSet returns body with the unused bits of its last base64 field
// that has padding set: the same bytes to a lax decoder, and not base64 in
// its one encoding.
func unusedBitsSet(t *testing.T, body []byte) []byte {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := bytes.LastIndex(body, []byte(`="`))
	for i > 0 && body[i-1] == '=' {
		i--
	}
	if i < 1 {
		t.Fatal("no base64 field with padding in the body")
	}
	c := strings.IndexByte(alphabet, body[i-1])
	if c < 0 || c%4 != 0 {
		t.Fatalf("the last base64 field is not in its one encoding: %q", body[i-1])
	}
	out := append([]byte{}, body...)
	out[i-1] = alphabet[c+1]
	return out
}
