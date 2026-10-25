package server

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// stands reads a box's record and the certificate its current statement is
// signed under.
func (e *env) stands(a protocol.Address) (*Box, *protocol.Certificate) {
	e.t.Helper()
	b, err := e.store.Box(context.Background(), a)
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		e.t.Fatal(err)
	}
	_, cert, err := protocol.VerifyPrekeyRecord(id, b.Statement, b.Signature)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, cert
}

// A box's record may go once nothing of the box is valid any more
// (PROTOCOL.md §13): a registration and every renewal set its expiry to the
// later of its certificate's end and its prekey's last mail.
func TestARecordExpiresWhenNothingOfTheBoxIsValid(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	b, cert := e.stands(r.id.Address())
	if want := b.Prekey.NotAfter.Add(protocol.TTL); !b.Expires.Equal(want) || !want.After(cert.NotAfter()) {
		t.Fatalf("a registration's record expires %v, want its prekey's last mail, %v, which is after its certificate's end %v", b.Expires, want, cert.NotAfter())
	}
	// A prekey that ends early leaves the certificate's end the later.
	r.prekey(2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 200, "")
	b, cert = e.stands(r.id.Address())
	if !b.Expires.Equal(cert.NotAfter()) || !cert.NotAfter().After(b.Prekey.NotAfter.Add(protocol.TTL)) {
		t.Fatalf("a renewal's record expires %v, want its certificate's end, %v", b.Expires, cert.NotAfter())
	}
	// A renewal for the full lifetime moves it back to its prekey's last mail.
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "")
	if b, _ = e.stands(r.id.Address()); !b.Expires.Equal(b.Prekey.NotAfter.Add(protocol.TTL)) {
		t.Fatalf("a renewal for the full lifetime leaves the record expiring %v, want %v", b.Expires, b.Prekey.NotAfter.Add(protocol.TTL))
	}
}

// Once the TTL has deleted a box's record, the box is forgotten: its
// renewal is answered as for no box, and it registers anew, its ACL and its
// account gone with the old one. What its identity revoked stays. A test
// makes the delete the TTL makes.
func TestAForgottenBoxRegistersAnew(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/acl"), aclOf([]string{"*"}, nil), r.pass(1)), 200, "")
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), 200, "")
	r.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 200, "")
	if err := e.store.DeleteBox(ctx, r.id.Address()); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("GET", r.path(""), nil, ""), 404, protocol.CodeNoSuchMailbox)
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 404, protocol.CodeNoSuchMailbox)
	r.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 401, protocol.CodeCertificateRevoked) // still held to what its identity revoked
	e.want(e.do("PUT", r.path(""), r.registration(3), r.pass(3)), 201, "")
	if got := e.do("GET", r.path("/acl"), nil, r.pass(3)); got.status != 200 || string(got.body) != `{"allow":["*"],"deny":[]}`+"\n" {
		t.Fatalf("a box registered anew has an ACL: %d %s", got.status, got.body)
	}
	if b := held(t, e.do("GET", r.path(""), nil, "")); b == nil || len(b.RevokedCertificates) == 0 {
		t.Fatal("a box registered anew is read without its identity's revocation of certificates")
	}
}

// In DynamoDB a box's record carries its expiry as the TTL attribute, in
// seconds, and nothing its identity revoked, which is the item beside it
// (sk 0x01); a revocation of the address deletes the record and keeps the
// item. AWS only.
func TestTheRecordAndTheRevocationsAreTwoItems(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e, s := dynamoEnv(t)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), 200, "")
	get := func(key map[string]types.AttributeValue) item {
		t.Helper()
		out, err := s.dynamo().db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.dynamo().boxes, Key: key, ConsistentRead: aws.Bool(true)})
		if err != nil {
			t.Fatal(err)
		}
		return out.Item
	}
	recKey, revsKey := boxKey(r.id.Address()), revocationsKey(r.id.Address())
	rec, revs := get(recKey), get(revsKey)
	b, _ := e.stands(r.id.Address())
	if exp, err := rec.uint("expires_at"); err != nil || exp != uint64(b.Expires.Unix()) {
		t.Fatalf("the record's TTL attribute is %d (%v), want %d", exp, err, b.Expires.Unix())
	}
	for _, name := range []string{"revocation", "revoked_certs", "revoked_certs_sig", "through"} {
		if _, ok := rec[name]; ok {
			t.Errorf("the record carries %s", name)
		}
	}
	if through, err := revs.uint("through"); err != nil || through != 1 {
		t.Fatalf("the revocations item: through %d, %v", through, err)
	}
	if _, ok := revs["expires_at"]; ok {
		t.Error("the revocations item has an expiry")
	}
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), 201, "")
	if get(recKey) != nil {
		t.Error("the revocation of the address left the box's record")
	}
	if revs = get(revsKey); revs == nil {
		t.Fatal("the revocation of the address left no revocations item")
	}
	if _, ok := revs["revocation"]; !ok {
		t.Error("the revocations item does not keep the revocation of the address")
	}
}

// A second process that holds a box learns from the stream what another
// wrote: a revocation of the box's certificates, and the revocation of its
// address, each answered from its memory once it arrives. AWS only.
func TestASecondProcessLearnsWhatIsRevoked(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	other := startDynamo(t, e.clock.Now)
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	// within waits up to ten seconds for the second process to answer as
	// want: the stream is read every 200 ms.
	within := func(what string, call func() reply, status int, code protocol.Code) {
		t.Helper()
		var r reply
		for range 100 {
			if r = call(); r.status == status && r.code() == code {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: the second process answers %d %s, want %d %s", what, r.status, r.code(), status, code)
	}

	certs := e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(r *raw) func() reply {
		return func() reply {
			return e2.do("GET", r.path("/messages"), nil, e2.passFor(r.work[1], r.id.Address(), e2.name()))
		}
	}
	e2.want(poll(certs)(), 200, "") // the second process holds it
	e.want(e.do("PUT", certs.path("/revocations"), certs.certs(1), ""), 200, "")
	within("the box's certificate revoked", poll(certs), 401, protocol.CodeCertificateRevoked)

	revoked := e.raw().register(protocol.MaxPrekeyLifetime)
	e2.want(poll(revoked)(), 200, "")
	rev, err := protocol.SignRevocation(revoked.signer, revoked.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", revoked.path("/revocations"), protocol.Revocations{Identity: revoked.id.Document(), Revocation: rev}, ""), 201, "")
	within("the address revoked", poll(revoked), 410, protocol.CodeRevoked)
}
