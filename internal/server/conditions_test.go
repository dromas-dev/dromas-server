package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/protocol"
)

// call is one request a test makes.
type call struct {
	method, path string
	body         any
	pass         string
}

// ciphertextTo is an age file to r's prekey 1.
func ciphertextTo(t *testing.T, r *raw) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r.keys[1].Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return ct.Bytes()
}

// holding is a mailbox holding one message, and the message's path.
func holding(e *env) (*raw, string) {
	e.t.Helper()
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	ct := ciphertextTo(e.t, to)
	e.want(e.do(http.MethodPost, to.path("/messages"), to.sealed(1, ct), from.pass(1)), http.StatusCreated, "")
	sum := sha256.Sum256(ct)
	return to, to.path("/messages/" + hex.EncodeToString(sum[:]))
}

// inAccount adopts r into a new account, with a key good for uses more.
func inAccount(e *env, r *raw, uses int) string {
	e.t.Helper()
	_, key := accountEnv(e.t, e, false, uses+1)
	e.want(e.do(http.MethodPut, r.path("/account"), protocol.AdoptRequest{Key: key}, r.pass(1)), http.StatusOK, "")
	return key
}

// Every route evaluates If-Match and If-None-Match, as RFC 9110 §13.1.1 and
// §13.1.2 have an origin server evaluate each it receives, in §13.2.2's
// order, once it knows its target's state and before it acts
// (dromas-dev/dromas-server#86): each route below, its target there or
// not, is sent each of four conditions on a world of its own. A tag no
// target carries: If-Match is 412, If-None-Match holds. "*": If-Match holds
// where the target exists and is 412 where it does not; If-None-Match is 304
// to a GET and 412 to any other method where it exists, and holds where it
// does not. Where a condition is false, nothing the route does is done
// (unchanged).
func TestEveryRouteEvaluatesItsPreconditions(t *testing.T) {
	t.Parallel()
	forms := []struct {
		name, field, value string
	}{
		{"If-Match a tag", "If-Match", `"x"`},
		{"If-Match *", "If-Match", "*"},
		{"If-None-Match *", "If-None-Match", "*"},
		{"If-None-Match a tag", "If-None-Match", `"x"`},
	}
	open := aclOf([]string{"*"}, []string{})
	cases := []struct {
		name   string
		exists bool
		ok     int
		limits func(*Limits)
		setup  func(e *env) call
		// unchanged checks, after a condition that was false, that the
		// route did nothing.
		unchanged func(e *env, c call)
	}{
		{name: "the read of a mailbox", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"GET", r.path(""), nil, ""}
		}},
		{name: "a registration, of a mailbox registered: its identical retry", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"PUT", r.path(""), r.registration(1), r.pass(1)}
		}},
		{name: "a registration, of a mailbox not registered", exists: false, ok: 201, setup: func(e *env) call {
			r := e.raw()
			r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			return call{"PUT", r.path(""), r.registration(1), r.pass(1)}
		}, unchanged: func(e *env, c call) {
			e.want(e.do("GET", c.path, nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
		}},
		{name: "a renewal's identical retry", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"PUT", r.path("/prekey"), r.upload(1), r.pass(1)}
		}},
		{name: "a renewal", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			r.prekey(2, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
			return call{"PUT", r.path("/prekey"), r.upload(2), r.pass(2)}
		}, unchanged: func(e *env, c call) {
			if serial, _ := e.numbers(addressAt(e.t, c.path)); serial != 1 {
				e.t.Fatalf("the mailbox moved to prekey %d", serial)
			}
		}},
		{name: "the read of the revocations held", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
			return call{"GET", r.path("/revocations"), nil, ""}
		}},
		{name: "a revocation, through the serial held again", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
			return call{"PUT", r.path("/revocations"), r.certs(1), ""}
		}},
		{name: "a revocation, raised", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
			return call{"PUT", r.path("/revocations"), r.certs(2), ""}
		}, unchanged: func(e *env, c call) {
			var held protocol.Revocations
			if err := protocol.Unmarshal(e.do("GET", c.path, nil, "").body, &held); err != nil || bytes.Equal(held.RevokedCertificates, c.body.(protocol.Revocations).RevokedCertificates) {
				e.t.Fatalf("the raise was taken: %v", err)
			}
		}},
		{name: "a revocation, of an address with none held", exists: false, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"PUT", r.path("/revocations"), r.certs(1), ""}
		}, unchanged: func(e *env, c call) {
			e.want(e.do("GET", c.path, nil, ""), http.StatusNotFound, protocol.CodeNotRevoked)
		}},
		{name: "putting the ACL", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"PUT", r.path("/acl"), aclOf([]string{}, []string{"*"}), r.pass(1)}
		}, unchanged: func(e *env, c call) {
			if got := aclReply(e.t, e.do("GET", c.path, nil, c.pass)); len(got.Deny) != 0 {
				e.t.Fatalf("the ACL was put: %+v", got)
			}
		}},
		{name: "reading the ACL", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.do("PUT", r.path("/acl"), open, r.pass(1)), http.StatusOK, "")
			return call{"GET", r.path("/acl"), nil, r.pass(1)}
		}},
		{name: "an adopt, of a mailbox in an account", exists: true, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			key := inAccount(e, r, 1)
			return call{"PUT", r.path("/account"), protocol.AdoptRequest{Key: key}, r.pass(1)}
		}},
		{name: "an adopt, of a mailbox in none", exists: false, ok: 200, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			_, key := accountEnv(e.t, e, false, 1)
			return call{"PUT", r.path("/account"), protocol.AdoptRequest{Key: key}, r.pass(1)}
		}, unchanged: func(e *env, c call) {
			if a := accountAt(e, c.path); a != "" {
				e.t.Fatalf("the mailbox joined account %s", a)
			}
		}},
		{name: "a leave, of a mailbox in an account", exists: true, ok: 204, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			inAccount(e, r, 0)
			return call{"DELETE", r.path("/account"), nil, r.pass(1)}
		}, unchanged: func(e *env, c call) {
			if accountAt(e, c.path) == "" {
				e.t.Fatal("the mailbox left its account")
			}
		}},
		{name: "a leave, of a mailbox in none", exists: false, ok: 204, setup: func(e *env) call {
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"DELETE", r.path("/account"), nil, r.pass(1)}
		}},
		{name: "a send", exists: true, ok: 201, setup: func(e *env) call {
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			return call{"POST", to.path("/messages"), to.sealed(1, ciphertextTo(e.t, to)), from.pass(1)}
		}, unchanged: func(e *env, c call) {
			if n, err := e.store.Count(e.t.Context(), addressAt(e.t, c.path)); err != nil || n != 0 {
				e.t.Fatalf("the mailbox holds %d: %v", n, err)
			}
		}},
		{name: "a list", exists: true, ok: 200, setup: func(e *env) call {
			to, _ := holding(e)
			return call{"GET", to.path("/messages"), nil, to.pass(1)}
		}},
		{name: "a fetch", exists: true, ok: 200, limits: func(l *Limits) { l.DrainBurst, l.DrainRefill = 1, day }, setup: func(e *env) call {
			to, path := holding(e)
			return call{"GET", path, nil, to.pass(1)}
		}, unchanged: func(e *env, c call) {
			// The one token of new messages taken out is still there: the fetch
			// was not counted.
			e.want(e.do("GET", c.path, nil, c.pass), http.StatusOK, "")
		}},
		{name: "an ack", exists: true, ok: 204, setup: func(e *env) call {
			to, path := holding(e)
			return call{"DELETE", path, nil, to.pass(1)}
		}, unchanged: func(e *env, c call) {
			e.want(e.do("GET", c.path, nil, c.pass), http.StatusOK, "")
		}},
		{name: "the link page", exists: true, ok: 200, setup: func(*env) call {
			return call{"GET", protocol.LinkPath + "d_" + strings.Repeat("ab", 32), nil, ""}
		}},
	}
	for _, c := range cases {
		for i, f := range forms {
			t.Run(c.name+"/"+f.name, func(t *testing.T) {
				l := relaxed()
				if c.limits != nil {
					c.limits(&l)
				}
				e := newEnv(t, l)
				q := c.setup(e)
				want := c.ok
				switch {
				case i == 0, i == 1 && !c.exists:
					want = http.StatusPreconditionFailed
				case i == 2 && c.exists && q.method == http.MethodGet:
					want = http.StatusNotModified
				case i == 2 && c.exists:
					want = http.StatusPreconditionFailed
				}
				r := e.doWith(q.method, q.path, q.body, q.pass, f.field, f.value)
				switch {
				case r.status != want:
					t.Fatalf("%s %s with %s: %d %s, want %d: %s", q.method, q.path, f.name, r.status, r.code(), want, r.body)
				case want == http.StatusPreconditionFailed && r.code() != protocol.CodePreconditionFailed:
					t.Fatalf("a 412 that is not precondition_failed: %s", r.body)
				case want == http.StatusNotModified && len(r.body) != 0:
					t.Fatalf("a 304 with %d bytes", len(r.body))
				}
				if want != c.ok && c.unchanged != nil {
					c.unchanged(e, q)
				}
			})
		}
	}
}

// accountAt is the account of the mailbox whose path p is.
func accountAt(e *env, p string) string {
	e.t.Helper()
	b, err := e.store.Mailbox(e.t.Context(), addressAt(e.t, p))
	if err != nil || b == nil {
		e.t.Fatalf("the mailbox at %s: %v", p, err)
	}
	return b.Account
}

// addressAt is the address a path under /v1/ names.
func addressAt(t *testing.T, p string) protocol.Address {
	t.Helper()
	a, err := protocol.ParseAddress(strings.SplitN(strings.TrimPrefix(p, "/v1/"), "/", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A precondition is ignored where the answer without it would not be 2xx or
// 412 (RFC 9110 §13.2.1): a call refused for its pass, of a mailbox that does
// not exist, or with a body its route refuses before it reads its target,
// is answered as it is without one, a false If-Match or If-None-Match: *
// among them.
func TestAPreconditionIsIgnoredWhereTheAnswerWouldBeARefusal(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	other := e.raw().register(protocol.MaxPrekeyLifetime)
	nobody := e.raw()
	nobody.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	gone := e.raw().register(protocol.MaxPrekeyLifetime)
	rev, err := protocol.SignRevocation(gone.signer, gone.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", gone.path("/revocations"), protocol.Revocations{Identity: gone.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
	for _, c := range []struct {
		name   string
		q      call
		status int
		code   protocol.Code
	}{
		{"the ACL with no pass", call{"GET", r.path("/acl"), nil, ""}, 401, protocol.CodeUnauthorized},
		{"the ACL with another mailbox's pass", call{"PUT", r.path("/acl"), aclOf([]string{"*"}, []string{}), other.pass(1)}, 401, protocol.CodeUnauthorized},
		{"a send with no pass", call{"POST", r.path("/messages"), r.sealed(1, ciphertextTo(t, r)), ""}, 401, protocol.CodeUnauthorized},
		{"the read of no mailbox", call{"GET", nobody.path(""), nil, ""}, 404, protocol.CodeNoSuchMailbox},
		{"a renewal of no mailbox", call{"PUT", nobody.path("/prekey"), nobody.upload(1), nobody.pass(1)}, 404, protocol.CodeNoSuchMailbox},
		{"the revocations of an address with none", call{"GET", r.path("/revocations"), nil, ""}, 404, protocol.CodeNotRevoked},
		{"a revocation of a revoked address", call{"PUT", gone.path("/revocations"), gone.certs(1), ""}, 410, protocol.CodeRevoked},
		{"a registration whose body is not JSON", call{"PUT", nobody.path(""), []byte(`not json`), nobody.pass(1)}, 400, protocol.CodeBadRequest},
		{"a send that is not an age file", call{"POST", r.path("/messages"), r.sealed(1, []byte("not age")), other.pass(1)}, 400, protocol.CodeBadRequest},
	} {
		for _, h := range [][2]string{{"If-Match", `"x"`}, {"If-None-Match", "*"}} {
			got := e.doWith(c.q.method, c.q.path, c.q.body, c.q.pass, h[0], h[1])
			if got.status != c.status || got.code() != c.code {
				t.Errorf("%s, with %s: %s: %d %s, want %d %s", c.name, h[0], h[1], got.status, got.code(), c.status, c.code)
			}
		}
	}
}
