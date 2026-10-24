package server

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Every value an error's detail names is also a member of its own, of its
// type (PROTOCOL.md §13, AEP-193): a client reads the member and never the
// words, so a value only in the words is one a client loses.
func TestAnErrorsValuesAreMembers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	problem := func(err error) protocol.Problem {
		t.Helper()
		var ae *client.APIError
		if !errors.As(err, &ae) {
			t.Fatalf("not an API error: %v", err)
		}
		return ae.Problem
	}
	limitIs := func(what string, p protocol.Problem, code protocol.Code, want int) {
		t.Helper()
		if p.Code != code || p.Limit == nil || *p.Limit != uint64(want) || !strings.Contains(p.Detail, strconv.Itoa(want)) {
			t.Errorf("%s: %+v, want %s with limit %d, which its detail names", what, p, code, want)
		}
	}
	quotaIs := func(what string, p protocol.Problem, q protocol.Quota) {
		t.Helper()
		if p.Code != protocol.CodeRateLimited || p.QuotaID != q || p.Subject != q.Subject() {
			t.Errorf("%s: %+v, want rate_limited naming %s, counted against %s", what, p, q, q.Subject())
		}
	}

	_, err := a.Send(ctx, b.Address(), strings.Repeat("x", l.MaxSize+1))
	limitIs("a send over the cap", problem(err), protocol.CodeTooLarge, l.MaxSize)

	send(t, a, b, "1")
	_, err = a.Send(ctx, b.Address(), "2")
	limitIs("a send past the day's", problem(err), protocol.CodeRateLimited, l.SendsPerDay)
	quotaIs("a send past the day's", problem(err), protocol.QuotaSends)

	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
	reg := r.registration(1)
	got := e.do("PUT", r.path(""), map[string]any{"identity": reg.Identity, "prekey": reg.Prekey, "prekey_signature": reg.PrekeySignature, "surplus": 1}, r.pass(1))
	var p protocol.Problem
	if err := protocol.Unmarshal(got.body, &p); err != nil || p.Code != protocol.CodeBadRequest || p.Member != "surplus" || !strings.Contains(p.Detail, "surplus") {
		t.Errorf("a registration with a member it does not take: %s, %v", got.body, err)
	}
}
