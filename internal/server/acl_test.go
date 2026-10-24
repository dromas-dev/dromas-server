package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// aclOf is an ACL document: the lists as given.
func aclOf(allow, deny []string) protocol.ACLDocument {
	return protocol.ACLDocument{Allow: allow, Deny: deny}
}

// aclReply reads an ACL document out of an answer.
func aclReply(t *testing.T, r reply) protocol.ACLDocument {
	t.Helper()
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(r.body, &d); err != nil {
		t.Fatalf("not an ACL document: %v: %s", err, r.body)
	}
	return d
}

// sealTo is a send to box to, as the server sees one: an age file to its
// current prekey under both its serials. What is inside is the recipient's
// to judge, so a test needs nothing more.
func (e *env) sealTo(to *client.Box) sealed {
	e.t.Helper()
	b, err := e.store.Box(context.Background(), to.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	rcpt, err := b.Prekey.Recipient()
	if err != nil {
		e.t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rcpt)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	serial, under := e.numbers(to.Address())
	return sealedTo(serial, under, ct.Bytes())
}

// A box's ACL is the box's own to read and replace, whole; one that is not
// an ACL, or holds more entries than the server takes, is refused before
// anything is stored. A GET carries the ETag of the ACL held, and a PUT,
// whose ACL may not be what was sent, carries none (RFC 9110 §9.3.4).
func TestACLRoute(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.ACLEntries = 3
	e := newEnv(t, l)
	b, other := e.box(protocol.Classic), e.box(protocol.Classic)
	path := "/v1/" + b.Address().String() + "/acl"
	pass := e.pass(b)
	x, y := other.Address().String(), strings.Repeat("ab", 32)
	const open = `{"allow":["*"],"deny":[]}`

	// The box's own pass, and only that.
	e.want(e.do("GET", path, nil, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", path, aclOf([]string{"*"}, nil), ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", path, nil, e.pass(other)), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", path, aclOf([]string{"*"}, nil), e.pass(other)), 401, protocol.CodeUnauthorized)

	// A box that has put none lets everyone in, and has a tag for that.
	got := e.do("GET", path, nil, pass)
	e.want(got, 200, "")
	if string(bytes.TrimSpace(got.body)) != open || got.header.Get("ETag") != entityTag(got.body) {
		t.Fatalf("no ACL: %s, ETag %q", got.body, got.header.Get("ETag"))
	}

	for name, body := range map[string]any{
		"no allow list":      []byte(`{"deny":[]}`),
		"allow null":         []byte(`{"allow":null}`),
		"a version":          []byte(`{"version":1,"allow":["*"]}`),
		"an uppercase entry": aclOf([]string{strings.ToUpper(y)}, nil),
		"a partial pattern":  aclOf([]string{"*" + y[1:]}, nil),
		"a member it lacks":  []byte(`{"allow":["*"],"block":[]}`),
		"not JSON":           []byte(`allow everyone`),
	} {
		if r := e.do("PUT", path, body, pass); r.status != 400 || r.code() != protocol.CodeBadRequest {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, r.status, r.code(), protocol.CodeBadRequest, r.body)
		}
	}
	if r := e.do("PUT", path, []byte(`{"version":1,"allow":["*"]}`), pass); r.problem().Member != "version" {
		t.Errorf("a document with a version names no member version: %s", r.body)
	}
	// Over the entries, and over the body's bound drawn from them, which is
	// refused before it is parsed: the limit is the entries either way
	// (PROTOCOL.md §11.3: a too_large on an ACL is entries).
	huge := aclOf([]string{"*"}, []string{strings.Repeat(" ", int(e.server.aclBodyLimit()))})
	for _, body := range []any{aclOf([]string{"*", x}, []string{y, x}), huge} {
		r := e.do("PUT", path, body, pass)
		e.want(r, 413, protocol.CodeTooLarge)
		if p := r.problem(); p.Limit == nil || *p.Limit != 3 {
			t.Errorf("an ACL over 3 entries is told the limit %v, want its 3 entries: %s", p.Limit, r.body)
		}
	}
	if r := e.do("GET", path, nil, pass); string(bytes.TrimSpace(r.body)) != open {
		t.Fatalf("a refused ACL was stored: %s", r.body)
	}

	// Taken: stored and answered in its one form, sorted and each once, with
	// no tag; a GET then answers the tag of that form.
	put := e.do("PUT", path, aclOf([]string{y, x, y}, []string{}), pass)
	e.want(put, 200, "")
	lo, hi := min(x, y), max(x, y)
	want := `{"allow":["` + lo + `","` + hi + `"],"deny":[]}`
	if string(bytes.TrimSpace(put.body)) != want || put.header.Values("ETag") != nil {
		t.Fatalf("PUT answered %s with ETag %q, want %s and none", put.body, put.header.Values("ETag"), want)
	}
	r := e.do("GET", path, nil, pass)
	tag := r.header.Get("ETag")
	if string(bytes.TrimSpace(r.body)) != want || tag != entityTag([]byte(want+"\n")) || tag == got.header.Get("ETag") {
		t.Fatalf("GET answered %s with ETag %q", r.body, tag)
	}
	// The same ACL put again has the same tag: the tag is of the ACL.
	e.want(e.do("PUT", path, aclOf([]string{x, y}, nil), pass), 200, "")
	if r := e.do("GET", path, nil, pass); r.header.Get("ETag") != tag {
		t.Fatalf("the same ACL put again: ETag %q, want %q", r.header.Get("ETag"), tag)
	}

	// The record carries it, as the store writes it and reads it back.
	stored, err := e.store.Box(context.Background(), b.Address())
	if err != nil || stored.ACL == nil || stored.ACL.Allow.Any || stored.ACL.Allow.Len() != 2 {
		t.Fatalf("the stored ACL: %+v, %v", stored.ACL, err)
	}
	back, err := decodeBox(item(boxItem(stored)))
	if err != nil || back.ACL == nil || !back.ACL.SameLists(stored.ACL) {
		t.Fatalf("the ACL does not come back from the record as it went in: %+v, %v", back.ACL, err)
	}
	if doc, err := item(boxItem(stored)).bytes("acl"); err != nil || string(doc) != want {
		t.Fatalf("the record holds the ACL as %s, %v; want %s", doc, err, want)
	}
	none, err := e.store.Box(context.Background(), other.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := boxItem(none)["acl"]; ok {
		t.Fatal("a box with no ACL has one in its record")
	}
	if back, err := decodeBox(item(boxItem(none))); err != nil || back.ACL != nil {
		t.Fatalf("a record with no ACL reads back with one: %+v, %v", back.ACL, err)
	}
}

// A PUT with If-Match replaces only the ACL it names, compared strongly, as
// RFC 9110 §13.1.1 has an origin server evaluate one, a box with no ACL
// included; a false one is 412, changes nothing, and is answered before the
// body is read (RFC 9110 §13.2.1). One without If-Match replaces whatever is
// held, so no ACL is the last the server takes (IronGall-dev/irongall-client#360).
func TestAnACLsIfMatch(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.ACLEntries = 3
	e := newEnv(t, l)
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
	path := "/v1/" + b.Address().String() + "/acl"
	pass := e.pass(b)
	pause, open := aclOf([]string{}, []string{"*"}), aclOf([]string{"*"}, nil)
	tagOf := func() (string, string) {
		t.Helper()
		r := e.do("GET", path, nil, pass)
		e.want(r, 200, "")
		return r.header.Get("ETag"), string(r.body)
	}

	// A box with none: its tag is that of the ACL it answers.
	none, _ := tagOf()
	e.want(e.doWith("PUT", path, open, pass, "If-Match", `"other"`), 412, protocol.CodePreconditionFailed)
	e.want(e.doWith("PUT", path, pause, pass, "If-Match", none), 200, "")
	paused, body := tagOf()
	if paused == none {
		t.Fatalf("the pause has the tag %q of the open ACL before it", paused)
	}

	for _, c := range []struct {
		name   string
		lines  []string
		status int
	}{
		{"the tag held", []string{paused}, 200},
		{"*", []string{"*"}, 200},
		{"a list holding it", []string{`"other", ` + paused}, 200},
		{"two lines, one holding it", []string{`"other"`, paused}, 200},
		{"the tag before", []string{none}, 412},
		{"it marked weak", []string{"W/" + paused}, 412},
		{"its value unquoted", []string{strings.Trim(paused, `"`)}, 412},
		{"not a tag", []string{"junk"}, 412},
	} {
		var hdr []string
		for _, v := range c.lines {
			hdr = append(hdr, "If-Match", v)
		}
		r := e.doWith("PUT", path, pause, pass, hdr...)
		if r.status != c.status || c.status == 412 && r.code() != protocol.CodePreconditionFailed {
			t.Errorf("If-Match %s %q: %d %s, want %d", c.name, c.lines, r.status, r.code(), c.status)
		}
	}
	if tag, now := tagOf(); tag != paused || now != body {
		t.Fatalf("a false If-Match changed the ACL: %s, ETag %q", now, tag)
	}

	// A false one is answered before the body: one that is not an ACL, or is
	// over the bound, is 412 all the same.
	huge := aclOf([]string{"*"}, []string{strings.Repeat(" ", int(e.server.aclBodyLimit()))})
	for _, body := range []any{[]byte(`allow everyone`), huge} {
		e.want(e.doWith("PUT", path, body, pass, "If-Match", none), 412, protocol.CodePreconditionFailed)
	}

	// Mail waits refused while the pause holds, and a PUT with no If-Match,
	// or with the pause's tag, lets senders in again: nothing a writer once
	// wrote stops the next.
	e.want(e.do("POST", "/v1/"+b.Address().String()+"/messages", e.sealTo(b), e.pass(c)), 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("PUT", path, open, pass), 200, "")
	e.want(e.do("POST", "/v1/"+b.Address().String()+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	e.want(e.doWith("PUT", path, pause, pass, "If-Match", paused), 412, protocol.CodePreconditionFailed)
	opened, _ := tagOf()
	e.want(e.doWith("PUT", path, pause, pass, "If-Match", opened), 200, "")
	if tag, _ := tagOf(); tag != paused {
		t.Fatalf("the pause put again has the tag %q, want its own %q", tag, paused)
	}
}

// onRead runs f once, at the first read of the body it wraps.
type onRead struct {
	io.ReadCloser
	f    func()
	done bool
}

func (o *onRead) Read(p []byte) (int, error) {
	if !o.done {
		o.done = true
		o.f()
	}
	return o.ReadCloser.Read(p)
}

// A PUT's If-Match is held to the ACL its write replaces (PROTOCOL.md
// §11.2): another writer's ACL that lands while the PUT reads its body, after
// its If-Match was evaluated, makes the PUT 409 box_changed, and the other
// writer's ACL stays; the same PUT sent again meets an If-Match that is
// false (412), and one with the tag now held is taken
// (IronGall-dev/irongall-server#88).
func TestAnACLsIfMatchIsHeldToTheACLItsWriteReplaces(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b, x := e.box(protocol.Classic), e.box(protocol.Classic)
	path := "/v1/" + b.Address().String() + "/acl"
	pass := e.pass(b)
	tag := e.do("GET", path, nil, pass).header.Get("ETag")
	other := &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{x.Address()})}
	var raced atomic.Int32
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && raced.Load() == 0 {
			r.Body = &onRead{ReadCloser: r.Body, f: func() {
				cur, err := e.store.Box(context.Background(), b.Address())
				if err != nil {
					t.Error(err)
					return
				}
				cur.ACL = other
				if err := e.store.UpdateBox(context.Background(), cur); err != nil {
					t.Error(err)
					return
				}
				raced.Add(1)
			}}
		}
		next.ServeHTTP(w, r)
	})
	pause := aclOf([]string{}, []string{"*"})
	r := e.doWith("PUT", path, pause, pass, "If-Match", tag)
	e.setMiddle(nil)
	now := e.do("GET", path, nil, pass)
	if raced.Load() != 1 || r.status != http.StatusConflict || r.code() != protocol.CodeBoxChanged {
		t.Errorf("a PUT whose record changed while it read its body: %d %s (raced %d); the ACL held after: %s", r.status, r.body, raced.Load(), now.body)
	}
	if !strings.Contains(string(now.body), x.Address().String()) || now.header.Get("ETag") == tag {
		t.Fatalf("the other writer's ACL is not the one held: %s %s", now.body, now.header.Get("ETag"))
	}
	e.want(e.doWith("PUT", path, pause, pass, "If-Match", tag), http.StatusPreconditionFailed, protocol.CodePreconditionFailed)
	e.want(e.doWith("PUT", path, pause, pass, "If-Match", now.header.Get("ETag")), http.StatusOK, "")
}

// A GET of the ACL reads its preconditions as a list does, in RFC 9110
// §13.2.2's order and only where its answer would be 200 (§13.2.1): a false
// If-Match, compared strongly, is 412, and then an If-None-Match that names
// the tag, compared weakly, is 304 with the tag and no body.
func TestAnACLsGETReadsItsPreconditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b, other := e.box(protocol.Classic), e.box(protocol.Classic)
	path := "/v1/" + b.Address().String() + "/acl"
	pass := e.pass(b)
	e.want(e.do("PUT", path, aclOf([]string{"*"}, []string{other.Address().String()}), pass), 200, "")
	full := e.do("GET", path, nil, pass)
	e.want(full, 200, "")
	tag := full.header.Get("ETag")
	for _, c := range []struct {
		name    string
		headers []string
		status  int
	}{
		{"If-Match the tag", []string{"If-Match", tag}, 200},
		{"If-Match *", []string{"If-Match", "*"}, 200},
		{"If-Match another", []string{"If-Match", `"other"`}, 412},
		{"If-Match it weak", []string{"If-Match", "W/" + tag}, 412},
		{"If-None-Match the tag", []string{"If-None-Match", tag}, 304},
		{"If-None-Match it weak", []string{"If-None-Match", "W/" + tag}, 304},
		{"If-None-Match *", []string{"If-None-Match", "*"}, 304},
		{"If-None-Match a list holding it", []string{"If-None-Match", `"other", ` + tag}, 304},
		{"If-None-Match another", []string{"If-None-Match", `"other"`}, 200},
		{"If-None-Match * among tags", []string{"If-None-Match", `"other", *`}, 200},
		{"both true", []string{"If-Match", tag, "If-None-Match", tag}, 304},
		{"If-Match false first", []string{"If-Match", `"other"`, "If-None-Match", tag}, 412},
	} {
		r := e.doWith("GET", path, nil, pass, c.headers...)
		switch {
		case r.status != c.status:
			t.Errorf("%s: %d %s, want %d", c.name, r.status, r.code(), c.status)
		case c.status == 412 && r.code() != protocol.CodePreconditionFailed:
			t.Errorf("%s: %s", c.name, r.body)
		case c.status == 304 && (len(r.body) != 0 || r.header.Get("ETag") != tag):
			t.Errorf("%s: 304 with ETag %q and %d bytes", c.name, r.header.Get("ETag"), len(r.body))
		case c.status == 200 && (!bytes.Equal(r.body, full.body) || r.header.Get("ETag") != tag):
			t.Errorf("%s: 200 with ETag %q: %s", c.name, r.header.Get("ETag"), r.body)
		}
	}
	// Only where the answer would be 200: no pass, or no box, is answered as
	// it is without them.
	e.want(e.doWith("GET", path, nil, "", "If-Match", `"other"`), 401, protocol.CodeUnauthorized)
	e.want(e.doWith("GET", path, nil, e.pass(other), "If-None-Match", tag), 401, protocol.CodeUnauthorized)
}

// With no bound on its entries, an ACL's body is still bounded, to keep the
// record one item: a body over that is too_large with the body's bytes as
// its limit, the one limit there is (PROTOCOL.md §11.3).
func TestAnUnboundedACLNamesItsBodysBytes(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.ACLEntries = 0
	e := newEnv(t, l)
	b := e.box(protocol.Classic)
	huge := aclOf([]string{"*"}, []string{strings.Repeat(" ", int(e.server.aclBodyLimit()))})
	r := e.do("PUT", "/v1/"+b.Address().String()+"/acl", huge, e.pass(b))
	e.want(r, 413, protocol.CodeTooLarge)
	if p := r.problem(); p.Limit == nil || *p.Limit != uint64(aclBodyUnbounded) {
		t.Errorf("an unbounded ACL's body over its bound is told the limit %v, want its %d bytes: %s", p.Limit, aclBodyUnbounded, r.body)
	}
}

// A send the ACL refuses is refused with one code and one wording, whether
// its sender is denied or only not allowed, before anything of the sender's
// quotas is spent; a sender it lets in is taken.
func TestACLRefusesSends(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	acl := func(allow, deny []string) {
		t.Helper()
		e.want(e.do("PUT", to+"/acl", aclOf(allow, deny), e.pass(b)), 200, "")
	}

	acl([]string{a.Address().String()}, nil)
	notAllowed := e.do("POST", to+"/messages", e.sealTo(b), e.pass(c))
	e.want(notAllowed, 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 201, "")

	acl([]string{"*"}, []string{a.Address().String()})
	denied := e.do("POST", to+"/messages", e.sealTo(b), e.pass(a))
	e.want(denied, 403, protocol.CodeSenderNotAllowed)
	var p, q protocol.Problem
	_ = json.Unmarshal(notAllowed.body, &p)
	_ = json.Unmarshal(denied.body, &q)
	if p.Detail != q.Detail || p.Hint != q.Hint || p.Title != q.Title {
		t.Fatalf("denied and not allowed tell apart:\n%s\n%s", notAllowed.body, denied.body)
	}
	// c was refused twice under SendsPerDay 1: neither refusal spent its
	// send, which "*" now lets through, and the count then holds.
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	e.limited(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), protocol.QuotaSends)
}

// A deny list deletes the box's unacked mail from what it matches, and only
// that; a retry of a message stored before is still answered with its
// receipt, since a retry is no new mail (PROTOCOL.md §11.10 step 6). One that
// denies everyone is how a box pauses, and a later ACL undoes it (§11.14).
func TestACLDenyPurges(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	first := e.sealTo(b)
	stored := e.do("POST", to+"/messages", first, e.pass(a))
	e.want(stored, 201, "")
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 201, "")
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	count := func(from *client.Box) int {
		t.Helper()
		n, _, err := e.store.PairCount(ctx, b.Address(), from.Address())
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(a) != 2 || count(c) != 1 {
		t.Fatalf("before: %d from a, %d from c", count(a), count(c))
	}

	e.want(e.do("PUT", to+"/acl", aclOf([]string{"*"}, []string{a.Address().String()}), e.pass(b)), 200, "")
	if count(a) != 0 || count(c) != 1 {
		t.Fatalf("after denying a: %d from a, %d from c", count(a), count(c))
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 1 {
		t.Fatalf("the box holds %d, %v", n, err)
	}
	retry := e.do("POST", to+"/messages", first, e.pass(a))
	e.want(retry, 200, "")
	if !bytes.Equal(retry.body, stored.body) {
		t.Fatalf("a retry's receipt changed: %s, was %s", retry.body, stored.body)
	}
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 403, protocol.CodeSenderNotAllowed)

	// The pause (PROTOCOL.md §11.14), nobody allowed and everyone denied:
	// everything goes, and nothing more comes until a later ACL undoes it.
	// What the pause deleted stays deleted.
	e.want(e.do("PUT", to+"/acl", aclOf([]string{}, []string{"*"}), e.pass(b)), 200, "")
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 0 {
		t.Fatalf("after denying everyone the box holds %d, %v", n, err)
	}
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("PUT", to+"/acl", aclOf([]string{"*"}, nil), e.pass(b)), 200, "")
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 1 {
		t.Fatalf("after the pause is undone the box holds %d, %v; want the one sent since", n, err)
	}
}

// On DynamoDB, an ACL put through one process reaches another through the
// stream, and that process then refuses what it refuses.
func TestACLReachesAnotherProcess(t *testing.T) {
	t.Parallel()
	e, _ := dynamoEnv(t)
	other := startDynamo(t, e.clock.Now)
	srv2 := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	t.Cleanup(srv2.Close)
	e2 := &env{t: t, clock: e.clock, store: other, srv: srv2}
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()

	// The other process holds b's record, with no ACL in it.
	e2.want(e2.do("POST", to+"/messages", e2.sealTo(b), e2.pass(a)), 201, "")
	e.want(e.do("PUT", to+"/acl", aclOf([]string{"*"}, []string{a.Address().String()}), e.pass(b)), 200, "")
	start := time.Now()
	for {
		if rec, ok := other.Known(b.Address()); ok && rec != nil && rec.ACL != nil {
			break
		}
		if time.Since(start) > 15*time.Second {
			t.Fatal("the ACL did not reach the other process within 15 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("an ACL put on one process reached the other in %s", time.Since(start))
	e2.want(e2.do("POST", to+"/messages", e2.sealTo(b), e2.pass(a)), 403, protocol.CodeSenderNotAllowed)
	there, here := e2.do("GET", to+"/acl", nil, e2.pass(b)), e.do("GET", to+"/acl", nil, e.pass(b))
	if d := aclReply(t, there); len(d.Deny) != 1 || there.header.Get("ETag") != here.header.Get("ETag") {
		t.Fatalf("the other process answers %+v with ETag %q, this one ETag %q", d, there.header.Get("ETag"), here.header.Get("ETag"))
	}
}
