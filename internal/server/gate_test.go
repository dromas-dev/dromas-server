package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// recorded is a request body that records whether anything read it, and
// whether anything read it before counted reported its call counted.
type recorded struct {
	r       io.Reader
	read    bool
	early   bool
	counted func() bool
}

func (b *recorded) Read(p []byte) (int, error) {
	if !b.read && b.counted != nil && !b.counted() {
		b.early = true
	}
	b.read = true
	return b.r.Read(p)
}

// counts is every series of the counter family name in reg, by its labels.
func counts(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			out[strings.Join(labels, ",")] = m.GetCounter().GetValue()
		}
	}
	return out
}

// moved is what changed between two reads of counts: each series that moved,
// by how much.
func moved(before, after map[string]float64) map[string]float64 {
	d := map[string]float64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

var passSignature = regexp.MustCompile(`signature="([^"]*)"`)

// respelled is pass with a space put in its signature's armor, after the
// BEGIN line: one pass to a verifier, another value to a hash.
func respelled(t *testing.T, pass string) string {
	t.Helper()
	armored, err := base64.StdEncoding.DecodeString(passSignature.FindStringSubmatch(pass)[1])
	if err != nil {
		t.Fatal(err)
	}
	spaced := strings.Replace(string(armored), "-----\n", "-----\n ", 1)
	return passSignature.ReplaceAllLiteralString(pass, `signature="`+base64.StdEncoding.EncodeToString([]byte(spaced))+`"`)
}

// Every request is counted before anything is done for it: every handler is
// put on its router through one gate, and a request no route answers is
// counted by the router's own (LIMITS.md, rule 1;
// dromas-dev/dromas-client#269, dromas-dev/dromas-server#67, #69,
// #74). So from an address past its flood budget, every route on a mailbox in
// every state (live, revoked, forgotten, its current certificate revoked,
// and one the server holds nothing of), the link page, a site's page and a
// request no route answers are refused 429 requests, whatever the call
// carries, with nothing else done: no other count of any limit taken, no
// pass parsed or checked, no mailbox looked up, nothing of its body read before
// it was counted. What is read of the body after, the drain before its
// answer (pacedBody.drain), is the connection's, as net/http's own drain
// was (dromas-dev/dromas-client#413 item 3). The one call that
// goes on is a mailbox's: a pass this process has checked, of a mailbox that is
// live, to a route that takes that mailbox's pass (a send takes any mailbox's, a
// call about a mailbox only its own, and the read of a mailbox none:
// dromas-dev/dromas-client#352). Its answer moves a count of its mailbox's,
// whatever it is. A new route is held to this by being one of routes(), and
// a new state by being one of these; and each route that answers GET is
// held to it for HEAD too.
func TestEveryRequestIsCountedBeforeAnythingIsDone(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	l.MissesPerMinute = 1000
	l.CallBurst, l.CallRefill = 1000, time.Hour
	l.PollBurst, l.PollRefill = 1000, time.Hour
	l.DrainBurst, l.DrainRefill = 1000, time.Hour
	l.ReceiveBurst, l.ReceiveRefill = 1000, time.Hour
	l.SendsPerDay = 1000
	site := siteBackend(t, siteFiles)
	reg := prometheus.NewRegistry()
	e := newEnv(t, l, func(c *Config) { c.Metrics, c.SiteBackend = NewMetrics(reg), site })
	n := 0
	fresh := func() string { // an address that has spent nothing
		n++
		return fmt.Sprintf("10.%d.%d.%d", n/40000, n/200%200, n%200+1)
	}
	call := e.caller()
	// checked is a mailbox registered, a pass of it checked by this process, and
	// that pass.
	checked := func() (*raw, string) {
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
		e.want(call(fresh(), "PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusCreated, "")
		p := r.pass(1)
		e.want(call(fresh(), "GET", r.path("/messages"), nil, p), http.StatusOK, "")
		return r, p
	}
	live, livePass := checked()
	other, otherPass := checked()
	// A mailbox whose pass was checked by a send to another mailbox, which loads
	// nothing into memory but its record: a mailbox that sends and never polls.
	// The send names no prekey, so it is refused once the pass is checked.
	sender := e.raw()
	sender.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(call(fresh(), "PUT", sender.path(""), sender.registration(1), sender.pass(1)), http.StatusCreated, "")
	senderPass := sender.pass(1)
	e.want(call(fresh(), "POST", other.path("/messages"), nil, senderPass), http.StatusBadRequest, protocol.CodeBadRequest)
	revoked, revokedPass := checked()
	rev, err := protocol.SignRevocation(revoked.signer, revoked.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(call(fresh(), "PUT", revoked.path("/revocations"), protocol.Revocations{Identity: revoked.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
	forgotten, forgottenPass := checked()
	if err := e.store.DeleteMailbox(t.Context(), forgotten.id.Address()); err != nil { // as the TTL deletes it
		t.Fatal(err)
	}
	listed, listedPass := checked()
	e.want(call(fresh(), "PUT", listed.path("/revocations"), listed.certs(1), ""), http.StatusOK, "")
	e.clock.Add(time.Second)
	nobody := strings.Repeat("ab", 32) // an address the server holds nothing of

	type state struct {
		name string
		addr string
		pass string // the mailbox's own checked pass, if it has one
	}
	states := []state{
		{"live", live.id.Address().String(), livePass},
		{"revoked", revoked.id.Address().String(), revokedPass},
		{"forgotten", forgotten.id.Address().String(), forgottenPass},
		{"its certificate revoked", listed.id.Address().String(), listedPass},
		{"held by nobody", nobody, ""},
	}
	// The passes of a live mailbox, which make a call its mailbox's where the
	// route takes them.
	mailboxOf := map[string]string{livePass: live.id.Address().String(), otherPass: other.id.Address().String(), senderPass: sender.id.Address().String()}
	type target struct {
		method, path string
		pass         passRule
		mailbox      string // the mailbox in the path
		own          string // its own checked pass
		direct       bool   // answered by the router or a site, which the API's description does not hold
	}
	var targets []target
	for _, r := range e.server.routes() {
		method, path, _ := strings.Cut(r.pattern, " ")
		for _, st := range states {
			p := strings.NewReplacer("{addr}", st.addr, "{id}", strings.Repeat("0", 64), "{$}", "").Replace(path)
			targets = append(targets, target{method, p, r.pass, st.addr, st.pass, false})
			if method == http.MethodGet { // a pattern of GET matches HEAD too (http.ServeMux)
				targets = append(targets, target{http.MethodHead, p, r.pass, st.addr, st.pass, false})
			}
		}
	}
	targets = append(targets,
		target{"GET", protocol.LinkPath + nobody, passNone, nobody, "", false},
		target{"HEAD", protocol.LinkPath + nobody, passNone, nobody, "", false},
		target{"GET", "/llms.txt", passNone, "", "", true},
		target{"GET", "/v1/" + nobody + "/nothing/here", passNone, nobody, "", true},
		target{"POST", protocol.LinkPath + nobody, passNone, nobody, "", true},
	)
	described, direct := apitest.Handler(t, e.server.Handler()), e.server.Handler()
	for _, tg := range targets {
		values := []struct{ name, auth string }{
			{"no pass", ""},
			{"5,600 bytes of commas", "dromas-pass " + strings.Repeat(",", protocol.MaxPassAuthorization-len("dromas-pass "))},
			{"a new pass of a live mailbox", live.pass(1)},
			{"a live mailbox's checked pass, respelled", respelled(t, livePass)},
			{"a live mailbox's checked pass", livePass},
			{"another live mailbox's checked pass", otherPass},
			{"the checked pass of a live mailbox that never polled", senderPass},
		}
		if tg.own != "" && tg.own != livePass {
			values = append(values, struct{ name, auth string }{"the mailbox's own checked pass", tg.own})
		}
		for _, v := range values {
			ip := fresh()
			if got := call(ip, "GET", protocol.LinkPath+nobody, nil, ""); got.status != http.StatusOK { // its one call
				t.Fatalf("the address's one call: %d", got.status)
			}
			body := &recorded{r: strings.NewReader(`{"identity":"` + strings.Repeat("A", 4000) + `"}`)}
			req := httptest.NewRequest(tg.method, tg.path, body)
			req.Host = e.name()
			req.RemoteAddr = net.JoinHostPort(ip, "40000")
			if v.auth != "" {
				req.Header.Set("Authorization", v.auth)
			}
			limits, passes := counts(t, reg, "dromas_server_limit_requests_total"), counts(t, reg, "dromas_server_passes_total")
			body.counted = func() bool {
				return moved(limits, counts(t, reg, "dromas_server_limit_requests_total"))["decision=denied,limit=requests,subject=ip"] == 1
			}
			w := httptest.NewRecorder()
			if tg.direct {
				direct.ServeHTTP(w, req)
			} else {
				described.ServeHTTP(w, req)
			}
			got := reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
			what := fmt.Sprintf("%s %s with %s", tg.method, tg.path, v.name)
			if mailbox, ok := mailboxOf[v.auth]; ok && (tg.pass == passAnyMailbox || tg.pass == passPathMailbox && mailbox == tg.mailbox) {
				if q, _ := got.quota(); q == protocol.QuotaRequests {
					t.Errorf("%s: refused for the address's flood budget, though its mailbox's pass was checked", what)
				}
				if d := moved(limits, counts(t, reg, "dromas_server_limit_requests_total")); len(d) == 0 {
					t.Errorf("%s: answered %d with no count taken", what, got.status)
				}
				continue
			}
			if q, _ := got.quota(); got.status != http.StatusTooManyRequests || q != protocol.QuotaRequests {
				t.Errorf("%s, past the address's flood budget: %d %s, want 429 requests", what, got.status, got.body)
				continue
			}
			if d := moved(limits, counts(t, reg, "dromas_server_limit_requests_total")); len(d) != 1 || d["decision=denied,limit=requests,subject=ip"] != 1 {
				t.Errorf("%s: limits taken besides the one refusal: %v", what, d)
			}
			if d := moved(passes, counts(t, reg, "dromas_server_passes_total")); len(d) != 0 {
				t.Errorf("%s: passes looked at: %v", what, d)
			}
			if body.early {
				t.Errorf("%s: its body was read before it was counted", what)
			}
		}
	}
}

// A server that is not ready yet answers 503 only to a call it has counted:
// from an address past its flood budget, every route is refused 429
// requests, before its 503 (dromas-dev/dromas-server#75's note).
func TestAServerNotReadyCountsFirst(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	e := newEnv(t, l, func(c *Config) { c.Ready = func() bool { return false } })
	call := e.caller()
	nobody := strings.Repeat("ab", 32)
	for i, r := range e.server.routes() {
		method, path, _ := strings.Cut(r.pattern, " ")
		path = strings.NewReplacer("{addr}", nobody, "{id}", strings.Repeat("0", 64), "{$}", "").Replace(path)
		ip := fmt.Sprintf("10.1.0.%d", i+1)
		e.want(call(ip, method, path, nil, ""), http.StatusServiceUnavailable, protocol.CodeUnavailable)
		if got := call(ip, method, path, nil, ""); got.status != http.StatusTooManyRequests {
			t.Errorf("%s %s, past the address's flood budget, before the server is ready: %d %s, want 429 requests", method, path, got.status, got.body)
		}
	}
}

// A pass this process has not checked is its address's call until it is: it
// spends the address's flood budget before its signatures are checked, as
// Let's Encrypt limits every endpoint per address in front of its check of
// a request's signature. So a mailbox that signs a new pass for every call has
// at most that budget of them checked from one address
// (dromas-dev/dromas-server#67), and a pass the process has checked
// spends none of it: another mailbox behind the same address goes on.
func TestANewPassSpendsItsAddresssFloodBudget(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 20, time.Hour
	e, m, _ := metered(t, l)
	b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	call := e.caller()
	kept := e.pass(c)
	e.want(call("198.51.100.8", "GET", "/v1/"+c.Address().String()+"/messages", nil, kept), http.StatusOK, "")
	checked := m.passes.WithLabelValues("checked", "")
	before := testutil.ToFloat64(checked)
	w := worker(t, b)
	const ip = "198.51.100.7"
	answered, refused := 0, 0
	for i := range 150 {
		auth, _, err := protocol.NewPass(w, b.Address(), e.name(), e.clock.Now().Add(time.Duration(i+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		switch r := call(ip, "GET", "/v1/"+b.Address().String()+"/acl", nil, auth); {
		case r.status == http.StatusTooManyRequests:
			e.limited(r, protocol.QuotaRequests)
			refused++
		case r.status < 500:
			answered++
		default:
			t.Fatalf("a new pass: %d %s", r.status, r.body)
		}
	}
	if n := testutil.ToFloat64(checked) - before; n != float64(l.RequestBurst) || answered != l.RequestBurst || refused != 150-l.RequestBurst {
		t.Errorf("150 new passes from one address with a flood budget of %d: %v checked in full, %d answered, %d refused", l.RequestBurst, n, answered, refused)
	}
	e.want(call(ip, "GET", "/v1/"+c.Address().String()+"/messages", nil, kept), http.StatusOK, "")

	// A pass first shown in another form a server reads, the scheme in
	// capitals, is checked in that form too: it goes on from that address.
	d := e.mailbox(protocol.Classic)
	e.clock.Add(time.Second) // not the pass its registration showed
	upper := strings.Replace(e.pass(d), "dromas-pass ", "DROMAS-PASS ", 1)
	e.want(call("198.51.100.9", "GET", "/v1/"+d.Address().String()+"/messages", nil, upper), http.StatusOK, "")
	e.want(call(ip, "GET", "/v1/"+d.Address().String()+"/messages", nil, upper), http.StatusOK, "")

	// Two passes used in turn are each new when they come back: the gate
	// forgets a mailbox's pass once another is checked.
	first := e.pass(c)
	e.clock.Add(time.Second)
	second := e.pass(c)
	const other = "198.51.100.10"
	for i, auth := range []string{first, second} {
		e.want(call(other+"0", "GET", "/v1/"+c.Address().String()+"/messages", nil, auth), http.StatusOK, "")
		if i == 0 {
			e.want(call(other, "GET", "/v1/"+c.Address().String()+"/messages", nil, auth), http.StatusOK, "") // the flooding address's own
		}
	}
	for range l.RequestBurst {
		call(other, "GET", "/nothing", nil, "")
	}
	e.limited(call(other, "GET", "/v1/"+c.Address().String()+"/messages", nil, first), protocol.QuotaRequests)
}

// One pass written another way that OpenSSH reads as the same signature is
// that one pass to the server: answered from memory, with no second check
// of its signatures, however its armor is spaced and however its SSHSIG blob
// writes its version, a NUL after its namespace or its reserved field,
// which nothing signs (dromas-dev/dromas-server#69). A signature that
// differs in a bit is checked, and refused.
func TestARespelledPassCostsNoSecondCheck(t *testing.T) {
	t.Parallel()
	e, m, _ := metered(t, relaxed())
	b := e.mailbox(protocol.Classic)
	poll := func(auth string) reply { return e.do("GET", "/v1/"+b.Address().String()+"/messages", nil, auth) }
	e.clock.Add(time.Second) // not the pass the registration showed
	pass := e.pass(b)
	e.want(poll(pass), http.StatusOK, "")
	armored, err := base64.StdEncoding.DecodeString(passSignature.FindStringSubmatch(pass)[1])
	if err != nil {
		t.Fatal(err)
	}
	blob, err := protocol.Dearmor(armored)
	if err != nil {
		t.Fatal(err)
	}
	// rewrite is blob with version v, a NUL after its namespace when nul,
	// and reserved in its reserved field, armored as ssh-keygen does.
	rewrite := func(v uint32, nul bool, reserved []byte) []byte {
		rest := blob[10:]
		str := func() []byte {
			n := binary.BigEndian.Uint32(rest)
			s := rest[4 : 4+n]
			rest = rest[4+n:]
			return s
		}
		key, ns := str(), str()
		_ = str()
		hash, sig := str(), str()
		if nul {
			ns = append(append([]byte{}, ns...), 0)
		}
		out := binary.BigEndian.AppendUint32([]byte("SSHSIG"), v)
		for _, s := range [][]byte{key, ns, reserved, hash, sig} {
			out = binary.BigEndian.AppendUint32(out, uint32(len(s))) //nolint:gosec // a test's own signature
			out = append(out, s...)
		}
		return protocol.Armor(out)
	}
	with := func(a []byte) string {
		return passSignature.ReplaceAllLiteralString(pass, `signature="`+base64.StdEncoding.EncodeToString(a)+`"`)
	}
	forms := map[string][]byte{
		"CRLF after the BEGIN line":    bytes.Replace(armored, []byte("-----\n"), []byte("-----\r\n"), 1),
		"text after the END line":      append(append([]byte{}, armored...), "anything"...),
		"a tab inside the base64":      bytes.Replace(armored, []byte("-----\n"), []byte("-----\n\t"), 1),
		"a NUL before the END line":    bytes.Replace(armored, []byte("\n-----END"), []byte("\x00\n-----END"), 1),
		"the base64 on one line":       []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(blob) + "\n-----END SSH SIGNATURE-----\n"),
		"SSHSIG version 0":             rewrite(0, false, nil),
		"a NUL ending the namespace":   rewrite(1, true, nil),
		"a byte in the reserved field": rewrite(1, false, []byte{'x'}),
	}
	at := bytes.IndexByte(armored, '\n') + 1
	for i := 0; i < 40; i++ {
		forms[fmt.Sprintf("a space after byte %d of the base64", i)] = append(append(append([]byte{}, armored[:at+i]...), ' '), armored[at+i:]...)
	}
	checked := m.passes.WithLabelValues("checked", "")
	before := testutil.ToFloat64(checked)
	for name, a := range forms {
		if r := poll(with(a)); r.status != http.StatusOK {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if n := testutil.ToFloat64(checked) - before; n != 0 {
		t.Errorf("%d ways of writing one pass: %v checked again", len(forms), n)
	}
	flipped := append([]byte{}, blob...)
	flipped[len(flipped)-1] ^= 1
	e.want(poll(with(protocol.Armor(flipped))), http.StatusUnauthorized, protocol.CodeUnauthorized)
}
