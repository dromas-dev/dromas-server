package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/textproto"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// What any caller's bytes reach before a signature verifies or the request
// is counted is fuzzed here, beside the operator's two runtime files, as the
// client repo fuzzes what a reader runs on bytes nobody has vouched for (its
// protocol/fuzz_test.go). Each target holds the code to its doc comment: no
// panic, a refusal is an error (or false) with nothing beside it, and
// whatever else the comment says. go test runs each target's seeds;
// .github/workflows/ci.yml fuzzes each for an hour once a week. Run one at a
// time:
//
//	go test -tags dromas_nofsync -run '^$' -fuzz '^FuzzHandler$' -fuzztime 2m -parallel 1 ./internal/server

// parseCursor takes only strict unpadded base64url of 40 bytes, and what it
// takes formatCursor writes back as the same string, a cursor the client's
// check of one takes (protocol.CheckCursor); a refusal is invalid_request, with
// no cursor beside it.
func FuzzParseCursor(f *testing.F) {
	for _, h := range []Header{
		{},
		{ReceivedAt: fuzzNow(f), ID: sha256.Sum256([]byte("a message"))},
		{ReceivedAt: time.UnixMilli(-1)},
	} {
		f.Add(formatCursor(h))
	}
	one := formatCursor(Header{ReceivedAt: fuzzNow(f)})
	for _, s := range []string{"", "AAAA", one + "=", one[:len(one)-1], one + "A", strings.Repeat("A", 53) + "B", strings.ReplaceAll(one, "A", "+")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := parseCursor(s)
		b, derr := base64.RawURLEncoding.Strict().DecodeString(s)
		cursor := derr == nil && len(b) == 8+32
		if err != nil {
			if c != nil {
				t.Fatal("refused, with a cursor beside it")
			}
			if p, ok := errors.AsType[*problem](err); !ok || p.code != protocol.CodeInvalidRequest {
				t.Fatalf("refused as %v", err)
			}
			if cursor {
				t.Fatalf("refused %q, 40 bytes in strict base64url", s)
			}
			return
		}
		if !cursor {
			t.Fatalf("took %q, which is not 40 bytes in strict base64url", s)
		}
		if again := formatCursor(Header{ReceivedAt: c.ReceivedAt, ID: c.ID}); again != s {
			t.Fatalf("took %q, which formatCursor writes as %q", s, again)
		}
		if err := protocol.CheckCursor(s); err != nil {
			t.Fatalf("took %q, which the client's check of a cursor refuses: %v", s, err)
		}
	})
}

// fuzzProxies are the trusted proxies of the clientIP and FuzzHandler
// servers: the peers whose X-Forwarded-For is read.
var fuzzProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}

// clientIP of a request from a peer that is no trusted proxy is the peer's
// host, whatever its headers say; from one that is, it is the last entry of
// its X-Forwarded-For lines, read as one list (RFC 9110 §5.6.1: OWS around
// each), as one address with no zone, or the peer's host where that entry is
// not one. The limits key it as an IPv4 address or an IPv6 /64 and /48, with
// no zone and never a mapped IPv4 address (checkKeys). The lines are as
// net/http hands them to a handler (handed).
func FuzzClientIP(f *testing.F) {
	for _, c := range []struct{ peer, xff string }{
		{"192.0.2.1:40000", "203.0.113.9"},
		{"192.0.2.1:40000", "192.0.2.1, 198.51.100.7,203.0.113.9"},
		{"[2001:db8::1]:40000", "192.0.2.1\n2001:db8::9"},
		{"192.0.2.1:40000", "fe80::1%eth0"},
		{"192.0.2.1:40000", "::ffff:203.0.113.9"},
		{"192.0.2.1:40000", "203.0.113.9, unknown"},
		{"192.0.2.1:40000", "203.0.113.9,\t2001:db8::7 "},
		{"192.0.2.1:40000", ", ,"},
		{"192.0.2.1:40000", " 203.0.113.9"},
		{"[::ffff:192.0.2.1]:40000", "203.0.113.9"},
		{"[fe80::1%lo0]:40000", "203.0.113.9"},
		{"198.51.100.1:40000", "203.0.113.9"},
		{"192.0.2.1", "203.0.113.9"},
		{"", ""},
	} {
		f.Add(c.peer, c.xff)
	}
	s := New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), TrustedProxies: fuzzProxies})
	f.Fuzz(func(t *testing.T, peer, xff string) {
		r := handed("X-Forwarded-For", xff)
		if r == nil {
			return
		}
		r.RemoteAddr = peer
		got := s.clientIP(r)
		host := peer
		if h, _, err := net.SplitHostPort(peer); err == nil {
			host = h
		}
		ph, err := netip.ParseAddr(host)
		trusted := err == nil && slices.ContainsFunc(fuzzProxies, func(p netip.Prefix) bool { return p.Contains(ph.Unmap().WithZone("")) })
		list := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
		last := list[strings.LastIndexByte(list, ',')+1:]
		want := host
		if a, err := netip.ParseAddr(strings.Trim(last, " \t")); trusted && err == nil {
			want = a.WithZone("").String()
		}
		if got != want {
			t.Fatalf("from %q, trusted %v, with X-Forwarded-For %q: the client is %q, want %q", peer, trusted, r.Header.Values("X-Forwarded-For"), got, want)
		}
		checkKeys(t, got)
	})
}

// hostAddr takes exactly what netip.ParseAddr does, and gives the same
// address with no zone, an IPv4 address written as IPv6 as the IPv4 address;
// what it gives, written, it reads as itself. A refusal gives no address.
// The limits key what it takes as an IPv4 address or an IPv6 /64 and /48
// (checkKeys).
func FuzzHostAddr(f *testing.F) {
	for _, s := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "::ffff:c000:201", "fe80::1%eth0", "::ffff:192.0.2.1%x", "::", "0.0.0.0", "1.2.3", "192.0.2.01", "[2001:db8::1]", "2001:db8::1/64", "", "%"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		a, ok := hostAddr(host)
		parsed, err := netip.ParseAddr(host)
		if ok != (err == nil) {
			t.Fatalf("%q: taken %v, netip.ParseAddr says %v", host, ok, err)
		}
		if !ok {
			if a != (netip.Addr{}) {
				t.Fatalf("%q: refused, with %v beside it", host, a)
			}
			return
		}
		switch {
		case !a.IsValid() || a.Zone() != "" || a.Is4In6():
			t.Fatalf("%q: read as %v, with a zone or a mapped IPv4 address", host, a)
		case a.As16() != parsed.As16():
			t.Fatalf("%q: read as %v, another address", host, a)
		}
		if again, ok := hostAddr(a.String()); !ok || again != a {
			t.Fatalf("%q: read as %v, whose text reads as %v", host, a, again)
		}
		checkKeys(t, host)
	})
}

// checkKeys holds the limits' keys of host to what ipKey and rangeKey say:
// an address is keyed as its IPv4 address, or as its IPv6 /64 and /48, each
// a prefix holding it, and never by a zone or a mapped IPv4 address; what is
// no address is keyed as itself, with no /48.
func checkKeys(t *testing.T, host string) {
	t.Helper()
	k, rk := ipKey(host), rangeKey(host)
	a, ok := hostAddr(host)
	if !ok {
		if k != host || rk != "" {
			t.Fatalf("%q, no address: keyed %q and %q", host, k, rk)
		}
		return
	}
	if a.Is4() {
		if k != a.String() || rk != "" {
			t.Fatalf("%q, an IPv4 address: keyed %q and %q", host, k, rk)
		}
		return
	}
	for _, c := range []struct {
		key  string
		bits int
	}{{k, 64}, {rk, 48}} {
		p, err := netip.ParsePrefix(c.key)
		if err != nil || p.Bits() != c.bits || !p.Contains(a) || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			t.Fatalf("%q, an IPv6 address: keyed %q, not its /%d", host, c.key, c.bits)
		}
	}
}

// handed is a request with the field name, one line of it for each line
// of lines, as net/http's server hands it to a handler, or nil for lines it
// would refuse.
func handed(name, lines string) *http.Request {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: " + fuzzName + "\r\n")
	if lines != "" {
		for l := range strings.SplitSeq(lines, "\n") {
			b.WriteString(name + ": " + l + "\r\n")
		}
	}
	b.WriteString("\r\n")
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(b.String())))
	if err != nil {
		return nil
	}
	return r
}

// acceptsGzip gives the answer RFC 9110 §12.5.3 reads in a request's
// Accept-Encoding fields, read here apart from it, with the readings its doc
// comment names where the RFC gives none (gzipByReference), and the same
// whether the fields are lines of their own or one line (RFC 9110 §5.3).
// The fields are as net/http hands them to a handler (handed).
func FuzzAcceptsGzip(f *testing.F) {
	for _, s := range []string{
		"", "gzip", "GZip", "x-gzip", "br, gzip", "br\ngzip", "gzip;q=0.5", "gzip ; Q=0.001", "*", "br", "identity",
		"gzip;q=0", "gzip; q=0.000", "gzip;q=nope", "gzip;level=1", "*;q=0", "*, gzip;q=0", "gzip;q=0, *", "gzip, *;q=0",
		"gzipped", "gzip;", "gzip;q=1;q=0", "gzip;q=1e-3", "gzip;q=0x1p-1", "gzip;q=inf", "gzip, gzip;q=0", "\tgzip\t",
		"gzip ", "\u0085gzip", "gzip;q=0.5 ", ",,gzip,,",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, lines string) {
		r := handed("Accept-Encoding", lines)
		if r == nil {
			return
		}
		fields := r.Header.Values("Accept-Encoding")
		got := acceptsGzip(fields)
		if want := gzipByReference(fields); got != want {
			t.Fatalf("Accept-Encoding %q: %v, and the RFC reads %v", fields, got, want)
		}
		if one := acceptsGzip([]string{strings.Join(fields, ",")}); one != got {
			t.Fatalf("Accept-Encoding %q: %v, and %v as one line", fields, got, one)
		}
	})
}

// gzipByReference reads Accept-Encoding fields as RFC 9110 §12.5.3 does: one
// list of codings (§5.3), each with optional whitespace (OWS, §5.6.3: spaces
// and tabs) around its parts, its name in any case (§8.4.1), gzip or its
// alias x-gzip (§8.4.1.3), and a weight (§12.4.2) of q, in any case, after
// a semicolon; a coding named outright outranks "*". Where the RFC gives no
// reading, acceptsGzip's doc comment does: none for no field, a coding
// named twice by its last weight, a weight read by strconv.ParseFloat and
// taken above zero, none for any other parameter, and 1 for none.
func gzipByReference(fields []string) bool {
	ows := func(s string) string { return strings.Trim(s, " \t") }
	var gz, star *bool
	for _, c := range strings.Split(strings.Join(fields, ","), ",") {
		parts := strings.Split(c, ";")
		w := true
		switch rest := strings.Join(parts[1:], ";"); {
		case len(parts) == 1 || ows(rest) == "":
		case len(parts) > 2:
			w = false
		default:
			k, v, ok := strings.Cut(rest, "=")
			n, err := strconv.ParseFloat(ows(v), 64)
			w = ok && protocol.LowerASCII(ows(k)) == "q" && err == nil && n > 0
		}
		switch protocol.LowerASCII(ows(parts[0])) {
		case "gzip", "x-gzip":
			gz = &w
		case "*":
			star = &w
		}
	}
	switch {
	case gz != nil:
		return *gz
	case star != nil:
		return *star
	}
	return false
}

// The ACL a mailbox PUTs is read as putACL reads it (decodeJSON) and checked
// as it checks it (protocol.CheckACL, at the bound given, 0 for none): a
// refusal is not an ACL, or past the bound exactly when it has more entries
// than it, with no ACL beside it; an ACL taken holds exactly the entries
// written, AnyAddress as itself and each address by its one form, each once,
// admits a sender by its deny list then its allow list, and is its own
// document, checked again.
func FuzzCheckACL(f *testing.F) {
	addr := func(s string) string { return protocol.Address(sha512.Sum384([]byte(s))).String() }
	a, b, c := addr("a"), addr("b"), addr("c")
	for _, s := range []struct {
		body string
		max  uint16
	}{
		{`{"allow":["*"],"deny":[]}`, 0},
		{`{"allow":["*"]}`, 1},
		{`{"allow":[],"deny":["*"]}`, 0},
		{`{"allow":["` + a + `","` + b + `","` + a + `"],"deny":["` + c + `"]}`, 0},
		{`{"allow":["` + a + `","` + b + `","` + a + `"],"deny":["` + c + `"]}`, 3},
		{`{"allow":["*","*","` + a + `"],"deny":["*"]}`, 4},
		{`{"allow":["` + strings.ToUpper(a) + `"]}`, 0},
		{`{"allow":["` + a[:len(a)-1] + `"]}`, 0},
		{`{"allow":["` + a + `="]}`, 0},
		{`{"allow":["d_"]}`, 0},
		{`{"allow":["**"]}`, 0},
		{`{"deny":[]}`, 0},
		{`{"allow":null,"deny":null}`, 0},
		{`{"allow":[],"other":1}`, 0},
		{`{"allow":[1]}`, 0},
		{`{"allow":[],"allow":["*"]}`, 0},
		{`[]`, 0},
	} {
		f.Add([]byte(s.body), s.max)
	}
	f.Add([]byte(`{"allow":["*"]}`), uint16(DefaultLimits().ACLEntries))
	f.Fuzz(func(t *testing.T, body []byte, bound uint16) {
		var d protocol.ACLDocument
		if decodeJSON(body, &d) != nil {
			return
		}
		n, written := int(bound), len(d.Allow)+len(d.Deny)
		acl, err := protocol.CheckACL(&d, n)
		if err != nil {
			switch {
			case acl != nil:
				t.Fatal("refused, with an ACL beside it")
			case errors.Is(err, protocol.ErrACLTooLarge) != (d.Allow != nil && n > 0 && written > n):
				t.Fatalf("%d entries, at a bound of %d, refused as %v", written, n, err)
			case !errors.Is(err, protocol.ErrACLTooLarge) && !errors.Is(err, protocol.ErrACL):
				t.Fatalf("refused as %v", err)
			}
			return
		}
		if d.Allow == nil || n > 0 && written > n {
			t.Fatalf("took %d entries at a bound of %d, an allow list of %v", written, n, d.Allow)
		}
		for _, l := range []struct {
			entries []string
			list    protocol.ACLList
		}{{d.Allow, acl.Allow}, {d.Deny, acl.Deny}} {
			var want []protocol.Address
			for _, e := range l.entries {
				if e == protocol.AnyAddress {
					continue
				}
				a, err := protocol.ParseAddress(e)
				if err != nil {
					t.Fatalf("took the entry %q, which is neither an address nor %q", e, protocol.AnyAddress)
				}
				want = append(want, a)
			}
			if l.list.Any != slices.Contains(l.entries, protocol.AnyAddress) || !slices.Equal(l.list.Addrs, protocol.NewACLList(false, want).Addrs) {
				t.Fatalf("the entries %q are checked as %+v", l.entries, l.list)
			}
			for _, a := range want {
				if acl.Admits(a) != (!acl.Deny.Has(a) && acl.Allow.Has(a)) {
					t.Fatalf("%s is admitted %v, against its lists", a, acl.Admits(a))
				}
			}
		}
		doc := acl.Document()
		again, err := protocol.CheckACL(&doc, n)
		if err != nil || !again.SameLists(acl) || !reflect.DeepEqual(again.Document(), doc) {
			t.Fatalf("its own document %+v is checked as %+v: %v", doc, again, err)
		}
	})
}

// ParseLimits, of a limits file laid over the defaults, refuses with no
// limits beside it; the limits it gives hold to Limits.Check, keep the
// defaults' startup-only fields and every field the file names no member of,
// and are read again as themselves from the file LimitsFile writes of them.
func FuzzParseLimits(f *testing.F) {
	base := DefaultLimits()
	for _, s := range []string{
		string(LimitsFile(base)), string(LimitsFile(relaxed())), `{}`, `{"poll_refill":"50s"}`, `{"poll_refill":"-1ns"}`,
		`{"poll_burst":1.5}`, `{"poll_burst":1e3}`, `{"poll_burst":"10"}`, `{"max_size":1}`, `{"acl_entries":0}`,
		`{"max_certificate_lifetime":"1h"}`, `{"head_bytes":1}`, `{"no_such_limit":1}`, `{"poll_burst":1,"poll_burst":2}`,
		`{"poll_refill":"9223372036854775807ns"}`, `{"poll_burst":9223372036854775808}`, `[]`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLimits(b, base)
		if err != nil {
			if !reflect.ValueOf(l).IsZero() {
				t.Fatalf("refused (%v), with limits beside it", err)
			}
			return
		}
		if err := l.Check(); err != nil {
			t.Fatalf("limits Check refuses: %v", err)
		}
		var members map[string]json.RawMessage
		if err := protocol.UnmarshalRequest(b, &members); err != nil {
			t.Fatalf("took a file that is no JSON object: %v", err)
		}
		v, bv := reflect.ValueOf(l), reflect.ValueOf(base)
		for field := range startupOnly {
			if !v.FieldByName(field).Equal(bv.FieldByName(field)) {
				t.Fatalf("the startup-only %s is not the base's", field)
			}
		}
		for _, fm := range limitFields() {
			if _, named := members[fm.member]; !named && !v.FieldByName(fm.field).Equal(bv.FieldByName(fm.field)) {
				t.Fatalf("%s, which the file does not name, is not the base's", fm.member)
			}
		}
		again, err := ParseLimits(LimitsFile(l), base)
		if err != nil || again != l {
			t.Fatalf("the limits, written by LimitsFile, are read as %+v: %v", again, err)
		}
	})
}

// ParseVersionPolicy refuses with no document beside it; the document it
// gives holds to protocol.ServerDocument.Check, carries the server's own
// members (policyOf: the limits' longest certificate, the code's
// capabilities, the implementation), and its policy, written again, is read
// as the same document.
func FuzzParseVersionPolicy(f *testing.F) {
	l := DefaultLimits()
	for _, s := range []string{
		policyText("1.2", "1.5"), `{}`, `{"min_version":"1.2"}`, `{"latest_version":"18446744073709551615.0.1"}`,
		`{"deprecations":[{"below":"1.4","effective_at":"2027-01-01T00:00:00Z"}],"sunsets":[{"below":"1.1","effective_at":"2026-12-01T00:00:00Z"}]}`,
		`{"sunsets":[{"below":"1.1","effective_at":"2026-12-01T00:00:00.5Z"}]}`, `{"deprecations":[{"below":"1.4"}]}`,
		`{"min_version":"1.2","capabilities":[]}`, `{"max_certificate_lifetime_seconds":3891600}`, `{"min_version":"01.2"}`,
		`{"min_version":"1.2","min_version":"1.3"}`, `{"min_version":1.2}`, `{"deprecations":null,"sunsets":[]}`, `[]`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseVersionPolicy(b, l)
		if err != nil {
			if !reflect.ValueOf(d).IsZero() {
				t.Fatalf("refused (%v), with a document beside it", err)
			}
			return
		}
		if err := d.Check(); err != nil {
			t.Fatalf("the document's Check refuses: %v", err)
		}
		own := policyOf(protocol.ServerDocument{}, l)
		if d.MaxCertificateLifetime != own.MaxCertificateLifetime || !reflect.DeepEqual(d.Capabilities, own.Capabilities) || !reflect.DeepEqual(d.Server, own.Server) {
			t.Fatalf("the document's own members are %d, %v and %v, not the server's", d.MaxCertificateLifetime, d.Capabilities, d.Server)
		}
		written, err := json.Marshal(versionPolicy{MinVersion: d.MinVersion, LatestVersion: d.LatestVersion, Deprecations: d.Deprecations, Sunsets: d.Sunsets})
		if err != nil {
			t.Fatal(err)
		}
		if again, err := ParseVersionPolicy(written, l); err != nil || !reflect.DeepEqual(again, d) {
			t.Fatalf("its policy, written as %s, is read as %+v: %v", written, again, err)
		}
	})
}

// fuzzName is the name the fuzzed requests call the server by, the one the
// vectors' passes are made for.
const fuzzName = "dromas.example"

// fuzzPeer is the peer every fuzzed request comes from: a trusted proxy
// (fuzzProxies), so its X-Forwarded-For reaches the limits.
const fuzzPeer = "192.0.2.1:40000"

// fuzzNow is the vectors' clock, the server's in FuzzHandler, at which every
// pass and statement of theirs holds.
func fuzzNow(f *testing.F) time.Time {
	f.Helper()
	now, err := protocol.ParseTime(strings.TrimSpace(string(clientFile(f, "testdata/vectors/now"))))
	if err != nil {
		f.Fatal(err)
	}
	return now
}

// fuzzCall is a request as FuzzHandler takes one: its method, its target,
// its Authorization line, any other header lines, and its body.
type fuzzCall struct {
	method, target, auth, head string
	body                       []byte
}

// request is the request net/http's server hands a handler for the call's
// bytes, from fuzzPeer to fuzzName, or nil for bytes it answers itself: a
// request line or a header it refuses, and any Expect (417, or its 100
// Continue). The body is framed by its length alone, so the fuzzer moves
// what a handler reads, never how net/http frames it.
func (c fuzzCall) request() *http.Request {
	var b bytes.Buffer
	b.WriteString(c.method + " " + c.target + " HTTP/1.1\r\nHost: " + fuzzName + "\r\n")
	if c.auth != "" {
		b.WriteString("Authorization: " + c.auth + "\r\n")
	}
	for l := range strings.SplitSeq(c.head, "\n") {
		name, _, _ := strings.Cut(l, ":")
		switch textproto.CanonicalMIMEHeaderKey(textproto.TrimString(name)) {
		case "Content-Length", "Transfer-Encoding", "Host", "":
			continue
		}
		b.WriteString(l + "\r\n")
	}
	if len(c.body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(c.body))
	}
	b.WriteString("\r\n")
	b.Write(c.body)
	r, err := http.ReadRequest(bufio.NewReader(&b))
	if err != nil || len(r.Header.Values("Expect")) > 0 {
		return nil
	}
	delete(r.Header, "Host")
	r.RemoteAddr = fuzzPeer
	return r
}

// fuzzVectors are the client's vector mailboxes A, B and C, the calls that
// make A and B on a server at the vectors' clock (A's message to B among
// them), and seeds of every route as they call it.
type fuzzVectors struct {
	setup []fuzzCall
	seeds []fuzzCall
}

func readFuzzVectors(f *testing.F) fuzzVectors {
	f.Helper()
	read := func(p string) []byte { return clientFile(f, "testdata/vectors/"+p) }
	pass := func(m string) string { return strings.TrimSpace(string(read(m + "/pass.authorization"))) }
	path := func(m, rest string) string {
		return "/v1/" + protocol.AddressOf(read(m+"/identity.doc")).String() + rest
	}
	js := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	// Every call names the latest version policyText gives, as a client
	// names its own, but the few that name another or none.
	latest := protocol.VersionHeader + ": 1.5.0"
	at := func(head string) string {
		if head == "" {
			return latest
		}
		return latest + "\n" + head
	}
	register := func(m string) fuzzCall {
		return fuzzCall{"PUT", path(m, ""), pass(m), latest, js(protocol.RegisterRequest{
			Identity: read(m + "/identity.doc"), Prekey: read(m + "/prekey-1.txt"), PrekeySignature: read(m + "/prekey-1.txt.sig")})}
	}
	ciphertext := read("message/a-to-b.age")
	send := fuzzCall{"POST", path("b", "/messages?"+protocol.SendQuery{Statement: protocol.StatementHash(read("b/prekey-1.txt"))}.Encode()), pass("a"), latest, ciphertext}
	msg := path("b", "/messages/"+hexID(sha256.Sum256(ciphertext)))
	acl := js(protocol.ACLDocument{Allow: []string{protocol.AnyAddress}, Deny: []string{protocol.AddressOf(read("c/identity.doc")).String()}})
	v := fuzzVectors{setup: []fuzzCall{register("a"), register("b"), send}}
	v.seeds = append(slices.Clone(v.setup), []fuzzCall{
		register("c"),
		{"GET", protocol.DocumentPath, "", at(""), nil},
		{"GET", protocol.DocumentPath, "", "", nil},
		{"GET", path("a", ""), "", "", nil},
		{"GET", path("a", ""), "", protocol.VersionHeader + ": 1.1.0", nil},
		{"GET", path("a", ""), "", protocol.VersionHeader + ": 1.3.0-rc.1\nAccept-Encoding: gzip", nil},
		{"HEAD", path("a", ""), "", at(""), nil},
		{"GET", path("c", ""), "", at("If-None-Match: *"), nil},
		{"GET", "/v1/d_", "", at(""), nil},
		{"PUT", path("a", "/prekey"), pass("a"), at(""), js(protocol.PrekeyRequest{Prekey: read("a/prekey-2.txt"), PrekeySignature: read("a/prekey-2.txt.sig")})},
		{"PUT", path("a", "/revocation"), "", at(""), js(protocol.Revocations{Identity: read("a/identity.doc"), RevokedCertificates: read("a/revoked-certs.txt"), RevokedCertificatesSignature: read("a/revoked-certs.sig")})},
		{"PUT", path("a", "/revocation"), "", at(""), js(protocol.Revocations{Identity: read("a/identity.doc"), Revocation: read("a/revoke.sig")})},
		{"GET", path("a", "/revocation"), "", at(""), nil},
		{"PUT", path("b", "/acl"), pass("b"), at("If-Match: *"), acl},
		{"GET", path("b", "/acl"), pass("b"), at(""), nil},
		{"PUT", path("b", "/account"), pass("b"), at(""), js(protocol.AdoptRequest{Key: "not a key"})},
		{"DELETE", path("b", "/account"), pass("b"), at(""), nil},
		{"GET", path("b", "/messages"), pass("b"), at("Accept-Encoding: gzip"), nil},
		{"GET", path("b", "/messages?wait=30"), pass("b"), at("If-None-Match: *"), nil},
		{"GET", path("b", "/messages?cursor="+formatCursor(Header{ReceivedAt: fuzzNow(f)})), pass("b"), at(""), nil},
		{"GET", msg, pass("b"), at(""), nil},
		{"DELETE", msg, pass("b"), at(""), nil},
		{"GET", msg, pass("a"), at("X-Forwarded-For: 2001:db8::1%eth0"), nil},
		{"GET", protocol.LinkPath + protocol.AddressOf(read("a/identity.doc")).String(), "", "", nil},
		{"GET", protocol.LinkPath, "", "", nil},
		{"OPTIONS", "*", "", "", nil},
		{"GET", "/llms.txt", "", "", nil},
	}...)
	return v
}

// The handler, on the in-memory store at the vectors' clock with the
// version policy policyText gives, A and B registered and A's message to B
// held, and each request a fresh server's (so no budget it spends ends the
// next input at 429), never panics, answers no 5xx, and gives every answer
// api/openapi.yaml describes (apitest.Handler). It reaches the gate, the
// pass check and each route's checks in their real order. A long poll is
// held for Limits.MaxWait, ten milliseconds here.
func FuzzHandler(f *testing.F) {
	now := fuzzNow(f)
	v := readFuzzVectors(f)
	for _, c := range v.seeds {
		f.Add(c.method, c.target, c.auth, c.head, c.body)
	}
	l := relaxed()
	l.MaxWait = 10 * time.Millisecond
	policy, err := ParseVersionPolicy([]byte(policyText("1.2", "1.5")), l)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, method, target, auth, head string, body []byte) {
		c := fuzzCall{method, target, auth, head, body}
		r := c.request()
		if r == nil {
			return
		}
		clk := &clock{t: now}
		s := New(Config{Store: NewMemStore(clk.Now), Limits: l, Now: clk.Now, TrustedProxies: fuzzProxies, Policy: policy})
		h := s.Handler()
		for _, set := range v.setup {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, set.request())
			if w.Code >= 300 {
				t.Fatalf("%s %s, before the input: %d %s", set.method, set.target, w.Code, w.Body)
			}
		}
		w := httptest.NewRecorder()
		if r.RequestURI == "*" {
			// The router's own plain 400 (http.ServeMux), to a target the
			// description cannot name, which apitest takes for no route.
			h.ServeHTTP(w, r)
		} else {
			apitest.Handler(t, h).ServeHTTP(w, r)
		}
		if w.Code >= 500 {
			t.Fatalf("%s %s: %d %s", method, target, w.Code, w.Body)
		}
	})
}
