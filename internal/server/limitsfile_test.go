package server

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// startupBase is the base a limits file is laid over with the defaults' own
// startup-only limits, and every other field zero.
func startupBase() Limits {
	d := DefaultLimits()
	return Limits{HeadBytes: d.HeadBytes, HeadTimeout: d.HeadTimeout}
}

// Every limit is a count or a duration, the two forms a limits file writes.
func TestEveryLimitIsACountOrADuration(t *testing.T) {
	t.Parallel()
	ty := reflect.TypeFor[Limits]()
	for i := range ty.NumField() {
		f := ty.Field(i)
		if f.Type != durationType && f.Type.Kind() != reflect.Int {
			t.Errorf("%s is a %s, neither a count nor a duration", f.Name, f.Type)
		}
	}
}

// The defaults written as a limits file read back as the defaults over a base
// that holds nothing but the startup-only limits: so every limit but those has
// a member, which the file names and reads.
func TestTheDefaultsAreAFileThatReadsBack(t *testing.T) {
	t.Parallel()
	got, err := ParseLimits(LimitsFile(DefaultLimits()), startupBase())
	if err != nil {
		t.Fatal(err)
	}
	if got != DefaultLimits() {
		t.Fatalf("the defaults read back as\n%+v\nwant\n%+v", got, DefaultLimits())
	}
	for f := range startupOnly {
		if strings.Contains(string(LimitsFile(DefaultLimits())), `"`+limitMember(f)+`"`) {
			t.Errorf("the file names %s, which http.Server fixes at start", f)
		}
	}
}

// A member is its field in snake case, an initialism one word.
func TestALimitsMemberIsItsFieldInSnakeCase(t *testing.T) {
	t.Parallel()
	for field, want := range map[string]string{
		"MaxSize":                     "max_size",
		"ACLEntries":                  "acl_entries",
		"SendsPerMinutePerIP":         "sends_per_minute_per_ip",
		"MaxLongPollsPerRange":        "max_long_polls_per_range",
		"CertificateRevocationsBurst": "certificate_revocations_burst",
	} {
		if got := limitMember(field); got != want {
			t.Errorf("%s: %q, want %q", field, got, want)
		}
	}
}

// A member a file holds replaces its field, and every other field is the
// base's, the startup-only ones among them.
func TestALimitsFileLaysOverItsBase(t *testing.T) {
	t.Parallel()
	base := DefaultLimits()
	base.HeadBytes = 12345
	got, err := ParseLimits([]byte(`{"registrations_per_hour": 7, "poll_refill": "30s"}`), base)
	if err != nil {
		t.Fatal(err)
	}
	want := base
	want.RegistrationsPerHour, want.PollRefill = 7, 30*time.Second
	if got != want {
		t.Fatalf("got\n%+v\nwant\n%+v", got, want)
	}
	if got, err := ParseLimits([]byte(`{}`), base); err != nil || got != base {
		t.Fatalf("an empty file: %v, %+v", err, got)
	}
}

// A file that is not an object of limits, names a member that is no limit (a
// startup-only one among them) or gives a member another form is refused,
// naming the member at most and never a value.
func TestALimitsFileThatBreaksItsFormIsRefused(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, body, says string }{
		{"not JSON", `registrations_per_hour: 7`, "not a JSON object"},
		{"an array", `[7]`, "not a JSON object"},
		{"a member twice", `{"poll_burst": 1, "poll_burst": 2}`, ""},
		{"no limit", `{"secretish_limit": 7}`, `"secretish_limit" is no limit`},
		{"startup-only", `{"head_bytes": 7}`, `"head_bytes" is no limit`},
		{"a count as a string", `{"poll_burst": "secretish"}`, `"poll_burst" is not a whole number`},
		{"a fraction", `{"poll_burst": 1.5}`, `"poll_burst" is not a whole number`},
		{"a duration as a number", `{"poll_refill": 50}`, `"poll_refill" is not a duration`},
		{"a duration of another form", `{"poll_refill": "secretish"}`, `"poll_refill" is not a duration`},
	} {
		_, err := ParseLimits([]byte(c.body), DefaultLimits())
		if err == nil || !strings.Contains(err.Error(), c.says) || strings.Contains(err.Error(), "secretish\"") || strings.Contains(err.Error(), ": secretish") {
			t.Errorf("%s: %v, want a refusal saying %q and no value", c.name, err, c.says)
		}
	}
}

// refusedFile is the error ParseLimits gives the file of one member m of
// value v over the defaults.
func refusedFile(m string, v any) error {
	j := fmt.Sprint(v)
	if d, ok := v.(time.Duration); ok {
		j = `"` + d.String() + `"`
	}
	_, err := ParseLimits([]byte(`{"`+m+`": `+j+`}`), DefaultLimits())
	return err
}

// A cap on a ciphertext above the protocol's largest (PROTOCOL.md §11.10), not
// a whole number of its own padding blocks (§9.3), or below zero is refused,
// naming its member. Control: the caps the protocol allows pass, its largest
// ciphertext among them.
func TestASizeCapTheProtocolDoesNotAllowIsRefused(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"max_size", "account_max_size"} {
		for _, c := range []struct {
			n    int
			says string
		}{
			{protocol.MaxCiphertext + 1, "over the largest ciphertext"},
			{2 * protocol.MaxCiphertext, "over the largest ciphertext"},
			{100 << 10, "not a whole number of its own padding blocks"},
			{protocol.MaxCiphertext - 1, "not a whole number of its own padding blocks"},
			{-1, "not a size"},
		} {
			if err := refusedFile(m, c.n); err == nil || !strings.HasPrefix(err.Error(), m+":") || !strings.Contains(err.Error(), c.says) {
				t.Errorf("%s %d: %v, want a refusal naming the member and saying %q", m, c.n, err, c.says)
			}
		}
		for _, n := range []int{0, protocol.PadMinBlock, 64 << 10, 10 << 20, protocol.MaxCiphertext} {
			if err := refusedFile(m, n); err != nil {
				t.Errorf("%s %d: %v", m, n, err)
			}
		}
	}
}

// A budget of new messages turned off, or refilled faster than
// ReceiveCeiling, is refused, naming its member. Control: a budget of one at
// the ceiling passes.
func TestNewMessagesPastTheCeilingAreRefused(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		m    string
		v    any
		says string
	}{
		{"receive_burst", 0, "no budget"},
		{"receive_burst", -1, "no budget"},
		{"receive_refill", time.Duration(0), "shorter than"},
		{"receive_refill", ReceiveCeiling - time.Millisecond, "shorter than"},
	} {
		if err := refusedFile(c.m, c.v); err == nil || !strings.HasPrefix(err.Error(), c.m+":") || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s %v: %v, want a refusal naming the member and saying %q", c.m, c.v, err, c.says)
		}
	}
	l := DefaultLimits()
	l.ReceiveBurst, l.ReceiveRefill = 1, ReceiveCeiling
	if err := l.Check(); err != nil {
		t.Errorf("at the ceiling: %v", err)
	}
}

// An ACL bound that is off or over the protocol's (PROTOCOL.md §11.14) is
// refused, naming its member. Control: one, the protocol's bound and the
// default pass.
func TestAnACLBoundOffOrOverTheProtocolsIsRefused(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1, protocol.MaxACLEntries + 1} {
		if err := refusedFile("acl_entries", n); err == nil || !strings.HasPrefix(err.Error(), "acl_entries:") {
			t.Errorf("acl_entries %d: %v, want a refusal naming the member", n, err)
		}
	}
	for _, n := range []int{1, protocol.MaxACLEntries, DefaultLimits().ACLEntries} {
		if err := refusedFile("acl_entries", n); err != nil {
			t.Errorf("acl_entries %d: %v", n, err)
		}
	}
}

// A longest certificate that is not above the message TTL and the hour
// together signs no message (PROTOCOL.md §11.18), and one above the
// protocol's maximum no verifier takes (§5.2): each is refused, naming its
// member. Control: a second above the least, the default and the protocol's
// maximum pass.
func TestAMaximumCertificateThatSignsNoMessageIsRefused(t *testing.T) {
	t.Parallel()
	least := protocol.TTL + protocol.MaxSkew
	for _, v := range []time.Duration{least, least - time.Second, least + time.Second/2, protocol.MaxCertificateLifetime + time.Second} {
		if err := refusedFile("max_certificate_lifetime", v); err == nil || !strings.HasPrefix(err.Error(), "max_certificate_lifetime:") {
			t.Errorf("max_certificate_lifetime %v: %v, want a refusal naming the member", v, err)
		}
	}
	for _, v := range []time.Duration{least + time.Second, DefaultLimits().MaxCertificateLifetime, protocol.MaxCertificateLifetime} {
		if err := refusedFile("max_certificate_lifetime", v); err != nil {
			t.Errorf("max_certificate_lifetime %v: %v", v, err)
		}
	}
}

// A number a day that is on with a bucket of nothing is refused, for each of
// the four, naming the bucket's member. Control: a limit that is off with no
// bucket passes.
func TestABurstOfNothingIsRefused(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"sends", "renewals", "certificates", "certificate_revocations"} {
		if err := refusedFile(name+"_burst", 0); err == nil || !strings.HasPrefix(err.Error(), name+"_burst:") {
			t.Errorf("%s_burst 0: %v, want a refusal naming the member", name, err)
		}
	}
	if _, err := ParseLimits([]byte(`{"sends_per_day": 0, "sends_burst": 0}`), DefaultLimits()); err != nil {
		t.Errorf("a limit that is off with no bucket: %v", err)
	}
}

// The bound on a limits file holds every member at its longest value, written
// with indents; one past the bound is refused.
func TestTheLargestLimitsFileFits(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	v := reflect.ValueOf(&l).Elem()
	for _, f := range limitFields() {
		v.FieldByName(f.field).SetInt(math.MinInt64)
	}
	if b := LimitsFile(l); len(b) > MaxLimitsFile {
		t.Fatalf("the largest limits file is %d bytes, past the bound of %d", len(b), MaxLimitsFile)
	}
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, []byte(`{}`+strings.Repeat(" ", MaxLimitsFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadLimits(path, DefaultLimits()); err == nil {
		t.Fatal("a file past the bound was read")
	}
}

// A resized bucket keeps each key's state, read by the new size: a key that
// spent the one token of a bucket of one has one left of a bucket of two, and
// none after it, never a full bucket of two.
func TestAResizedBucketKeepsItsKeys(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	bs := newBuckets("test", 1, time.Hour)
	if ok, _ := bs.take("a", t0); !ok {
		t.Fatal("the first token was refused")
	}
	if ok, _ := bs.take("a", t0); ok {
		t.Fatal("a bucket of one gave two")
	}
	bs.resize(2, time.Hour)
	if ok, _ := bs.take("a", t0); !ok {
		t.Fatal("a bucket grown to two gave none to a key that spent one")
	}
	if ok, _ := bs.take("a", t0); ok {
		t.Fatal("a bucket grown to two started its key full")
	}
}

// A limits file reloaded puts its limits in force for the next request. A
// key keeps what it owes in time, as Boulder keeps a key's TAT, so a key that
// spent a registration a hour is refused at once under three an hour, and
// takes its next twenty minutes on, where one a hour would refuse it for the
// hour (the control). The server's document serves the file's longest
// certificate, beside the version policy in force.
func TestAReloadedLimitsFileIsInForce(t *testing.T) {
	t.Parallel()
	for _, reloaded := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "limits.json")
		write := func(body string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write(`{"registrations_per_hour": 1, "range_registrations_per_hour": 0}`)
		l, read, err := ReadLimits(path, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		e := newEnv(t, l, func(c *Config) { c.Policy = protocol.ServerDocument{LatestVersion: "1.5.0"} })
		call := e.caller()
		register := func() reply {
			t.Helper()
			r := e.raw()
			r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
			return call("192.0.2.9", "PUT", r.path(""), r.registration(1), r.pass(1))
		}
		e.want(register(), http.StatusCreated, "")
		e.limited(register(), protocol.QuotaRegistrations)
		if reloaded {
			write(`{"registrations_per_hour": 3, "range_registrations_per_hour": 0, "max_certificate_lifetime": "500h"}`)
			e.server.Limits(path, read, DefaultLimits()).reload(false)
			e.limited(register(), protocol.QuotaRegistrations)
		}
		e.clock.Add(21 * time.Minute)
		if !reloaded {
			e.limited(register(), protocol.QuotaRegistrations)
			continue
		}
		e.want(register(), http.StatusCreated, "")
		var doc protocol.ServerDocument
		if err := protocol.Unmarshal(e.do("GET", protocol.DocumentPath, nil, "").body, &doc); err != nil || doc.MaxCertificateLifetime != uint64(500*time.Hour/time.Second) || doc.LatestVersion != "1.5.0" {
			t.Fatalf("the document after the reload: %+v, %v", doc, err)
		}
	}
}

// A limits file that fails at a reload keeps the limits in force.
func TestAFailedReloadKeepsTheLimits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, []byte(`{"poll_after": 30}`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, read, err := ReadLimits(path, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, l)
	if err := os.WriteFile(path, []byte(`{"poll_after": 40, "acl_entries": 0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.server.Limits(path, read, DefaultLimits()).reload(true)
	if got := e.server.limits().PollAfter; got != 30 {
		t.Fatalf("poll_after %d after a refused file, want 30", got)
	}
}
