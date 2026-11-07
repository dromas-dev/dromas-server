package server

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/dromas-dev/dromas-client/protocol"
)

// The limits file (serve --limits) is a runtime file: a JSON object with one
// optional member for each limit, named as its Limits field in snake case
// (limitMember), each a number, or a duration as Go writes one ("50s"). A
// member left out is the default it is laid over. The limits reload while the
// server runs, but for the ones http.Server fixes at start (startupOnly), which
// are serve's flags, as Prometheus keeps its flags for what cannot change
// while it runs and its configuration file for what can.

// startupOnly are the Limits fields http.Server fixes when it starts
// (HTTPServer): serve's --max-header-bytes and --header-timeout, never a
// member of the limits file.
var startupOnly = map[string]bool{"HeadBytes": true, "HeadTimeout": true}

// durationType is the type of a Limits field written as a duration.
var durationType = reflect.TypeFor[time.Duration]()

// limitMember is the member of the limits file for the Limits field named
// field: snake case, an initialism one word (ACLEntries is acl_entries,
// SendsPerMinutePerIP sends_per_minute_per_ip).
func limitMember(field string) string {
	r := []rune(field)
	var b strings.Builder
	for i, c := range r {
		if i > 0 && unicode.IsUpper(c) && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]) || (i+1 < len(r) && unicode.IsLower(r[i+1]))) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

// limitFields are the Limits fields the limits file sets, in their order in
// Limits, each beside its member.
func limitFields() []struct{ field, member string } {
	t := reflect.TypeFor[Limits]()
	var fs []struct{ field, member string }
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() || startupOnly[f.Name] {
			continue
		}
		fs = append(fs, struct{ field, member string }{f.Name, limitMember(f.Name)})
	}
	return fs
}

// MaxLimitsFile is the most of a limits file read: four times its every
// member written with indents and its largest value (TestTheLargestLimitsFileFits).
const MaxLimitsFile = 8 << 10

// The limits file's name in the metrics.
const limitsFile = "limits"

// ParseLimits reads b as a limits file laid over base: each member it holds
// replaces its field, and every other field is base's, the startup-only ones
// among them. It returns the limits held to Limits.Check. Its errors name a
// member at most, never a value.
func ParseLimits(b []byte, base Limits) (Limits, error) {
	var members map[string]jsontext.Value
	if err := protocol.UnmarshalRequest(b, &members); err != nil {
		if m := protocol.Member(err); m != "" {
			return Limits{}, fmt.Errorf("its member %q is not of a limit's form", m)
		}
		return Limits{}, errors.New("it is not a JSON object of limits")
	}
	byMember := map[string]string{}
	for _, f := range limitFields() {
		byMember[f.member] = f.field
	}
	l := base
	v := reflect.ValueOf(&l).Elem()
	for m, raw := range members {
		field, ok := byMember[m]
		if !ok {
			return Limits{}, fmt.Errorf("its member %q is no limit", m)
		}
		fv := v.FieldByName(field)
		if fv.Type() == durationType {
			var s string
			if err := jsonv2.Unmarshal(raw, &s); err != nil {
				return Limits{}, fmt.Errorf("its member %q is not a duration as Go writes one", m)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return Limits{}, fmt.Errorf("its member %q is not a duration as Go writes one", m)
			}
			fv.SetInt(int64(d))
			continue
		}
		var n int64
		if err := jsonv2.Unmarshal(raw, &n); err != nil {
			return Limits{}, fmt.Errorf("its member %q is not a whole number", m)
		}
		fv.SetInt(n)
	}
	if err := l.Check(); err != nil {
		return Limits{}, err
	}
	return l, nil
}

// LimitsFile writes l as a limits file, every member in Limits' order, with
// indents: dromas-server limits default writes DefaultLimits so.
func LimitsFile(l Limits) []byte {
	v := reflect.ValueOf(l)
	var b bytes.Buffer
	b.WriteString("{\n")
	fs := limitFields()
	for i, f := range fs {
		fv := v.FieldByName(f.field)
		var val any = fv.Int()
		if fv.Type() == durationType {
			val = time.Duration(fv.Int()).String()
		}
		j, err := json.Marshal(val)
		if err != nil {
			panic(err) // a string or an int64 always marshals
		}
		fmt.Fprintf(&b, "  %q: %s", f.member, j)
		if i < len(fs)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// ReadLimits reads the limits file at path, to MaxLimitsFile bytes, laid over
// base (ParseLimits); it returns the bytes read beside it, for the Reloader
// that keeps it in force.
func ReadLimits(path string, base Limits) (Limits, []byte, error) {
	b, err := readBounded(path, MaxLimitsFile)
	if err != nil {
		return Limits{}, nil, err
	}
	l, err := ParseLimits(b, base)
	if err != nil {
		return Limits{}, nil, err
	}
	return l, b, nil
}

// Check refuses limits the server cannot run under, naming the limits file's
// member: a cap on a ciphertext the protocol does not allow, a budget of new
// messages past ReceiveCeiling, a number a day whose bucket holds nothing, a
// longest certificate that signs no message or that no reader takes, and a
// bound on an ACL that is off or past the protocol's.
func (l Limits) Check() error {
	for _, c := range []struct {
		member string
		n      int
	}{{"max_size", l.MaxSize}, {"account_max_size", l.AccountMaxSize}} {
		switch {
		case c.n < 0:
			return fmt.Errorf("%s: %d is not a size", c.member, c.n)
		case c.n > protocol.MaxCiphertext:
			return fmt.Errorf("%s: %d bytes is over the largest ciphertext the protocol allows, %d (PROTOCOL.md §11.10)", c.member, c.n, protocol.MaxCiphertext)
		case protocol.PaddedSize(c.n) != c.n:
			return fmt.Errorf("%s: %d bytes is not a whole number of its own padding blocks, so a message just under it would be padded past it (PROTOCOL.md §9.3): %d is the next size that is", c.member, c.n, protocol.PaddedSize(c.n))
		}
	}
	switch {
	case l.ReceiveBurst <= 0:
		return fmt.Errorf("receive_burst: %d is no budget, and no mailbox takes new messages faster than one each %v (ReceiveCeiling)", l.ReceiveBurst, ReceiveCeiling)
	case l.ReceiveRefill < ReceiveCeiling:
		return fmt.Errorf("receive_refill: %v is shorter than %v, the fastest any mailbox takes new messages (ReceiveCeiling)", l.ReceiveRefill, ReceiveCeiling)
	}
	for _, b := range []struct {
		name          string
		perDay, burst int
	}{
		{"sends", l.SendsPerDay, l.SendsBurst},
		{"renewals", l.RenewalsPerDay, l.RenewalsBurst},
		{"certificates", l.CertificatesPerDay, l.CertificatesBurst},
		{"certificate_revocations", l.CertificateRevocationsPerDay, l.CertificateRevocationsBurst},
	} {
		if b.perDay < 0 || b.burst < 0 || (b.perDay > 0 && b.burst == 0) {
			return fmt.Errorf("%s_burst: %d with %s_per_day %d: a number a day that is on takes a bucket of at least 1", b.name, b.burst, b.name, b.perDay)
		}
	}
	// In the whole seconds it is served and held to in, so a fraction above the
	// least is the least.
	if least := protocol.TTL + protocol.MaxSkew; l.MaxCertificateLifetime.Truncate(time.Second) <= least {
		return fmt.Errorf("max_certificate_lifetime: %v is not above %v, the TTL and the hour a client dates a certificate back, so a certificate it takes would sign no message", l.MaxCertificateLifetime, least)
	}
	if most := protocol.MaxCertificateLifetime; l.MaxCertificateLifetime.Truncate(time.Second) > most {
		return fmt.Errorf("max_certificate_lifetime: %v is above %v, the protocol's maximum, which every verifier holds a certificate to", l.MaxCertificateLifetime, most)
	}
	if l.ACLEntries <= 0 || l.ACLEntries > protocol.MaxACLEntries {
		return fmt.Errorf("acl_entries: %d is not from 1 to %d, the most entries the protocol lets an ACL hold (PROTOCOL.md §11.14)", l.ACLEntries, protocol.MaxACLEntries)
	}
	return nil
}

// Limits is the Reloader of s's limits from the file at path, laid over base
// (the defaults with serve's startup-only flags), whose bytes read at start
// were read: each file it reads that holds replaces the limits in force at
// once, for the next request, every bucket keeping its keys.
func (s *Server) Limits(path string, read []byte, base Limits) *Reloader {
	return &Reloader{name: limitsFile, path: path, bound: MaxLimitsFile, last: read, log: s.log, metrics: s.metrics,
		apply: func(b []byte) error {
			l, err := ParseLimits(b, base)
			if err != nil {
				return err
			}
			s.setLimits(l, nil)
			return nil
		}}
}
