package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Every error body is RFC 9457 Problem Details with the extension members
// code and hint, and one member for each value the error carries
// (PROTOCOL.md §11.3). Every value the detail names is one of those members
// (AEP-193): fail takes the detail's values only as [value]s, each of which
// sets its member, so a detail cannot carry a value its body does not. The
// words, detail and hint, are for a person reading the body: a client needs
// nothing from them, and shows none of them.

// problem is an error to answer with.
type problem struct {
	code       protocol.Code
	detail     string
	hint       string
	retryAfter time.Duration // 429 and 503
	values     []value
	record     *protocol.Revocations // revoked: the record held of the address (revokedWith)
	quota      protocol.Quota        // rate_limited: the limit, and from it whom it was counted against
}

func (p *problem) Error() string { return string(p.code) + ": " + p.detail }

// value is a value an error carries: formatted into its detail as any
// operand is, and set as its own member of the body.
type value struct {
	v   any
	set func(*protocol.Problem)
}

func (v value) Format(f fmt.State, verb rune) { _, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), v.v) }

func u64(n uint64) *uint64 { return &n }

// limitValue is the limit hit: bytes, entries, or a day's count.
func limitValue(n int) value {
	return value{n, func(p *protocol.Problem) { p.Limit = u64(uint64(max(n, 0))) }}
}

// countValue is how many messages a full mailbox holds, as its list counts them.
func countValue(n int) value {
	return value{n, func(p *protocol.Problem) { p.Count = u64(uint64(max(n, 0))) }}
}

func prekeySerialValue(v uint64) value {
	return value{v, func(p *protocol.Problem) { p.PrekeySerial = u64(v) }}
}

func certificateSerialValue(v uint64) value {
	return value{v, func(p *protocol.Problem) { p.CertificateSerial = u64(v) }}
}

// maxLifetimeValue is the longest certificate the server takes, in seconds.
func maxLifetimeValue(v uint64) value {
	return value{v, func(p *protocol.Problem) { p.MaxCertificateLifetime = u64(v) }}
}

func throughValue(v uint64) value {
	return value{v, func(p *protocol.Problem) { p.Through = u64(v) }}
}

func keyTypesValue(ts []string) value {
	return value{strings.Join(ts, ", "), func(p *protocol.Problem) { p.KeyTypes = slices.Clone(ts) }}
}

func keyTypeValue(t string) value {
	return value{t, func(p *protocol.Problem) { p.KeyType = t }}
}

func memberValue(name string) value {
	return value{name, func(p *protocol.Problem) { p.Member = name }}
}

func fail(code protocol.Code, hint, format string, values ...value) *problem {
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
	}
	return &problem{code: code, hint: hint, detail: fmt.Sprintf(format, args...), values: values}
}

// failErr is a refusal whose detail is err's words: one of the protocol's
// own errors, whose words are fixed. A member it names, unknown or holding a
// value its call does not take, is a value, and set as one.
func failErr(code protocol.Code, hint string, err error) *problem {
	p := &problem{code: code, hint: hint, detail: err.Error()}
	if name := protocol.Member(err); name != "" {
		p.values = append(p.values, memberValue(name))
	}
	return p
}

func writeProblem(w http.ResponseWriter, p *problem) {
	status := p.code.Status()
	body := protocol.Problem{
		Type:   p.code.TypeURI(),
		Title:  p.code.Title(),
		Status: int64(status),
		Detail: p.detail,
		Code:   p.code,
		Hint:   p.hint,
	}
	for _, v := range p.values {
		v.set(&body)
	}
	body.Record = p.record
	if p.quota != "" {
		body.QuotaID, body.Subject = p.quota, p.quota.Subject()
	}
	noteCode(w, p.code)
	h := w.Header()
	h.Set("Content-Type", protocol.ProblemContentType)
	if status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", protocol.PassScheme) // RFC 9110 §11.6.1
	}
	if p.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(retrySeconds(p.retryAfter)))
	}
	writeBody(w, status, body)
}

// writeJSON answers with compact JSON, no HTML escaping.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	writeBody(w, status, v)
}

func writeBody(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

// jsonBytes is v as writeBody writes it: compact JSON, no HTML escaping, and
// a line feed after it. A list's ETag is the hash of these bytes.
func jsonBytes(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
