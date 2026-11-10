package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dromas-dev/dromas-client/protocol"
)

// sent is the id of the message a send's answer r stored.
func (e *env) sent(r reply) string {
	e.t.Helper()
	e.want(r, http.StatusCreated, "")
	var rc protocol.Receipt
	if err := json.Unmarshal(r.body, &rc); err != nil {
		e.t.Fatal(err)
	}
	return rc.ID
}

// The metrics count what the server does and refuses (dromas-dev/dromas-server#59):
// each request by its route, status and code; each take of a limit by its
// name, whom it counts and whether it was allowed; passes, lists and
// fetches by kind; and how many keys each limit holds.
func TestMetricsCountWhatTheServerDoes(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.PollBurst, l.PollRefill = 1, time.Minute
	l.ReceiveBurst, l.ReceiveRefill = 10, time.Minute
	e, m, _ := metered(t, l)
	a, b := e.mailbox(), e.mailbox()
	to := "/v1/" + b.Address().String()
	id := e.sent(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)))
	e.want(e.do("GET", to+"/messages", nil, e.pass(b)), http.StatusOK, "")
	e.want(e.do("GET", to+"/messages", nil, e.pass(b)), http.StatusTooManyRequests, protocol.CodeRateLimited)
	for range 2 {
		e.want(e.do("GET", to+"/messages/"+id, nil, e.pass(b)), http.StatusOK, "")
	}
	e.caller()("192.0.2.1", "GET", to+"/nothing/here", nil, "")
	e.want(e.do("GET", to+"/messages", nil, "dromas-pass nonsense"), http.StatusUnauthorized, protocol.CodeInvalidPass)

	for _, c := range []struct {
		what string
		got  prometheus.Collector
		want float64
	}{
		{"sends stored", m.requests.WithLabelValues("POST /v1/{address}/messages", "201", ""), 1},
		{"a poll refused", m.requests.WithLabelValues("GET /v1/{address}/messages", "429", "rate_limited"), 1},
		{"a route no route matches", m.requests.WithLabelValues("unmatched", "404", ""), 1},
		{"polls allowed", m.limits.WithLabelValues("polls", "mailbox", "allowed"), 1},
		{"polls denied", m.limits.WithLabelValues("polls", "mailbox", "denied"), 1},
		{"new messages taken", m.limits.WithLabelValues("mailbox_rate_limited", "mailbox", "allowed"), 1},
		{"polls", m.lists.WithLabelValues("poll"), 1},
		{"first fetches", m.fetches.WithLabelValues("first"), 1},
		{"repeat fetches", m.fetches.WithLabelValues("repeat"), 1},
		{"a value that is no pass", m.passes.WithLabelValues("refused", string(protocol.CodeInvalidPass)), 1},
	} {
		if got := testutil.ToFloat64(c.got); got != c.want {
			t.Errorf("%s: %v, want %v", c.what, got, c.want)
		}
	}
	if got := testutil.ToFloat64(m.passes.WithLabelValues("checked", "")); got < 2 {
		t.Errorf("passes checked: %v, want at least the two mailboxes'", got)
	}
	if got := testutil.ToFloat64(m.passes.WithLabelValues("remembered", "")); got < 1 {
		t.Errorf("passes remembered: %v", got)
	}
	if got := testutil.CollectAndCount(m.latency); got == 0 {
		t.Error("no latency observed")
	}
}

// No label of the metrics is a value a caller chose: a scrape after messages
// between two mailboxes, a refusal and a request that matches no route carries
// none of the mailboxes' addresses, the message's id, the caller's IP or a path
// as it was sent.
func TestMetricsCarryNoCallerValue(t *testing.T) {
	t.Parallel()
	l := relaxed()
	// Enough calls with no checked pass for two mailboxes' registrations and
	// their first reads of the server's document, from the test's address.
	l.MissesPerMinute, l.RequestBurst, l.RequestRefill = 1, 6, time.Minute
	e, _, reg := metered(t, l)
	a, b := e.mailbox(), e.mailbox()
	to := "/v1/" + b.Address().String()
	id := e.sent(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)))
	e.want(e.do("GET", to+"/messages/"+id, nil, e.pass(b)), http.StatusOK, "")
	call := e.caller()
	for range 4 { // past the address's flood budget
		call("203.0.113.77", "GET", "/v1/"+"d_"+strings.Repeat("e", 64), nil, "")
		call("203.0.113.77", "GET", "/made/up/path", nil, "")
	}
	w := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := w.Body.String()
	if !strings.Contains(text, `dromas_server_limit_requests_total{decision="denied",limit="requests",subject="ip"}`) {
		t.Fatalf("the scrape lacks the flood budget's refusals, so it shows nothing of these calls:\n%s", text)
	}
	for _, v := range []string{a.Address().String(), b.Address().String(), id, "d_" + strings.Repeat("e", 64), "203.0.113.77", "127.0.0.1", "/made/up", a.Address().String()[:16]} {
		if strings.Contains(text, v) {
			t.Errorf("the metrics carry %q", v)
		}
	}
}

// Every call to AWS is counted by its service, operation and outcome, from a
// fixed set, and timed with its retries (Metrics.InstrumentAWS): S3's, where
// bodies are kept, a body read, one missing and one throttled.
func TestMetricsCountTheStoresCalls(t *testing.T) {
	t.Parallel()
	var answer atomic.Int32 // the status S3 answers
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		status := int(answer.Load())
		code := map[int]string{http.StatusNotFound: "NoSuchKey", http.StatusServiceUnavailable: "SlowDown"}[status]
		if code == "" {
			_, _ = w.Write([]byte("abc"))
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}))
	t.Cleanup(srv.Close)
	m := NewMetrics(prometheus.NewRegistry())
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""), BaseEndpoint: aws.String(srv.URL), RetryMaxAttempts: 1}
	m.InstrumentAWS(&cfg)
	b := s3Bodies{newS3(cfg, func(o *s3.Options) { o.UsePathStyle = true }), "bodies"}
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusServiceUnavailable} {
		answer.Store(int32(status))
		_, err := b.Get(context.Background(), "k", 0, 3)
		if (err == nil) != (status == http.StatusOK) {
			t.Fatalf("a read answered %d: %v", status, err)
		}
	}
	for outcome, want := range map[string]float64{"ok": 1, "not_found": 1, "throttled": 1, "error": 0} {
		if got := testutil.ToFloat64(m.store.WithLabelValues("S3", "GetObject", outcome)); got != want {
			t.Errorf("GetObject %s: %v, want %v", outcome, got, want)
		}
	}
	if got := testutil.CollectAndCount(m.storeTime); got != 1 {
		t.Errorf("the calls' times: %d series, want 1", got)
	}
}
