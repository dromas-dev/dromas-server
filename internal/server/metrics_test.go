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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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

// metered is a test server whose metrics are m, on a registry of their own.
func metered(t *testing.T, l Limits) (*env, *Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	return newEnv(t, l, func(c *Config) { c.Metrics = m }), m, reg
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
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	id := e.sent(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)))
	e.want(e.do("GET", to+"/messages", nil, e.pass(b)), http.StatusOK, "")
	e.want(e.do("GET", to+"/messages", nil, e.pass(b)), http.StatusTooManyRequests, protocol.CodeRateLimited)
	for range 2 {
		e.want(e.do("GET", to+"/messages/"+id, nil, e.pass(b)), http.StatusOK, "")
	}
	e.caller()("192.0.2.1", "GET", to+"/nothing/here", nil, "")
	e.want(e.do("GET", to+"/messages", nil, "dromas-pass nonsense"), http.StatusUnauthorized, protocol.CodeUnauthorized)

	for _, c := range []struct {
		what string
		got  prometheus.Collector
		want float64
	}{
		{"sends stored", m.requests.WithLabelValues("POST /v1/{addr}/messages", "201", ""), 1},
		{"a poll refused", m.requests.WithLabelValues("GET /v1/{addr}/messages", "429", "rate_limited"), 1},
		{"a route no route matches", m.requests.WithLabelValues("unmatched", "404", ""), 1},
		{"polls allowed", m.limits.WithLabelValues("polls", "box", "allowed"), 1},
		{"polls denied", m.limits.WithLabelValues("polls", "box", "denied"), 1},
		{"new mail taken", m.limits.WithLabelValues("mailbox_busy", "box", "allowed"), 1},
		{"polls", m.lists.WithLabelValues("poll"), 1},
		{"first fetches", m.fetches.WithLabelValues("first"), 1},
		{"repeat fetches", m.fetches.WithLabelValues("repeat"), 1},
		{"a value that is no pass", m.passes.WithLabelValues("refused", string(protocol.CodeUnauthorized)), 1},
	} {
		if got := testutil.ToFloat64(c.got); got != c.want {
			t.Errorf("%s: %v, want %v", c.what, got, c.want)
		}
	}
	if got := testutil.ToFloat64(m.passes.WithLabelValues("checked", "")); got < 2 {
		t.Errorf("passes checked: %v, want at least the two boxes'", got)
	}
	if got := testutil.ToFloat64(m.passes.WithLabelValues("remembered", "")); got < 1 {
		t.Errorf("passes remembered: %v", got)
	}
	if got := testutil.CollectAndCount(m.latency); got == 0 {
		t.Error("no latency observed")
	}
}

// No label of the metrics is a value a caller chose: a scrape after mail
// between two boxes, a refusal and a request that matches no route carries
// none of the boxes' addresses, the message's id, the caller's IP or a path
// as it was sent.
func TestMetricsCarryNoCallerValue(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.MissesPerMinute, l.RequestBurst, l.RequestRefill = 1, 2, time.Minute
	e, _, reg := metered(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	id := e.sent(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)))
	e.want(e.do("GET", to+"/messages/"+id, nil, e.pass(b)), http.StatusOK, "")
	call := e.caller()
	for range 3 {
		call("203.0.113.77", "GET", "/v1/"+strings.Repeat("e", 64), nil, "")
		call("203.0.113.77", "GET", "/made/up/path", nil, "")
	}
	w := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := w.Body.String()
	if !strings.Contains(text, `dromasd_limit_requests_total{decision="denied",limit="requests",subject="ip"}`) {
		t.Fatalf("the scrape lacks the flood budget's refusals, so it shows nothing of these calls:\n%s", text)
	}
	for _, v := range []string{a.Address().String(), b.Address().String(), id, strings.Repeat("e", 64), "203.0.113.77", "127.0.0.1", "/made/up", a.Address().String()[:16]} {
		if strings.Contains(text, v) {
			t.Errorf("the metrics carry %q", v)
		}
	}
}

// Every call to AWS is counted by its service, operation and outcome, from a
// fixed set, and timed with its retries (Metrics.InstrumentAWS).
func TestMetricsCountTheStoresCalls(t *testing.T) {
	t.Parallel()
	refuse := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if refuse {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"the condition failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	m := NewMetrics(prometheus.NewRegistry())
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""), BaseEndpoint: aws.String(srv.URL), RetryMaxAttempts: 1}
	m.InstrumentAWS(&cfg)
	db := dynamodb.NewFromConfig(cfg)
	put := func() error {
		_, err := db.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String("t"), Item: map[string]dtypes.AttributeValue{"pk": &dtypes.AttributeValueMemberS{Value: "x"}}})
		return err
	}
	if err := put(); err == nil {
		t.Fatal("the refused put succeeded")
	}
	refuse = false
	if err := put(); err != nil {
		t.Fatal(err)
	}
	for outcome, want := range map[string]float64{"conditional": 1, "ok": 1, "error": 0} {
		if got := testutil.ToFloat64(m.store.WithLabelValues("DynamoDB", "PutItem", outcome)); got != want {
			t.Errorf("PutItem %s: %v, want %v", outcome, got, want)
		}
	}
	if got := testutil.CollectAndCount(m.storeTime); got != 1 {
		t.Errorf("the calls' times: %d series, want 1", got)
	}
}

// collectionsWant is the exposition of dromasd_item_collection_estimate_bytes
// after one observation of gb, DynamoDB's GB.
func collectionsWant(gb float64) string {
	const name = "dromasd_item_collection_estimate_bytes"
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP %s After each message written, the upper bound of DynamoDB's estimate of its box's item collection, the box's items and their LSI entries, at 2^30 bytes a GB: past 10 GB, the box takes no more mail.\n# TYPE %s histogram\n", name, name)
	for _, le := range gigabytes {
		n := 0
		if gb*(1<<30) <= le {
			n = 1
		}
		fmt.Fprintf(&b, "%s_bucket{le=\"%g\"} %d\n", name, le, n)
	}
	fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} 1\n%s_sum %g\n%s_count 1\n", name, name, gb*(1<<30), name)
	return b.String()
}

// A message write asks DynamoDB for the size of its box's item collection,
// and the upper bound of the estimate is observed, in GB: AWS's advice for a
// table with an LSI, whose item collections are capped at 10 GB. The fake's
// answer is made up, so the test holds the conversion at 2^30 bytes a GB,
// not AWS's unit, which AWS does not state (gigabytes).
func TestMetricsObserveTheItemCollectionAMessageWriteGrew(t *testing.T) {
	t.Parallel()
	f := newFakeAWS()
	var asked atomic.Bool
	f.dynamo = func(op string, _ int, body []byte) answer {
		if op != "PutItem" {
			return answer{status: http.StatusOK, body: "{}"}
		}
		asked.Store(strings.Contains(string(body), `"ReturnItemCollectionMetrics":"SIZE"`))
		return answer{status: http.StatusOK, body: `{"ItemCollectionMetrics":{"ItemCollectionKey":{"box":{"B":"BA=="}},"SizeEstimateRangeGB":[8.0,9.0]}}`}
	}
	s := fakeStore(t, f)
	m := NewMetrics(prometheus.NewRegistry())
	s.dynamo().metrics = m
	now := time.Now().UTC().Truncate(time.Millisecond)
	h := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	if _, err := s.PutMessage(t.Context(), protocol.Address{4}, h, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !asked.Load() {
		t.Error("the message write did not ask for its item collection's size")
	}
	if err := testutil.CollectAndCompare(m.collections, strings.NewReader(collectionsWant(9)), "dromasd_item_collection_estimate_bytes"); err != nil {
		t.Error(err)
	}
}
