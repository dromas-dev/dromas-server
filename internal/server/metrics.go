package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Metrics count what this server does and refuses, for its operator
// (dromas-dev/dromas-server#59; ARCHITECTURE.md § Metrics), as
// Prometheus counts a service: its requests, errors and latency, every
// failure beside its attempts. They are served on a listener of their own
// (dromas-server serve --metrics-listen), never the API's.
//
// No label is a value a caller chooses: no address, IP, mailbox, message id,
// cursor or path as sent, each of which would be a series per caller and is
// what the logs leave out. Every label is from a set this code defines: a
// route is the router's pattern, a code the protocol's, a limit the name a
// refusal gives it. A nil *Metrics counts nothing.
type Metrics struct {
	reg         prometheus.Registerer
	requests    *prometheus.CounterVec
	latency     *prometheus.HistogramVec
	limits      *prometheus.CounterVec
	passes      *prometheus.CounterVec
	fetches     *prometheus.CounterVec
	lists       *prometheus.CounterVec
	store       *prometheus.CounterVec
	storeTime   *prometheus.HistogramVec
	caches      *prometheus.CounterVec
	largeRead   *prometheus.CounterVec
	cut         prometheus.Counter
	conns       prometheus.Gauge
	streamAge   *prometheus.GaugeVec
	collections prometheus.Histogram
	holds       prometheus.Gauge
	held        *prometheus.CounterVec
}

// seconds are the latency buckets: from the 34 µs of a poll answered from
// memory to the seconds of a large body or a throttled store.
var seconds = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// gigabytes are the item collection's buckets, in bytes, as Prometheus
// names a size, from the GB DynamoDB estimates in and caps an item
// collection at, 10, each taken as 2^30 bytes. AWS does not say whether its
// GB is 10^9 or 2^30 bytes (ItemCollectionMetrics: "in gigabytes"), and 2^30
// is the safe side: the bytes observed are never fewer than the estimate's,
// and 7.4% more if a GB is 10^9. Each bucket is a whole number of AWS's GB
// whichever it means, so the one at 8 is the alert AWS advises, and the one
// at 10 the cap.
var gigabytes = []float64{1 << 30, 2 << 30, 4 << 30, 6 << 30, 8 << 30, 9 << 30, 10 << 30}

// NewMetrics makes the server's metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	const ns = "dromas_server"
	m := &Metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "requests_total",
			Help: "Requests answered, by route (the router's pattern; unmatched for none), status and code (the problem's, empty for none); 499 for one whose caller left before its answer, which is not sent."}, []string{"route", "status", "code"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "request_duration_seconds",
			Help: "How long a request took to answer, by route.", Buckets: seconds}, []string{"route"}),
		limits: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "limit_requests_total",
			Help: "Each take of a limit, by its name (a rate_limited's quota_id, or the code of its own), whom it counts (mailbox or ip) and the decision (allowed or denied)."}, []string{"limit", "subject", "decision"}),
		passes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "passes_total",
			Help: "Passes, by outcome: remembered (taken from memory), checked (verified), refused (with its code)."}, []string{"outcome", "code"}),
		fetches: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "fetches_total",
			Help: "Messages served, by kind: first, or a repeat of one fetched before."}, []string{"kind"}),
		lists: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "lists_total",
			Help: "Lists taken, by kind: a poll, or a page after the first of a drain."}, []string{"kind"}),
		store: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "store_calls_total",
			Help: "Calls to AWS, retries included, by service, operation and outcome: ok, conditional (a condition or a transaction refused), not_found, throttled or error."}, []string{"service", "operation", "outcome"}),
		storeTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "store_call_duration_seconds",
			Help: "How long a call to AWS took, its retries included, by service and operation.", Buckets: seconds}, []string{"service", "operation"}),
		caches: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "cache_events_total",
			Help: "The record caches, by cache (mailboxes, accounts, missing) and event (hit, miss, eviction)."}, []string{"cache", "event"}),
		largeRead: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "large_reads_total",
			Help: "Sends past the free size, by how their wait for the one large read ended: taken, timed_out, or gone (the caller left)."}, []string{"outcome"}),
		cut: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "bodies_cut_total",
			Help: "Request bodies cut off at their deadline (--body-timeout, --body-min-rate)."}),
		conns: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "connections_open",
			Help: "Connections open on the API's listener."}),
		streamAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "stream_record_age_seconds",
			Help: "How old the last record applied from each table's stream was when it was applied: how far behind memory follows."}, []string{"table"}),
		collections: prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: "item_collection_estimate_bytes",
			Help: "After each message written, the upper bound of DynamoDB's estimate of its mailbox's item collection, the mailbox's items and their LSI entries, at 2^30 bytes a GB: past 10 GB, the mailbox takes no more messages.", Buckets: gigabytes}),
		holds: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "lists_held",
			Help: "Lists held for a change now (PROTOCOL.md §11.11)."}),
		held: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "held_lists_total",
			Help: "Held lists, each once by how it ended: changed (the mailbox changed, or a message in it expired), waited (its wait passed), gone (the caller left), stopped (the server stopped), or refused (past --max-held-lists)."}, []string{"outcome"}),
	}
	reg.MustRegister(m.requests, m.latency, m.limits, m.passes, m.fetches, m.lists, m.store, m.storeTime, m.caches, m.largeRead, m.cut, m.conns, m.streamAge, m.collections, m.holds, m.held)
	return m
}

// watch registers what m reads of s at each scrape: how many keys each of
// its limits holds.
func (m *Metrics) watch(s *Server) {
	if m == nil {
		return
	}
	for _, sets := range s.limitsByName() {
		for _, bs := range sets {
			bs.m = m
		}
	}
	// A second server on one registry, in a test, counts on the first's keys.
	_ = m.reg.Register(keyCounts{s: s, desc: prometheus.NewDesc("dromas_server_limit_keys",
		"Keys each limit holds now: the mailboxes or addresses whose bucket is not full, by the limit's name.", []string{"limit"}, nil)})
}

// keyCounts reports how many keys each of a server's limits holds, read at
// each scrape.
type keyCounts struct {
	s    *Server
	desc *prometheus.Desc
}

func (k keyCounts) Describe(ch chan<- *prometheus.Desc) { ch <- k.desc }

func (k keyCounts) Collect(ch chan<- prometheus.Metric) {
	for name, sets := range k.s.limitsByName() {
		n := 0
		for _, bs := range sets {
			bs.mu.Lock()
			n += len(bs.full)
			bs.mu.Unlock()
		}
		ch <- prometheus.MustNewConstMetric(k.desc, prometheus.GaugeValue, float64(n), name)
	}
}

// answered counts a request answered on route with status, and code, the
// problem's or none, taking took.
func (m *Metrics) answered(route string, status int, code protocol.Code, took time.Duration) {
	if m == nil {
		return
	}
	if route == "" {
		route = "unmatched"
	}
	m.requests.WithLabelValues(route, strconv.Itoa(status), string(code)).Inc()
	m.latency.WithLabelValues(route).Observe(took.Seconds())
}

// limit counts one take of the limit named name, allowed or not.
func (m *Metrics) limit(name string, ok bool) {
	if m == nil {
		return
	}
	decision := "allowed"
	if !ok {
		decision = "denied"
	}
	m.limits.WithLabelValues(name, string(subjectOf(name)), decision).Inc()
}

// subjectOf is whom the limit named name counts: a quota's subject, and the
// mailbox for a limit with a code of its own.
func subjectOf(name string) protocol.Subject {
	if s := protocol.Quota(name).Subject(); s != "" {
		return s
	}
	return protocol.SubjectMailbox
}

// pass counts a pass taken from memory (remembered), or checked, with err
// its refusal.
func (m *Metrics) pass(remembered bool, err error) {
	if m == nil {
		return
	}
	var p *problem
	switch {
	case remembered:
		m.passes.WithLabelValues("remembered", "").Inc()
	case err == nil:
		m.passes.WithLabelValues("checked", "").Inc()
	case errors.As(err, &p):
		m.passes.WithLabelValues("refused", string(p.code)).Inc()
	default:
		m.passes.WithLabelValues("refused", "").Inc()
	}
}

// fetch counts a message served, a repeat when again.
func (m *Metrics) fetch(again bool) {
	if m == nil {
		return
	}
	kind := "first"
	if again {
		kind = "repeat"
	}
	m.fetches.WithLabelValues(kind).Inc()
}

// list counts a list taken, a page after the first when continues.
func (m *Metrics) list(continues bool) {
	if m == nil {
		return
	}
	kind := "poll"
	if continues {
		kind = "page"
	}
	m.lists.WithLabelValues(kind).Inc()
}

// holding counts a list held (n 1) or no longer held (n -1).
func (m *Metrics) holding(n float64) {
	if m == nil {
		return
	}
	m.holds.Add(n)
}

// heldEnded counts how a held list ended.
func (m *Metrics) heldEnded(outcome string) {
	if m == nil {
		return
	}
	m.held.WithLabelValues(outcome).Inc()
}

// cacheEvent counts a hit, a miss or an eviction of the cache named name.
func (m *Metrics) cacheEvent(name, event string) {
	if m == nil {
		return
	}
	m.caches.WithLabelValues(name, event).Inc()
}

// large counts how a send's wait for the one large read ended.
func (m *Metrics) large(outcome string) {
	if m == nil {
		return
	}
	m.largeRead.WithLabelValues(outcome).Inc()
}

// bodyCut counts a request body cut off at its deadline.
func (m *Metrics) bodyCut() {
	if m == nil {
		return
	}
	m.cut.Inc()
}

// applied records the age of a record applied from table's stream.
func (m *Metrics) applied(table string, made time.Time, now time.Time) {
	if m == nil || made.IsZero() {
		return
	}
	m.streamAge.WithLabelValues(table).Set(max(now.Sub(made), 0).Seconds())
}

// collection records the upper bound of DynamoDB's estimate of the item
// collection a message write grew, given in GB (ReturnItemCollectionMetrics):
// AWS's advice for a table with an LSI, whose item collections are capped.
func (m *Metrics) collection(gb float64) {
	if m == nil {
		return
	}
	m.collections.Observe(gb * (1 << 30))
}

// ConnState counts the API listener's open connections, as http.Server's
// ConnState.
func (m *Metrics) ConnState(_ net.Conn, st http.ConnState) {
	if m == nil {
		return
	}
	switch st {
	case http.StateNew:
		m.conns.Inc()
	case http.StateHijacked, http.StateClosed:
		m.conns.Dec()
	}
}

// InstrumentAWS counts and times every call the clients made from cfg make,
// each with its retries, by service, operation and outcome.
func (m *Metrics) InstrumentAWS(cfg *aws.Config) {
	if m == nil {
		return
	}
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("DromasdMetrics", func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
			start := time.Now()
			out, md, err := next.HandleInitialize(ctx, in)
			service, op := awsmiddleware.GetServiceID(ctx), awsmiddleware.GetOperationName(ctx)
			m.store.WithLabelValues(service, op, storeOutcome(err)).Inc()
			m.storeTime.WithLabelValues(service, op).Observe(time.Since(start).Seconds())
			return out, md, err
		}), middleware.After)
	})
}

// storeOutcome names how a call to AWS ended, from a fixed set: never the
// error's own code, which is AWS's to add to.
func storeOutcome(err error) string {
	var ae smithy.APIError
	switch {
	case err == nil:
		return "ok"
	case IsThrottle(err):
		return "throttled"
	case errors.As(err, &ae) && (ae.ErrorCode() == "ConditionalCheckFailedException" || ae.ErrorCode() == "TransactionCanceledException"):
		return "conditional"
	case errors.As(err, &ae) && (ae.ErrorCode() == "NoSuchKey" || ae.ErrorCode() == "NotFound" || ae.ErrorCode() == "ResourceNotFoundException"):
		return "not_found"
	}
	return "error"
}
