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
	reg        prometheus.Registerer
	requests   *prometheus.CounterVec
	latency    *prometheus.HistogramVec
	limits     *prometheus.CounterVec
	passes     *prometheus.CounterVec
	fetches    *prometheus.CounterVec
	lists      *prometheus.CounterVec
	store      *prometheus.CounterVec
	storeTime  *prometheus.HistogramVec
	caches     *prometheus.CounterVec
	largeRead  *prometheus.CounterVec
	cut        prometheus.Counter
	misroutes  prometheus.Counter
	conns      prometheus.Gauge
	streamAge  *prometheus.GaugeVec
	holds      prometheus.Gauge
	held       *prometheus.CounterVec
	boxes      prometheus.Gauge
	bodiesOpen prometheus.Gauge
	bodies     *prometheus.CounterVec
	versions   *prometheus.CounterVec
	reloads    *prometheus.CounterVec
}

// seconds are the latency buckets: from the 34 µs of a poll answered from
// memory to the seconds of a large body or a throttled store.
var seconds = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

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
			Help: "Calls to S3, where messages' bodies are kept in a bucket, retries included, and to Valkey, the shared store of per-sender budgets (--valkey), by service (S3 or Valkey), operation (the S3 operation: PutObject, GetObject, DeleteObjects; Valkey's: take, give, read, clear) and outcome: ok, not_found, throttled, timeout (Valkey, past its deadline) or error."}, []string{"service", "operation", "outcome"}),
		storeTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "store_call_duration_seconds",
			Help: "How long a call to S3, for messages' bodies, took, its retries included, or one to Valkey, by service (S3 or Valkey) and operation.", Buckets: seconds}, []string{"service", "operation"}),
		caches: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "cache_events_total",
			Help: "The record caches, by cache (mailboxes, accounts, missing) and event (hit, miss, eviction)."}, []string{"cache", "event"}),
		largeRead: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "large_reads_total",
			Help: "Sends past the free size, by how their wait for the one large read ended: taken, timed_out, or gone (the caller left)."}, []string{"outcome"}),
		cut: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "bodies_cut_total",
			Help: "Request bodies cut off at their deadline (body_timeout, body_min_rate)."}),
		misroutes: prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "misrouted_total",
			Help: "Calls for a mailbox outside this process's shard (--shard), answered 503: the reverse proxy in front sent them to the wrong process."}),
		conns: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "connections_open",
			Help: "Connections open on the API's listener."}),
		streamAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "stream_record_age_seconds",
			Help: "How old the last change the feed applied to each table was when it was applied, from its transaction's commit time, by table (mailboxes, revocations, messages, accounts): how far behind memory follows."}, []string{"table"}),
		holds: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "long_polls_held",
			Help: "Long polls held now (PROTOCOL.md §11.11)."}),
		held: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "long_polls_total",
			Help: "Long polls, each once by how it ended: changed (the mailbox changed, or a message in it expired), waited (its wait passed), gone (the caller left), stopped (the server stopped), replaced (a later list of the same mailbox was held in its place), standing (at a wake, its pass or its mailbox was no longer taken), refused (past max_long_polls), or refused_range (past max_long_polls_per_range)."}, []string{"outcome"}),
		boxes: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "mailboxes",
			Help: "Mailboxes in the store whose record has not expired, counted as the sweep starts and after each pass (--sweep-interval): the whole store's, the same on every process that shares it. PostgreSQL only."}),
		bodiesOpen: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "bodies_before_pass_open",
			Help: "Request bodies open now on calls that are their address's (max_bodies_before_pass)."}),
		bodies: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "bodies_before_pass_total",
			Help: "Requests with a body on calls that are their address's, by outcome: opened, refused (past max_bodies_before_pass of its IPv4 address or IPv6 /64), or refused_range (past max_bodies_before_pass_per_range of its IPv6 /48)."}, []string{"outcome"}),
		// By the policy's verdict on the request's version, never the version
		// itself, which the caller writes: Kubernetes counts requests to
		// deprecated APIs the same way, apiserver_requested_deprecated_apis
		// (from memory), labelled by what its own code defines.
		versions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "version_requests_total",
			Help: "Requests under /v1/, by what the version policy says of the version each names (PROTOCOL.md §11.17): retired (answered 410 client_version_unsupported, but on GET /v1/), sunset (a sunset covers it, not yet passed), deprecated (a deprecation covers it, no sunset does), or current."}, []string{"state"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "runtime_config_reloads_total",
			Help: "Reloads of each file of the runtime-config directory, by file (version-policy, limits) and result: ok (read, checked and in force) or failed (not read, too large or refused: what was in force stays)."}, []string{"file", "result"}),
	}
	for _, r := range []string{"ok", "failed"} {
		m.reloads.WithLabelValues(versionPolicyFile, r) // each series from the start, at 0
	}
	reg.MustRegister(m.requests, m.latency, m.limits, m.passes, m.fetches, m.lists, m.store, m.storeTime, m.caches, m.largeRead, m.cut, m.misroutes, m.conns, m.streamAge, m.holds, m.held, m.boxes, m.bodiesOpen, m.bodies, m.versions, m.reloads)
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

// version counts a request under /v1/ by its version's state (versionState).
func (m *Metrics) version(state string) {
	if m == nil {
		return
	}
	m.versions.WithLabelValues(state).Inc()
}

// reload counts a reload of the runtime file named file, ok or failed.
func (m *Metrics) reload(file string, ok bool) {
	if m == nil {
		return
	}
	result := "ok"
	if !ok {
		result = "failed"
	}
	m.reloads.WithLabelValues(file, result).Inc()
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

// holding counts a long poll (n 1) or no longer held (n -1).
func (m *Metrics) holding(n float64) {
	if m == nil {
		return
	}
	m.holds.Add(n)
}

// heldEnded counts how a long poll ended.
func (m *Metrics) heldEnded(outcome string) {
	if m == nil {
		return
	}
	m.held.WithLabelValues(outcome).Inc()
}

// bodyOpen counts a body opened on a call that is its address's (n 1), or
// closed (n -1).
func (m *Metrics) bodyOpen(n float64) {
	if m == nil {
		return
	}
	m.bodiesOpen.Add(n)
}

// body counts a body's place taken (refused "") or refused.
func (m *Metrics) body(refused string) {
	if m == nil {
		return
	}
	if refused == "" {
		refused = "opened"
	}
	m.bodies.WithLabelValues(refused).Inc()
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

// misrouted counts a call for a mailbox outside this process's shard.
func (m *Metrics) misrouted() {
	if m == nil {
		return
	}
	m.misroutes.Inc()
}

// applied records the age of a change the feed applied to table: from made,
// its transaction's commit time, to now.
func (m *Metrics) applied(table string, made time.Time, now time.Time) {
	if m == nil || made.IsZero() {
		return
	}
	m.streamAge.WithLabelValues(table).Set(max(now.Sub(made), 0).Seconds())
}

// mailboxes sets the count of the store's live mailboxes.
func (m *Metrics) mailboxes(n int64) {
	if m == nil {
		return
	}
	m.boxes.Set(float64(n))
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

// sharedCall counts and times a call to the shared store (sharedBuckets).
func (m *Metrics) sharedCall(op string, err error, took time.Duration) {
	if m == nil {
		return
	}
	m.store.WithLabelValues("Valkey", op, sharedOutcome(err)).Inc()
	m.storeTime.WithLabelValues("Valkey", op).Observe(took.Seconds())
}

// storeOutcome names how a call to S3 ended, from a fixed set: never the
// error's own code, which is AWS's to add to.
func storeOutcome(err error) string {
	var ae smithy.APIError
	switch {
	case err == nil:
		return "ok"
	case IsThrottle(err):
		return "throttled"
	case errors.As(err, &ae) && (ae.ErrorCode() == "NoSuchKey" || ae.ErrorCode() == "NotFound"):
		return "not_found"
	}
	return "error"
}
