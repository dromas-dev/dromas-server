package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// versionsEnv is a server whose version policy, at its clock's start N, is:
// a floor of 1.2; 1.5.1 the latest version; every version below 1.4
// deprecated from N less a day, 1.3.x from N less two days and 1.4.x from N
// less a day; 1.3.x sunset at N plus an hour and every version below 1.4 at
// N plus two hours. So 1.3.x carries the earlier of each pair, 1.2.x the
// later, 1.4.x a deprecation alone and 1.5.x neither. Each of with changes
// its Config after.
func versionsEnv(t *testing.T, l Limits, with ...func(*Config)) (*env, time.Time) {
	t.Helper()
	var start time.Time
	e := newEnv(t, l, append([]func(*Config){func(c *Config) {
		start = c.Now()
		c.Policy = protocol.ServerDocument{
			MinVersion:    "1.2",
			LatestVersion: "1.5.1",
			Deprecations: []protocol.Scheduled{
				{Below: "1.4", At: formatTime(start.Add(-24 * time.Hour))},
				{Version: "1.3", At: formatTime(start.Add(-48 * time.Hour))},
				{Version: "1.4", At: formatTime(start.Add(-24 * time.Hour))},
			},
			Sunsets: []protocol.Scheduled{
				{Version: "1.3", At: formatTime(start.Add(time.Hour))},
				{Below: "1.4", At: formatTime(start.Add(2 * time.Hour))},
			},
			MaxCertificateLifetime: DefaultLimits().maxCertificate(),
		}
		if err := c.Policy.Check(); err != nil {
			t.Fatal(err)
		}
	}}, with...)...)
	return e, start
}

// asVersion has every request from the tests' clients that names no
// version name v, so a mailbox can be made on a server with a floor.
func (e *env) asVersion(v string) {
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Header.Get(protocol.VersionHeader) == "" {
			r.Header.Set(protocol.VersionHeader, v)
		}
		next.ServeHTTP(w, r)
	})
}

// A request whose version is below the floor, or covered by a sunset whose
// date has passed at the server's clock, is answered 410 version_retired,
// with min_version where there is a floor (PROTOCOL.md §11.17). A request
// with no Dromas-Version, or one of another form, is of version 0.0.0, below
// the floor. A pre-release is below its release. Controls: a version at the
// floor, one whose sunset is a second away, and a request outside /v1/ are
// answered as without the policy.
func TestARetiredVersionIsAnswered410(t *testing.T) {
	t.Parallel()
	e, _ := versionsEnv(t, relaxed())
	nobody := "/v1/" + strings.Repeat("ab", 38) + "a"
	retired := func(r reply, what string) {
		t.Helper()
		if r.status != http.StatusGone || r.code() != protocol.CodeVersionRetired || r.problem().MinVersion != "1.2" {
			t.Errorf("%s: %d %s, want 410 version_retired with min_version 1.2", what, r.status, r.body)
		}
	}
	for _, v := range []string{"1.1.9", "1.2.0-rc.1", "0.0.0", "1.1", "v1.5.0", "1.5.0+build", "1.5", "garbage"} {
		retired(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, v), "Dromas-Version "+v)
	}
	retired(e.do("GET", nobody, nil, ""), "no Dromas-Version")
	// At the floor and past it, the call goes on: the address is unknown.
	for _, v := range []string{"1.2.0", "1.3.7", "1.5.0", "2.0.0-alpha"} {
		e.want(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, v), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	}
	// Outside /v1/, nothing is the policy's: the link page takes any version.
	e.want(e.do("GET", protocol.LinkPath+strings.Repeat("ab", 38)+"a", nil, ""), http.StatusOK, "")

	// The sunsets, by the server's clock: 1.3.x's an hour on, every version
	// below 1.4's two hours on.
	e.clock.Add(time.Hour - time.Second)
	e.want(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.3.7"), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e.clock.Add(time.Second)
	retired(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.3.7"), "1.3.7 at its sunset")
	retired(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.3.0-rc.1"), "a pre-release of 1.3 at its sunset")
	e.want(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.2.5"), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e.clock.Add(time.Hour)
	retired(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.2.5"), "1.2.5 at its sunset")
	e.want(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.4.0"), http.StatusNotFound, protocol.CodeNoSuchMailbox)
}

// A sunset is passed by the server's clock, not the mailbox's (AGENTS.md §
// Clocks): a mailbox whose clock is past its version's sunset works while
// the server's is not, and one whose clock is before it is refused once the
// server's is past. The mailbox is told version_retired, the code it reads
// (the client repo's client/errors.go).
func TestASunsetIsPassedByTheServersClock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		name string
		off  time.Duration // the mailbox's clock from the server's
	}{
		{"a mailbox whose clock is past the sunset", 49 * time.Minute}, // near as far ahead as a pass lets it be
		{"a mailbox whose clock is before the sunset", -5 * time.Minute},
	} {
		off := c.off
		e, _ := versionsEnv(t, relaxed())
		o := e.skewed(&off)
		o.Version = "1.3.7" // sunset at the server's start plus an hour
		e.clock.Add(15 * time.Minute)
		b, err := client.Init(ctx, t.TempDir(), o)
		if err != nil {
			t.Fatalf("%s: init before the sunset by the server's clock: %v", c.name, err)
		}
		if off > 0 {
			// Its clock reads past the sunset, the server's does not: it works.
			if _, err := b.Receive(ctx); err != nil {
				t.Errorf("%s: a call before the sunset by the server's clock: %v", c.name, err)
			}
			continue
		}
		e.clock.Add(45 * time.Minute) // the server's clock at the sunset; the mailbox's five minutes before it
		if _, err := b.Receive(ctx); codeOf(err) != protocol.CodeVersionRetired {
			t.Errorf("%s: a call at the sunset by the server's clock: %v, want version_retired", c.name, err)
		}
	}
}

// Every answer under /v1/ to a request whose version a deprecation covers
// carries Deprecation, as RFC 9745 writes it, and one a sunset covers
// Sunset, as RFC 8594 does, each the earliest date of those that cover it
// (PROTOCOL.md §11.17): on a 2xx, on an error, and on the 410 of a retired
// version. A version neither covers carries neither, and neither does any
// answer outside /v1/.
func TestDeprecationAndSunsetAreTheEarliestThatCover(t *testing.T) {
	t.Parallel()
	e, n := versionsEnv(t, relaxed())
	e.asVersion("1.5.0")
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	e.setMiddle(nil)
	nobody := "/v1/" + strings.Repeat("ab", 38) + "a"
	dep := func(d time.Duration) string { return protocol.FormatDeprecation(n.Add(d)) }
	sun := func(d time.Duration) string { return protocol.FormatSunset(n.Add(d)) }
	for _, c := range []struct {
		version, deprecation, sunset string
	}{
		{"1.3.7", dep(-48 * time.Hour), sun(time.Hour)},     // version 1.3's, earlier than below 1.4's
		{"1.2.0", dep(-24 * time.Hour), sun(2 * time.Hour)}, // below 1.4's alone
		{"1.4.2", dep(-24 * time.Hour), ""},                 // version 1.4's, and no sunset
		{"1.1.0", dep(-24 * time.Hour), sun(2 * time.Hour)}, // retired, below the floor
		{"1.5.0", "", ""}, // none
		{"2.0.0", "", ""}, // none
		{"1.4.0-rc.1", dep(-24 * time.Hour), sun(2 * time.Hour)}, // below 1.4, and named by version 1.4
	} {
		for _, call := range []struct {
			what, method, path string
			status             int
		}{
			{"a 2xx", "GET", b.path(""), http.StatusOK},
			{"the document", "GET", protocol.DocumentPath, http.StatusOK},
			{"an error", "GET", nobody, http.StatusNotFound},
		} {
			got := e.doWith(call.method, call.path, nil, "", protocol.VersionHeader, c.version)
			if c.version != "1.1.0" || call.path == protocol.DocumentPath {
				if got.status != call.status {
					t.Errorf("%s, %s: %d %s, want %d", c.version, call.what, got.status, got.body, call.status)
				}
			} else if got.status != http.StatusGone {
				t.Errorf("%s, %s: %d, want 410", c.version, call.what, got.status)
			}
			if d, s := got.header.Get(protocol.DeprecationHeader), got.header.Get(protocol.SunsetHeader); d != c.deprecation || s != c.sunset {
				t.Errorf("%s, %s: Deprecation %q, Sunset %q, want %q, %q", c.version, call.what, d, s, c.deprecation, c.sunset)
			}
			if vals := got.header.Values(protocol.DeprecationHeader); len(vals) > 1 {
				t.Errorf("%s, %s: Deprecation %d times", c.version, call.what, len(vals))
			}
		}
	}
	// Outside /v1/: none.
	// The link page is a browser's, and the description takes no Dromas-Version on it.
	got := e.do("GET", protocol.LinkPath+b.id.Address().String(), nil, "")
	if got.status != http.StatusOK || got.header.Get(protocol.DeprecationHeader) != "" || got.header.Get(protocol.SunsetHeader) != "" {
		t.Errorf("the link page: %d, Deprecation %q, Sunset %q", got.status, got.header.Get(protocol.DeprecationHeader), got.header.Get(protocol.SunsetHeader))
	}
}

// A request of a retired version reads nothing of itself, its pass
// included, and spends nothing but its address's flood budget (PROTOCOL.md
// §11.4 rule 0): with a pass that does not verify it is answered 410, not
// 401, and with a mailbox's checked pass on a route that takes it, it spends
// the address's budget and none of the mailbox's, its pass neither looked up
// nor checked; past the address's budget it is 429 requests, counted first.
// Controls: the same calls of a current version are a 401 and a call of the
// mailbox's.
func TestARetiredVersionReadsNothing(t *testing.T) {
	t.Parallel()
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1000, time.Hour
	l.CallBurst, l.CallRefill = 1000, time.Hour
	l.PollBurst, l.PollRefill = 1000, time.Hour
	reg := prometheus.NewRegistry()
	e, _ := versionsEnv(t, l, func(c *Config) { c.Metrics = NewMetrics(reg) })
	e.asVersion("1.5.0")
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := b.pass(1)
	e.want(e.do("GET", b.path("/messages"), nil, pass), http.StatusOK, "") // its pass checked, the mailbox live
	e.setMiddle(nil)
	h := apitest.Handler(t, e.server.Handler())
	at := func(ip, method, path, pass, version string, body string) (reply, map[string]float64, map[string]float64, *recorded) {
		t.Helper()
		limits, passes := counts(t, reg, "dromas_server_limit_requests_total"), counts(t, reg, "dromas_server_passes_total")
		rb := &recorded{r: strings.NewReader(body)}
		rb.counted = func() bool {
			return moved(limits, counts(t, reg, "dromas_server_limit_requests_total"))["decision=allowed,limit=requests,subject=ip"] == 1
		}
		req := httptest.NewRequest(method, path, rb)
		req.Host = e.name()
		req.RemoteAddr = ip + ":40000"
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		if version != "" {
			req.Header.Set(protocol.VersionHeader, version)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()},
			moved(limits, counts(t, reg, "dromas_server_limit_requests_total")), moved(passes, counts(t, reg, "dromas_server_passes_total")), rb
	}
	bad := e.passFor(e.raw().certify(1), b.id.Address(), e.name()) // a pass of the mailbox that does not verify
	body := `{"identity":"` + strings.Repeat("A", 400) + `"}`

	got, limits, passes, rb := at("10.9.0.1", "PUT", b.path("/acl"), bad, "1.1.0", body)
	if got.status != http.StatusGone || got.problem().Code != protocol.CodeVersionRetired {
		t.Errorf("a retired version with a pass that does not verify: %d %s, want 410 version_retired", got.status, got.body)
	}
	if len(passes) != 0 || rb.early {
		t.Errorf("a retired version: passes looked at %v, body read before it was counted %v", passes, rb.early)
	}
	if len(limits) != 1 || limits["decision=allowed,limit=requests,subject=ip"] != 1 {
		t.Errorf("a retired version: limits taken %v, want its address's requests alone", limits)
	}
	got, _, _, _ = at("10.9.0.2", "PUT", b.path("/acl"), bad, "1.5.0", body)
	if got.status != http.StatusUnauthorized {
		t.Errorf("control, a current version with a pass that does not verify: %d %s, want 401", got.status, got.body)
	}

	got, limits, passes, _ = at("10.9.0.3", "GET", b.path("/messages"), pass, "1.1.0", "")
	if got.status != http.StatusGone || len(passes) != 0 || len(limits) != 1 || limits["decision=allowed,limit=requests,subject=ip"] != 1 {
		t.Errorf("a retired version with the mailbox's checked pass: %d, passes %v, limits %v, want 410 on its address's requests alone", got.status, passes, limits)
	}
	got, limits, _, _ = at("10.9.0.4", "GET", b.path("/messages"), pass, "1.5.0", "")
	if got.status != http.StatusOK || limits["decision=allowed,limit=requests,subject=ip"] != 0 || limits["decision=allowed,limit=polls,subject=mailbox"] != 1 {
		t.Errorf("control, a current version with the mailbox's checked pass: %d, limits %v, want a poll of the mailbox's and no requests", got.status, limits)
	}

	// Past the address's budget: counted first, so 429 requests.
	l2 := relaxed()
	l2.RequestBurst, l2.RequestRefill = 1, time.Hour
	e2, _ := versionsEnv(t, l2)
	c2 := e2.caller()
	e2.want(c2("10.9.1.1", "GET", "/v1/"+strings.Repeat("ab", 38)+"a", nil, ""), http.StatusGone, protocol.CodeVersionRetired)
	e2.limited(c2("10.9.1.1", "GET", "/v1/"+strings.Repeat("ab", 38)+"a", nil, ""), protocol.QuotaRequests)
}

// A retired version is answered before any route is matched, a path no
// route answers among them (PROTOCOL.md §11.4 rule 0). The client repo's
// api/openapi.yaml describes no answer to a route it lacks but the router's,
// so this is checked on the handler alone.
func TestARetiredVersionIsAnsweredBeforeRouting(t *testing.T) {
	t.Parallel()
	e, _ := versionsEnv(t, relaxed())
	for _, c := range []struct {
		method, path, version string
		status                int
	}{
		{"GET", "/v1/" + strings.Repeat("ab", 38) + "a" + "/nothing/here", "1.1.0", http.StatusGone},
		{"POST", "/v1/", "1.1.0", http.StatusMethodNotAllowed}, // the document's path takes every version, whatever the method
		{"GET", "/v1/" + strings.Repeat("ab", 38) + "a" + "/nothing/here", "1.5.0", http.StatusNotFound},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set(protocol.VersionHeader, c.version)
		w := httptest.NewRecorder()
		e.server.Handler().ServeHTTP(w, req)
		if w.Code != c.status {
			t.Errorf("%s %s of %s: %d, want %d", c.method, c.path, c.version, w.Code, c.status)
		}
	}
}

// GET /v1/ is the server's document (PROTOCOL.md §11.18): the policy serve
// was given, with no capability, to any caller with no pass, whatever its
// version, a retired one among them, with Date and Cache-Control: no-store
// as every answer under /v1/; its HEAD is the same without content. A
// server given no policy answers its empty lists.
func TestTheDocumentIsThePolicy(t *testing.T) {
	t.Parallel()
	e, _ := versionsEnv(t, relaxed())
	for _, v := range []string{"1.5.0", "1.1.0", ""} {
		got := e.doWith("GET", protocol.DocumentPath, nil, "", protocol.VersionHeader, v)
		if got.status != http.StatusOK || got.header.Get("Cache-Control") != "no-store" || got.header.Get("Date") != e.clock.Now().Format(http.TimeFormat) ||
			got.header.Get("Content-Type") != "application/json" {
			t.Fatalf("version %q: %d %v %s", v, got.status, got.header, got.body)
		}
		var d protocol.ServerDocument
		if err := protocol.Unmarshal(got.body, &d); err != nil {
			t.Fatalf("version %q: %v: %s", v, err, got.body)
		}
		want := e.server.policy.Load()
		wj, _ := json.Marshal(want)
		dj, _ := json.Marshal(d)
		if string(wj) != string(dj) || d.MinVersion != "1.2" || d.LatestVersion != "1.5.1" || len(d.Deprecations) != 3 || len(d.Sunsets) != 2 || len(d.Capabilities) != 0 {
			t.Errorf("version %q: the document %s, want %s", v, dj, wj)
		}
		h := e.head(protocol.DocumentPath, "", protocol.VersionHeader, v)
		_ = h.Body.Close()
		if h.StatusCode != http.StatusOK || h.Header.Get("Cache-Control") != "no-store" || h.ContentLength > 0 && h.Header.Get("Content-Length") == "" {
			t.Errorf("HEAD, version %q: %d %v", v, h.StatusCode, h.Header)
		}
	}
	// No policy: no floor, no latest version, and every list written.
	bare := newEnv(t, relaxed())
	got := bare.do("GET", protocol.DocumentPath, nil, "")
	if got.status != http.StatusOK || strings.TrimSpace(string(got.body)) != `{"deprecations":[],"sunsets":[],"capabilities":[]}` {
		t.Errorf("no policy: %d %s", got.status, got.body)
	}
	if got.header.Get(protocol.DeprecationHeader) != "" || got.header.Get(protocol.SunsetHeader) != "" {
		t.Errorf("no policy: %v", got.header)
	}
}

// Each request under /v1/ is counted once by what the policy says of its
// version, never by the version itself (bounded cardinality): current,
// deprecated, sunset (not yet passed) or retired, the last the 410s and a
// retired version's read of the document. A request outside /v1/ is counted
// by none.
func TestTheVersionMetricCountsEachState(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	e, _ := versionsEnv(t, relaxed(), func(c *Config) { c.Metrics = NewMetrics(reg) })
	nobody := "/v1/" + strings.Repeat("ab", 38) + "a"
	for _, c := range []struct {
		version, path, state string
	}{
		{"1.5.0", nobody, "current"},
		{"2.0.0", protocol.DocumentPath, "current"},
		{"1.4.2", nobody, "deprecated"},
		{"1.3.7", nobody, "sunset"},
		{"1.2.0", nobody, "sunset"},
		{"1.1.0", nobody, "retired"},
		{"", nobody, "retired"},
		{"1.1.0", protocol.DocumentPath, "retired"},
		{"", protocol.LinkPath + strings.Repeat("ab", 38) + "a", ""}, // outside /v1/; the link page takes no Dromas-Version
	} {
		before := counts(t, reg, "dromas_server_version_requests_total")
		if c.version == "" {
			e.do("GET", c.path, nil, "")
		} else {
			e.doWith("GET", c.path, nil, "", protocol.VersionHeader, c.version)
		}
		d := moved(before, counts(t, reg, "dromas_server_version_requests_total"))
		if c.state == "" {
			if len(d) != 0 {
				t.Errorf("%s %s: counted %v, want nothing", c.version, c.path, d)
			}
			continue
		}
		if len(d) != 1 || d["state="+c.state] != 1 {
			t.Errorf("%s %s: counted %v, want state=%s once", c.version, c.path, d, c.state)
		}
	}
	e.clock.Add(time.Hour) // 1.3's sunset passes
	before := counts(t, reg, "dromas_server_version_requests_total")
	e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.3.7")
	if d := moved(before, counts(t, reg, "dromas_server_version_requests_total")); d["state=retired"] != 1 {
		t.Errorf("1.3.7 past its sunset: %v, want retired", d)
	}
	for k := range counts(t, reg, "dromas_server_version_requests_total") {
		if strings.Contains(k, "1.") || strings.Contains(k, "2.0") {
			t.Errorf("a series names a version: %s", k)
		}
	}
}
