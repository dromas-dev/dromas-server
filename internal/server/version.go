package server

import (
	"net/http"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// The states of a request's version by the policy, as the metrics count
// them (Metrics.version): retired, answered 410 version_retired; sunset, a
// sunset covers it and its date has not passed; deprecated, a deprecation
// covers it and no sunset does; current, neither.
const (
	versionCurrent    = "current"
	versionDeprecated = "deprecated"
	versionSunset     = "sunset"
	versionRetired    = "retired"
)

// policyOf is d as the server keeps and answers it: each list written, empty
// or not (protocol.ServerDocument).
func policyOf(d protocol.ServerDocument) protocol.ServerDocument {
	if d.Deprecations == nil {
		d.Deprecations = []protocol.Scheduled{}
	}
	if d.Sunsets == nil {
		d.Sunsets = []protocol.Scheduled{}
	}
	if d.Capabilities == nil {
		d.Capabilities = []protocol.Capability{}
	}
	return d
}

// versioned puts what the policy says of a request's version
// (protocol.RequestVersion of its Dromas-Version) on every answer under /v1/
// (PROTOCOL.md §11.17): Deprecation where a deprecation covers it and Sunset
// where a sunset does, each the earliest date of those that cover it, on
// whatever answer it gets. A request whose version is retired at the
// server's clock is answered 410 version_retired, with min_version where
// there is a floor, before it is routed and with nothing of it read, its pass
// included, but on the document, GET /v1/, which takes every version (§11.4
// rule 0). It counts against nothing but its address's flood budget, as a
// request no route answers does (spendRequest): it is the API's handler's,
// in front of every gate.
func (s *Server) versioned(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := protocol.RequestVersion(r.Header.Get(protocol.VersionHeader))
		d := s.policy.Load() // one policy for the whole request, whatever a reload swaps in meanwhile
		if at, ok := d.DeprecationFor(v); ok {
			w.Header().Set(protocol.DeprecationHeader, protocol.FormatDeprecation(at))
		}
		if at, ok := d.SunsetFor(v); ok {
			w.Header().Set(protocol.SunsetHeader, protocol.FormatSunset(at))
		}
		state := versionState(d, v, s.now())
		s.metrics.version(state)
		retired := state == versionRetired
		if !retired || r.URL.Path == protocol.DocumentPath {
			h.ServeHTTP(w, r)
			return
		}
		if p := s.spendRequest(r); p != nil {
			writeProblem(w, p)
			return
		}
		writeProblem(w, retiredVersion(d.MinVersion))
	})
}

// retiredVersion is the answer to a request of a retired version: 410
// version_retired, naming the floor where there is one.
func retiredVersion(floor string) *problem {
	const hint = "upgrade this client"
	if floor == "" {
		return fail(protocol.CodeVersionRetired, hint, "this server no longer takes this client's version")
	}
	return fail(protocol.CodeVersionRetired, hint, "this server no longer takes this client's version: it takes %s and later",
		value{floor, func(p *protocol.Problem) { p.MinVersion = floor }})
}

// document answers GET /v1/, the server's document: its version policy and
// the capabilities it serves, the same to every caller (PROTOCOL.md
// §11.18). It reads nothing but the policy in force.
func (s *Server) document(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, s.policy.Load())
	return nil
}

// versionState is what policy d says at now of a request of version v:
// retired first, then sunset, then deprecated (the metrics' states).
func versionState(d *protocol.ServerDocument, v protocol.Version, now time.Time) string {
	switch _, sunset := d.SunsetFor(v); {
	case d.Retired(v, now):
		return versionRetired
	case sunset:
		return versionSunset
	}
	if _, ok := d.DeprecationFor(v); ok {
		return versionDeprecated
	}
	return versionCurrent
}
