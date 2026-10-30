package server

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The server's routes are the API description's, no more and no fewer: a
// route added on one side and not the other fails here, and every answer
// on a route is held to the description by apitest in every other test.
func TestTheRoutesAreTheDescriptions(t *testing.T) {
	t.Parallel()
	want, err := apitest.Routes()
	if err != nil {
		t.Fatal(err)
	}
	got := []string{linkRoute}
	for _, r := range (&Server{}).routes() {
		// {$} anchors a pattern to its path (http.ServeMux): the
		// description's path is the pattern's without it.
		got = append(got, strings.TrimSuffix(r.pattern, "{$}"))
	}
	// A pattern of GET matches HEAD too (http.ServeMux), so each is a route
	// of both.
	for _, p := range got {
		if path, ok := strings.CutPrefix(p, http.MethodGet+" "); ok {
			got = append(got, http.MethodHead+" "+path)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the server's routes are\n  %v\nthe description's\n  %v", got, want)
	}
}

// The read of a mailbox is GET /v1/<address>, and the read of its identity it
// replaced is no route of this server: GET …/identity gets the router's plain
// 404. GET …/revocations is a route, the read of what the server keeps of an
// address (TestTheRevocationsOfAnyAddressAreServed).
func TestTheReadTheMailboxReplacedIsGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t, relaxed())
	b := e.mailbox()
	resp, err := http.Get(e.srv.URL + "/v1/" + b.Address().String() + "/identity")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") == protocol.ProblemContentType {
		t.Errorf("GET …/identity: %d %s, want the router's plain 404", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	e.want(e.do(http.MethodGet, "/v1/"+b.Address().String(), nil, ""), http.StatusOK, "")
}
