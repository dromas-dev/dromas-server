package main

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-server/internal/server"
)

// healthcheck succeeds only once the server answers its document: a
// process whose store has not loaded its memory answers 503 and fails it,
// the same process ready passes it, and a closed address fails it.
func TestTheHealthcheckPassesOnlyAReadyServer(t *testing.T) {
	t.Parallel()
	var ready atomic.Bool
	s := server.New(server.Config{Store: server.NewMemStore(time.Now), Limits: server.DefaultLimits(), Now: time.Now, Ready: ready.Load})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	url := srv.URL + "/v1/"
	if err := healthcheck([]string{"--url", url}); err == nil {
		t.Fatal("a server not ready passed the healthcheck")
	}
	ready.Store(true)
	if err := healthcheck([]string{"--url", url}); err != nil {
		t.Fatalf("a ready server failed the healthcheck: %v", err)
	}
	srv.Close()
	if err := healthcheck([]string{"--url", url, "--timeout", "500ms"}); err == nil {
		t.Fatal("a closed address passed the healthcheck")
	}
	if err := healthcheck([]string{"extra"}); err == nil {
		t.Fatal("an argument was taken")
	}
}
