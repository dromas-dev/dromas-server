package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// The operator's socket: made 0600, a stale one replaced, anything else at
// its path refused, and limits clear answered through it.
func TestTheAdminSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "dr") // a short path: a Unix socket's is at most 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	s := server.New(server.Config{Store: server.NewMemStore(time.Now), Limits: server.DefaultLimits(), Now: time.Now})

	first, err := listenAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	// A socket file left by a process that is gone: net.Listen's listener
	// unlinks its file as it closes, so this one is told not to
	// (dromas-dev/dromas-server#49).
	first.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = first.Close()
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Fatalf("no stale socket to replace: %v", err)
	}
	if err := os.WriteFile(path+".x", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAdmin(path + ".x"); err == nil {
		t.Fatal("listened over a file that is not a socket")
	}
	l, err := listenAdmin(path)
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket's mode: %v %v", fi.Mode(), err)
	}
	go func() { _ = http.Serve(l, s.AdminHandler()) }()
	t.Cleanup(func() { _ = l.Close() })

	var out bytes.Buffer
	if err := adminCall(path, http.MethodPost, "/limits/clear?ip=192.0.2.7", &out); err != nil || strings.TrimSpace(out.String()) != `{"address":"192.0.2.7","cleared":[]}` {
		t.Fatalf("limits clear: %v %q", err, out.String())
	}
	if err := adminCall(path, http.MethodPost, "/limits/clear?ip=nonsense", &out); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("limits clear of no address: %v", err)
	}
	if err := limits("clear", []string{"--socket", path}); err == nil {
		t.Fatal("limits clear with no --ip")
	}
	out.Reset()
	if err := adminCall(path, http.MethodGet, "/limits/top?limit=mailbox_rate_limited&n=5", &out); err != nil || strings.TrimSpace(out.String()) != `{"limit":"mailbox_rate_limited","keys":[]}` {
		t.Fatalf("limits top: %v %q", err, out.String())
	}
	if err := adminCall(path, http.MethodGet, "/limits/top?limit=nonsense", &out); err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "mailbox_rate_limited") {
		t.Fatalf("limits top of no limit: %v", err)
	}
	if err := limits("top", []string{"--socket", path}); err == nil {
		t.Fatal("limits top with no --limit")
	}
	if err := limits("raise", []string{"--socket", path}); err == nil {
		t.Fatal("a limits command that is not one")
	}
}

// An answer of the operator's socket past 64 KiB is copied whole, so limits
// top of many keys prints JSON. Control: a read cut at 64 KiB prints its
// first 64 KiB, no JSON, and returns no error.
func TestALargeAdminAnswerIsCopiedWhole(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "dr") // a short path: a Unix socket's is at most 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	l, err := net.Listen("unix", path) // not listenAdmin, whose umask is the process's
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]server.Indebted, 1000) // limits top's most keys, mailboxes, at about 93 bytes each
	for i := range keys {
		keys[i] = server.Indebted{Key: protocol.AddressOf(fmt.Appendf(nil, "%d", i)).String(), FullIn: 86400}
	}
	answer, err := json.Marshal(map[string]any{"limit": "mailbox_rate_limited", "keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) <= 64<<10 {
		t.Fatalf("control: the answer is %d bytes, not past 64 KiB", len(answer))
	}
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(answer) }))
	}()
	t.Cleanup(func() { _ = l.Close() })
	var out bytes.Buffer
	if err := adminCall(path, http.MethodGet, "/limits/top?limit=mailbox_rate_limited&n=1000", &out); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) || !bytes.Equal(out.Bytes(), answer) {
		t.Fatalf("limits top printed %d bytes of the %d answered, valid JSON %v", out.Len(), len(answer), json.Valid(out.Bytes()))
	}
}
