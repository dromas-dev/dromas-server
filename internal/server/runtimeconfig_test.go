package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dromas-dev/dromas-client/protocol"
)

// policyText is a version policy file naming latest as its latest version,
// with a floor of floor.
func policyText(floor, latest string) string {
	return `{"min_version":"` + floor + `","latest_version":"` + latest + `","deprecations":[{"below":"1.4","at":"2027-01-01T00:00:00Z"}]}`
}

// reloading is a server whose version policy is read from a file in a
// directory of its own, with the Reloader of that file, the metrics, and
// what it logs. The server is made outside any synctest bubble, so the
// bubble holds only the Reloader.
type reloading struct {
	path   string
	server *Server
	reg    *prometheus.Registry
	logged *bytes.Buffer
	read   []byte
}

func newReloading(t *testing.T, text string) *reloading {
	t.Helper()
	r := &reloading{path: filepath.Join(t.TempDir(), "version-policy.json"), reg: prometheus.NewRegistry(), logged: &bytes.Buffer{}}
	r.write(t, text)
	d, read, err := ReadVersionPolicy(r.path)
	if err != nil {
		t.Fatal(err)
	}
	r.read = read
	r.server = New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Metrics: NewMetrics(r.reg), Log: log.New(r.logged, "", 0), Policy: d})
	return r
}

// write puts text in the file in place.
func (r *reloading) write(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(r.path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rename puts text in the file as editors and a ConfigMap's symlink swap do:
// a new file in the same directory, renamed over it.
func (r *reloading) rename(t *testing.T, text string) {
	t.Helper()
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		t.Fatal(err)
	}
}

func (r *reloading) latest() string { return r.server.policy.Load().LatestVersion }

// reloads is how many reloads of the version policy have ended ok and failed.
func (r *reloading) reloads(t *testing.T) (ok, failed float64) {
	t.Helper()
	c := counts(t, r.reg, "dromas_server_runtime_config_reloads_total")
	return c["file=version-policy,result=ok"], c["file=version-policy,result=failed"]
}

// run runs the file's Reloader in a synctest bubble, on fake time, and f
// with the channel its signals come on; the Reloader ends with f.
func (r *reloading) run(t *testing.T, f func(t *testing.T, hup chan os.Signal)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		hup := make(chan os.Signal)
		go r.server.VersionPolicy(r.path, r.read).Run(ctx, hup, ReloadEvery)
		f(t, hup)
		cancel()
	})
}

// A signal reloads the file at once (as Prometheus reloads --config.file on
// SIGHUP), and the policy it reads is in force; a signal reloads it whatever
// its bytes, and counts ok. Control: before the signal, and before a minute
// has passed, the policy is the one read at start.
func TestTheVersionPolicyIsReloadedOnASignal(t *testing.T) {
	t.Parallel()
	r := newReloading(t, policyText("1.2", "1.5.0"))
	r.run(t, func(t *testing.T, hup chan os.Signal) {
		r.write(t, policyText("1.2", "1.6.0"))
		time.Sleep(ReloadEvery - time.Second)
		synctest.Wait()
		if r.latest() != "1.5.0" {
			t.Fatalf("before the signal: %s", r.latest())
		}
		hup <- syscall.SIGHUP
		synctest.Wait()
		if ok, failed := r.reloads(t); r.latest() != "1.6.0" || ok != 1 || failed != 0 {
			t.Errorf("after the signal: latest %s, %v ok, %v failed", r.latest(), ok, failed)
		}
		hup <- syscall.SIGHUP // the same bytes
		synctest.Wait()
		if ok, _ := r.reloads(t); ok != 2 {
			t.Errorf("a signal on the same bytes: %v ok, want 2", ok)
		}
	})
	if !strings.Contains(r.logged.String(), r.path+": version-policy loaded") {
		t.Errorf("logged %q", r.logged.String())
	}
}

// The file is read again once a minute, whatever its metadata says, and put
// in force when its bytes differ: a change by rename (an editor's save, a
// ConfigMap's symlink swap), and one in place of the same size whose
// modification time is set back, which no check of the file's metadata
// would see. Bytes the same as the last read are no reload. On fake time:
// no test sleeps a real minute.
func TestTheVersionPolicyIsReadAgainEachMinute(t *testing.T) {
	t.Parallel()
	r := newReloading(t, policyText("1.2", "1.5.0"))
	info, err := os.Stat(r.path)
	if err != nil {
		t.Fatal(err)
	}
	r.run(t, func(t *testing.T, _ chan os.Signal) {
		time.Sleep(ReloadEvery)
		synctest.Wait()
		if ok, failed := r.reloads(t); ok != 0 || failed != 0 {
			t.Fatalf("a minute on, the file unchanged: %v ok, %v failed, want no reload", ok, failed)
		}
		r.rename(t, policyText("1.2", "1.6.0"))
		time.Sleep(ReloadEvery - time.Second)
		synctest.Wait()
		if r.latest() != "1.5.0" {
			t.Fatalf("before the minute: %s", r.latest())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if ok, _ := r.reloads(t); r.latest() != "1.6.0" || ok != 1 {
			t.Fatalf("a minute after a rename: latest %s, %v ok", r.latest(), ok)
		}
		r.write(t, policyText("1.2", "1.7.0")) // the same size
		if err := os.Chtimes(r.path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(ReloadEvery)
		synctest.Wait()
		if ok, _ := r.reloads(t); r.latest() != "1.7.0" || ok != 2 {
			t.Errorf("a minute after a rewrite of the same size, its time set back: latest %s, %v ok", r.latest(), ok)
		}
	})
}

// A reload that fails keeps the policy in force, counts failed, and logs one
// line naming the path and why, never what the file holds: a file that
// breaks a policy's form (on a signal, and once by the minute's read, which
// reads the same bytes again as no reload), one past the bound, and one that
// is gone, which fails each minute it is gone. A good file after them is in
// force at the next minute.
func TestAFailedReloadKeepsTheVersionPolicy(t *testing.T) {
	t.Parallel()
	r := newReloading(t, policyText("1.2", "1.5.0"))
	r.run(t, func(t *testing.T, hup chan os.Signal) {
		r.write(t, `{"min_version":"zz-marker"}`)
		hup <- syscall.SIGHUP
		synctest.Wait()
		if ok, failed := r.reloads(t); r.latest() != "1.5.0" || ok != 0 || failed != 1 {
			t.Fatalf("a bad file on a signal: latest %s, %v ok, %v failed", r.latest(), ok, failed)
		}
		time.Sleep(ReloadEvery)
		synctest.Wait()
		if _, failed := r.reloads(t); failed != 1 {
			t.Errorf("the same bad bytes a minute on: %v failed, want no reload", failed)
		}
		r.write(t, policyText("1.2", "1.6.0")+strings.Repeat(" ", MaxVersionPolicy))
		time.Sleep(ReloadEvery)
		synctest.Wait()
		if _, failed := r.reloads(t); r.latest() != "1.5.0" || failed != 2 {
			t.Errorf("a file past the bound: latest %s, %v failed", r.latest(), failed)
		}
		if err := os.Remove(r.path); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * ReloadEvery)
		synctest.Wait()
		if _, failed := r.reloads(t); r.latest() != "1.5.0" || failed != 4 {
			t.Errorf("a file gone two minutes: latest %s, %v failed", r.latest(), failed)
		}
		r.rename(t, policyText("1.2", "1.6.0"))
		time.Sleep(ReloadEvery)
		synctest.Wait()
		if ok, _ := r.reloads(t); r.latest() != "1.6.0" || ok != 1 {
			t.Errorf("a good file after: latest %s, %v ok", r.latest(), ok)
		}
	})
	lines := strings.Split(strings.TrimSpace(r.logged.String()), "\n")
	if len(lines) != 5 || strings.Contains(r.logged.String(), "zz-marker") || strings.Contains(r.logged.String(), "min_version\":") {
		t.Errorf("logged %d lines, want 5, none holding the file:\n%s", len(lines), r.logged.String())
	}
	for _, l := range lines[:4] {
		if !strings.HasPrefix(l, r.path+": kept the version-policy in force: ") {
			t.Errorf("a failed reload's line: %q", l)
		}
	}
}

// A request meets the policy in force when it arrives: a reload that
// raises the floor retires a version at once, and the document answers the
// new policy. Control: before it, the same request is taken.
func TestARequestMeetsTheVersionPolicyInForce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "version-policy.json")
	if err := os.WriteFile(path, []byte(policyText("1.2", "1.5.0")), 0o600); err != nil {
		t.Fatal(err)
	}
	d, read, err := ReadVersionPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, relaxed(), func(c *Config) { c.Policy = d })
	nobody := "/v1/" + strings.Repeat("ab", 32)
	e.want(e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.5.0"), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	if err := os.WriteFile(path, []byte(policyText("1.6", "1.6.0")), 0o600); err != nil {
		t.Fatal(err)
	}
	e.server.VersionPolicy(path, read).reload(false)
	got := e.doWith("GET", nobody, nil, "", protocol.VersionHeader, "1.5.0")
	e.want(got, http.StatusGone, protocol.CodeVersionRetired)
	if got.problem().MinVersion != "1.6" {
		t.Errorf("min_version %q, want 1.6", got.problem().MinVersion)
	}
	var doc protocol.ServerDocument
	if err := protocol.Unmarshal(e.do("GET", protocol.DocumentPath, nil, "").body, &doc); err != nil || doc.MinVersion != "1.6" || doc.LatestVersion != "1.6.0" {
		t.Errorf("the document: %+v, %v", doc, err)
	}
}

// The bound on a policy file holds the largest policy of the document's
// form, 64 deprecations and 64 sunsets of the longest versions, written with
// indents, with room; one past the bound is refused.
func TestTheLargestPolicyFits(t *testing.T) {
	t.Parallel()
	n := "18446744073709551615"
	v := n + "." + n + "." + n
	d := protocol.ServerDocument{MinVersion: v, LatestVersion: v}
	for range protocol.MaxDeprecations {
		d.Deprecations = append(d.Deprecations, protocol.Scheduled{Version: v, At: "2027-01-01T00:00:00Z"})
	}
	for range protocol.MaxSunsets {
		d.Sunsets = append(d.Sunsets, protocol.Scheduled{Version: v, At: "2027-01-01T00:00:00Z"})
	}
	b, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxVersionPolicy-4<<10 {
		t.Errorf("the largest policy, indented, is %d bytes: within 4 KiB of the bound, %d", len(b), MaxVersionPolicy)
	}
	if _, err := ParseVersionPolicy(b); err != nil {
		t.Errorf("the largest policy: %v", err)
	}
	path := filepath.Join(t.TempDir(), "version-policy.json")
	if err := os.WriteFile(path, append(b, bytes.Repeat([]byte(" "), MaxVersionPolicy+1-len(b))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadVersionPolicy(path); err == nil {
		t.Error("a file past the bound was read")
	}
}
