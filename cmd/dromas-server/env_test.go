package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
)

// Each flag is also its DROMAS_SERVER_ variable: a variable sets a flag the
// command line left unset, read as the flag reads a value; a flag given wins;
// a flag with neither keeps its default; and a value the flag refuses names
// its variable.
func TestAFlagIsAlsoItsVariable(t *testing.T) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	valkey := fs.String("valkey", "", "")
	listen := fs.String("listen", "127.0.0.1:8080", "")
	sweep := fs.Duration("sweep-interval", 10*time.Minute, "")
	conns := fs.Int("db-max-conns", 0, "")
	dev := fs.Bool("dev", false, "")
	names := fs.String("names", "", "")
	t.Setenv("DROMAS_SERVER_VALKEY", "valkey://127.0.0.1:6380")
	t.Setenv("DROMAS_SERVER_LISTEN", "127.0.0.1:1")
	t.Setenv("DROMAS_SERVER_SWEEP_INTERVAL", "1m")
	t.Setenv("DROMAS_SERVER_DB_MAX_CONNS", "7")
	t.Setenv("DROMAS_SERVER_DEV", "true")
	if err := fs.Parse([]string{"--listen", "127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	if err := fromEnv(fs); err != nil {
		t.Fatal(err)
	}
	if *valkey != "valkey://127.0.0.1:6380" || *sweep != time.Minute || *conns != 7 || !*dev {
		t.Fatalf("from the environment: valkey %q, sweep %s, conns %d, dev %v", *valkey, *sweep, *conns, *dev)
	}
	if *listen != "127.0.0.1:2" {
		t.Fatalf("--listen given and DROMAS_SERVER_LISTEN set: %q, want the flag's", *listen)
	}
	if *names != "" {
		t.Fatalf("a flag with no variable is %q, want its default", *names)
	}

	bad := flag.NewFlagSet("serve", flag.ContinueOnError)
	bad.Int("db-max-conns", 0, "")
	t.Setenv("DROMAS_SERVER_DB_MAX_CONNS", "many")
	if err := bad.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := fromEnv(bad); err == nil || !strings.Contains(err.Error(), "DROMAS_SERVER_DB_MAX_CONNS") {
		t.Fatalf("a variable its flag refuses: %v, want it named", err)
	}
}

// Every one of serve's flags has its own variable, and none is a secret's.
func TestServesFlagsAreItsVariables(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range serveFlags(t) {
		n := envName(f)
		if seen[n] {
			t.Errorf("two flags are %s", n)
		}
		seen[n] = true
		if n == "DROMAS_SERVER_VALKEY_PASSWORD" || strings.HasSuffix(n, "_FILE") {
			t.Errorf("--%s is a secret's variable, %s", f, n)
		}
	}
	if !seen["DROMAS_SERVER_VALKEY"] {
		t.Fatal("--valkey has no variable")
	}
}

// serveFlags is the name of each flag serve defines, read from its usage.
func serveFlags(t *testing.T) []string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	_ = serve([]string{"--help"})
	os.Stderr = stderr
	_ = w.Close()
	b := make([]byte, 1<<20)
	n, _ := r.Read(b)
	var names []string
	for _, line := range strings.Split(string(b[:n]), "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "--") {
			names = append(names, strings.TrimPrefix(f[0], "--"))
		}
	}
	if len(names) < 10 {
		t.Fatalf("read %d of serve's flags from its usage", len(names))
	}
	return names
}

// A secret is its variable, or the file its _FILE variable names, less one
// trailing newline; both set is refused; neither is none.
func TestASecretIsItsVariableOrItsFile(t *testing.T) {
	const name = "DROMAS_SERVER_TEST_SECRET"
	if s, err := secret(name); err != nil || s != "" {
		t.Fatalf("neither set: %q, %v", s, err)
	}
	t.Setenv(name, "from the variable")
	if s, err := secret(name); err != nil || s != "from the variable" {
		t.Fatalf("the variable: %q, %v", s, err)
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from the file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name+"_FILE", path)
	if _, err := secret(name); err == nil {
		t.Fatal("both set was taken")
	}
	os.Unsetenv(name)
	if s, err := secret(name); err != nil || s != "from the file" {
		t.Fatalf("the file: %q, %v", s, err)
	}
	t.Setenv(name+"_FILE", filepath.Join(t.TempDir(), "none"))
	if _, err := secret(name); err == nil {
		t.Fatal("a file that is not there was taken")
	}
}
