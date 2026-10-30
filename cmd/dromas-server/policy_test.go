package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refused runs serve with args, and reports what it returned: a refusal
// returns at once, before it listens or opens any store; one that has not
// returned in a few seconds has started a server, which ends with the test.
func refused(t *testing.T, args ...string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- serve(append([]string{"--dev", "--listen", "127.0.0.1:0"}, args...)) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%v: serve started", args)
		return nil
	}
}

// dromas-server serve refuses to start on a --version-policy file it cannot
// read, or one that breaks a version policy's form (PROTOCOL.md §11.17,
// §11.18), naming the flag and the path, never what the file holds.
// Control: a file of its form is taken, so the refusal is the next flag's.
func TestServeRefusesAVersionPolicyThatBreaksItsForm(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const at, later = "2027-01-01T00:00:00Z", "2027-02-01T00:00:00Z"
	for _, c := range []struct{ name, body string }{
		{"not-json", `min_version: 1.2`},
		{"unknown-member", `{"min_version":"1.2","floor":"1.2"}`},
		{"capabilities", `{"capabilities":[]}`},
		{"bad-floor", `{"min_version":"v1.2-secretish"}`},
		{"bad-latest", `{"latest_version":"1.2.3.4"}`},
		{"both", `{"deprecations":[{"below":"1.2","version":"1.3","at":"` + at + `"}]}`},
		{"bad-time", `{"sunsets":[{"below":"1.2","at":"2027-01-01"}]}`},
		{"sunset-first", `{"deprecations":[{"below":"1.2","at":"` + later + `"}],"sunsets":[{"below":"1.2","at":"` + at + `"}]}`},
		{"too-large", `{"min_version":"1.2"}` + strings.Repeat(" ", 25<<10)},
	} {
		p := file(c.name+".json", c.body)
		err := refused(t, "--version-policy", p)
		if err == nil || !strings.HasPrefix(err.Error(), "--version-policy: "+p+": ") || strings.Contains(err.Error(), "secretish") {
			t.Errorf("%s: %v, want a refusal naming the flag and the path, and nothing of the file", c.name, err)
		}
	}
	if err := refused(t, "--version-policy", filepath.Join(dir, "missing.json")); err == nil || !strings.HasPrefix(err.Error(), "--version-policy: ") {
		t.Errorf("a missing file: %v", err)
	}
	good := file("good.json", `{"min_version":"1.2","latest_version":"1.5.1","deprecations":[{"below":"1.4","at":"`+at+`"}],"sunsets":[{"below":"1.4","at":"`+later+`"}]}`)
	if err := refused(t, "--version-policy", good, "--max-size", "-1"); err == nil || !strings.HasPrefix(err.Error(), "--max-size:") {
		t.Errorf("control, a file of its form: %v, want the refusal of --max-size", err)
	}
}
