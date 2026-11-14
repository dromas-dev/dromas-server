package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every page and comment says what holds now, never how it came to be
// (AGENTS.md): a date is allowed only where it says when a source was read,
// a measurement measured, a review made or an outside document dated, and
// in the tag URIs of the protocol's error types, whose date is part of the
// URI; a time written out (2006-01-02T15:04:05Z) is an example of a format,
// not a date of anything.
func TestEveryPageSaysWhatHoldsNow(t *testing.T) {
	date := regexp.MustCompile(`20[0-9]{2}-[01][0-9]-[0-3][0-9]`)
	allowed := regexp.MustCompile(`(?i)(\b(read|measured|review|dated) |tag:dromas\.dev,)20[0-9]{2}-[01][0-9]-[0-3][0-9]|20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-9]{2}:`)
	root := filepath.Join("..", "..")
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (name == "testdata" || name == "dist" || strings.HasPrefix(name, ".") && name != ".github") {
				return filepath.SkipDir
			}
			return nil
		}
		// The part of each line a reader reads as the page's or a comment's words.
		var words func(string) string
		switch ext := filepath.Ext(name); {
		case ext == ".md":
			words = func(l string) string { return l }
		case ext == ".go":
			words = func(l string) string { _, c, _ := strings.Cut(l, "//"); return c }
		case ext == ".sh" || ext == ".yml" || ext == ".yaml" || name == "Dockerfile":
			words = func(l string) string { _, c, _ := strings.Cut(l, "#"); return c }
		default:
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // a file of this repo
		if err != nil {
			return err
		}
		n++
		for i, l := range strings.Split(string(data), "\n") {
			w := words(l)
			if date.MatchString(allowed.ReplaceAllString(w, "")) {
				t.Errorf("%s:%d dates something other than a source, a measurement or a review: %s", p, i+1, strings.TrimSpace(l))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("read %d files from %s: the walk is broken", n, root)
	}
}

// maxClaimWords is the longest a claim in SECURITY.md's table may run: one
// sentence, whose whole rule is the code, the doc comment or the page that
// its "Held by" cell names.
const maxClaimWords = 35

// testName is a test or fuzz test named in backticks.
var testName = regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`")

// Each claim in SECURITY.md § What dromas-server must still get right is one
// sentence of at most maxClaimWords words, and its "Held by" cell names the
// tests that hold the claim, the CI job that checks it or the test harness
// (`newEnv`) that every test runs it through, or says "no test". Each path the cell names is a
// file or directory of this repo, or of the client repo where it starts
// "dromas-client/", and each test it names is a test of this repo, defined in
// the test file the cell names it under.
func TestEachSecurityClaimIsOneSentence(t *testing.T) {
	root := filepath.Join("..", "..")
	b, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), "\n## What `dromas-server` must still get right\n")
	if !ok {
		t.Fatal("SECURITY.md has no § What dromas-server must still get right")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	tests := testsOf(t, root)
	link := regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	word := regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9'’\-.+]*`)
	stop := regexp.MustCompile(`[.!?]["”]?\s`)
	path := regexp.MustCompile("`([^` ]+)`")
	n := 0
	for l := range strings.SplitSeq(section, "\n") {
		if !strings.HasPrefix(l, "| **") {
			continue
		}
		n++
		cells := strings.Split(strings.Trim(l, "| "), " | ")
		if len(cells) != 2 {
			t.Errorf("a claim's row has %d cells, not 2: %.60s", len(cells), l)
			continue
		}
		claim, held := link.ReplaceAllString(cells[0], "$1"), cells[1]
		if w := len(word.FindAllString(claim, -1)); w > maxClaimWords {
			t.Errorf("a claim runs %d words, over %d: %.60s", w, maxClaimWords, claim)
		}
		if stop.MatchString(claim) {
			t.Errorf("a claim is more than one sentence: %.60s", claim)
		}
		names := testName.FindAllStringSubmatch(held, -1)
		if len(names) == 0 && !strings.Contains(held, "no test") && !strings.Contains(held, " job `") && !strings.Contains(held, "`newEnv`") {
			t.Errorf("a claim names no test and does not say \"no test\": %.60s", claim)
		}
		for _, m := range names {
			if len(tests[m[1]]) == 0 {
				t.Errorf("a claim is held by %s, which is no test of this repo: %.60s", m[1], claim)
			}
		}
		for _, part := range strings.Split(held, "; ") {
			file, list, ok := strings.Cut(part, "`: ")
			if !ok || !strings.HasSuffix(file, "_test.go") {
				continue
			}
			file = strings.TrimPrefix(file, "`")
			for _, m := range testName.FindAllStringSubmatch(list, -1) {
				if len(tests[m[1]]) > 0 && !slices.Contains(tests[m[1]], file) {
					t.Errorf("a claim names %s under %s, which does not define it: %.60s", m[1], file, claim)
				}
			}
		}
		for _, m := range path.FindAllStringSubmatch(held, -1) {
			p := m[1]
			if !strings.Contains(p, "/") || strings.Contains(p, "://") || strings.HasPrefix(p, "dromas-client/") {
				continue
			}
			if found, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(p, "/")))); err != nil || len(found) == 0 {
				t.Errorf("a claim is held by %s, which is not in this repo: %.60s", p, claim)
			}
		}
	}
	if n < 5 {
		t.Fatalf("read %d claims: the reading is broken", n)
	}
}

// testsOf maps each test and fuzz test of the repo at root to the files,
// relative to root, that define it.
func testsOf(t *testing.T, root string) map[string][]string {
	t.Helper()
	def := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
	tests := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // a file of this repo
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		for _, m := range def.FindAllStringSubmatch(string(b), -1) {
			tests[m[1]] = append(tests[m[1]], filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) < 100 {
		t.Fatalf("found %d tests under %s: the walk is broken", len(tests), root)
	}
	return tests
}
