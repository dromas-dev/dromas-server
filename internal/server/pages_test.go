package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every page and comment says what holds now, never how it came to be
// (AGENTS.md): a date is allowed only where it says when a source was read,
// a measurement measured, a review made or an outside document dated, and
// in the tag URIs of the protocol's error types, whose date is part of the
// URI.
func TestEveryPageSaysWhatHoldsNow(t *testing.T) {
	date := regexp.MustCompile(`20[0-9]{2}-[01][0-9]-[0-3][0-9]`)
	allowed := regexp.MustCompile(`(?i)(\b(read|measured|review|dated) |tag:dromas\.dev,)20[0-9]{2}-[01][0-9]-[0-3][0-9]`)
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
			if rel, _ := filepath.Rel(root, p); rel == "" {
				return nil
			}
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
