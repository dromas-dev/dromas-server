package main

import (
	"slices"
	"strings"
	"testing"
)

// --names takes server names in their one form, and refuses one that carries
// port 80 or 443 (PROTOCOL.md §8).
func TestNamesAreServerNames(t *testing.T) {
	t.Parallel()
	if got, err := serverNames(" dromas.example, dromas.example:8443,,[::1]:8080"); err != nil || !slices.Equal(got, []string{"dromas.example", "dromas.example:8443", "[::1]:8080"}) {
		t.Errorf("%v, %v", got, err)
	}
	for _, n := range []string{"dromas.example:443", "dromas.example:80", "dromas.example,dromas.example:443", "[::1]:80", "Dromas.example", "https://dromas.example"} {
		if got, err := serverNames(n); err == nil || !strings.Contains(err.Error(), "--names") {
			t.Errorf("%s: %v, %v", n, got, err)
		}
	}
}
