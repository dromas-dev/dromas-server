package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	clientDirOnce sync.Once
	clientDirPath string
	clientDirErr  error
)

// clientFile reads a file of the dromas-client module this one is built
// against: the release go.mod requires, or the checkout a go.work names.
func clientFile(t *testing.T, path string) []byte {
	t.Helper()
	clientDirOnce.Do(func() {
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/dromas-dev/dromas-client").Output()
		clientDirPath, clientDirErr = strings.TrimSpace(string(out)), err
	})
	if clientDirErr != nil {
		t.Fatal(clientDirErr)
	}
	b, err := os.ReadFile(filepath.Join(clientDirPath, path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
