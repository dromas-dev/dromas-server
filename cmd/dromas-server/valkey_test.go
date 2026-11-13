package main

import (
	"strings"
	"testing"
)

// A --valkey that is no Valkey URL refuses the start, saying which flag;
// one whose store is not there yet does not (server.OpenValkey).
func TestServeReadsItsValkeyURLAtStart(t *testing.T) {
	err := serve([]string{"--dev", "--listen", "127.0.0.1:0", "--valkey", "http://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "--valkey") {
		t.Fatalf("serve --valkey http://…: %v, want it refused naming --valkey", err)
	}
}
