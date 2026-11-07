package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Shard is the part of the addresses one process answers for, when the
// reverse proxy in front sends each mailbox's calls to one process by its
// address (ARCHITECTURE.md § Routing by address). An address is "d_" and
// base64url of a SHA-384, so its first character after "d_" is uniform over
// base64url's 64 values: shard I of N, N a power of two up to 64, is the
// characters whose value v has v*N/64 == I, v being the top six bits of
// the address's first byte. Shards of different N may sit side by side, so one half splits
// into two quarters with the other half untouched. The zero Shard is every
// address.
type Shard struct{ I, N int }

// maxShards is the number of values an address's first character after "d_"
// takes: the top six bits of its first byte.
const maxShards = 64

// ParseShard reads a shard written "I/N" (Shard.String); "" is every address.
func ParseShard(s string) (Shard, error) {
	if s == "" {
		return Shard{}, nil
	}
	is, ns, ok := strings.Cut(s, "/")
	i, ierr := strconv.Atoi(is)
	n, nerr := strconv.Atoi(ns)
	if !ok || ierr != nil || nerr != nil || n < 1 || n > maxShards || n&(n-1) != 0 || i < 0 || i >= n {
		return Shard{}, fmt.Errorf("a shard is I/N: N a power of two from 1 to %d, I from 0 to N-1", maxShards)
	}
	return Shard{I: i, N: n}, nil
}

// String writes the shard as ParseShard reads it.
func (s Shard) String() string {
	if s.N <= 1 {
		return "0/1"
	}
	return fmt.Sprintf("%d/%d", s.I, s.N)
}

// owns reports whether the shard answers for a path's address. What is not
// an address is every shard's, for its route to refuse.
func (s Shard) owns(addr string) bool {
	if s.N <= 1 {
		return true
	}
	a, err := protocol.ParseAddress(addr)
	return err != nil || int(a[0]>>2)*s.N/maxShards == s.I
}

// owned answers 503 to a call for a mailbox outside this process's shard,
// which the reverse proxy in front should have sent to another process: a
// misroute fails at once, and no mailbox is answered for by two processes.
// It runs behind the gate, so the call is counted first, as whenReady's are.
func (s *Server) owned(h http.Handler) http.Handler {
	if s.shard.N <= 1 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.shard.owns(r.PathValue("addr")) {
			s.metrics.misrouted()
			p := fail(protocol.CodeUnavailable, "retry later", "this process does not answer for that mailbox")
			p.retryAfter = retryLater
			writeProblem(w, p)
			return
		}
		h.ServeHTTP(w, r)
	})
}
