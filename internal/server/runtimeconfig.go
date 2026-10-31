package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A runtime file is a file of the operator's runtime-config directory
// (conventionally /config/ in the container, bind-mounted read-only as a
// directory), which the server reads at start and again while it runs: on
// SIGHUP, as Prometheus reloads its --config.file, and once each interval
// whatever else happens, since a Kubernetes ConfigMap changes its mount by a
// symlink swap and sends no signal. A Reloader keeps one such file in force.

// ReloadEvery is how often a Reloader reads its file again.
const ReloadEvery = time.Minute

// Reloader keeps what one runtime file says in force: it reads the file again
// on each signal and each interval (Run), and applies what it reads where its
// bytes differ from the last read, or on a signal whatever they are. A read
// that fails, a file larger than its bound, or one apply refuses keeps what
// is in force, is logged in one line naming the file's path and why, never
// its contents, and counted failed in
// dromas_server_runtime_config_reloads_total, by the file's name.
type Reloader struct {
	name    string               // the file's name in the metrics: "version-policy"
	path    string               // where it is read
	bound   int64                // the most of it read: past it, the read fails
	apply   func(b []byte) error // parses and checks b, and swaps it in, or refuses it
	last    []byte               // the bytes read last
	log     *log.Logger          // nil: none
	metrics *Metrics             // nil: none
}

// readBounded reads the file at path, to bound bytes: a larger one is an
// error, as is a file that cannot be read. Its words name neither path nor
// contents.
func readBounded(path string, bound int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the operator's own flag names the file
	if err != nil {
		return nil, errors.New("it cannot be opened: " + errorKind(err))
	}
	defer f.Close() //nolint:errcheck // read only
	b, err := io.ReadAll(io.LimitReader(f, bound+1))
	if err != nil {
		return nil, errors.New("it cannot be read: " + errorKind(err))
	}
	if int64(len(b)) > bound {
		return nil, fmt.Errorf("it is larger than %d bytes", bound)
	}
	return b, nil
}

// errorKind is why a file could not be opened or read, in the words of the
// system's error alone, without the path os puts in it.
func errorKind(err error) string {
	if pe, ok := errors.AsType[*os.PathError](err); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// reload reads the file again and applies it where its bytes differ from
// the last read, or whatever they are when forced (a signal).
func (r *Reloader) reload(forced bool) {
	b, err := readBounded(r.path, r.bound)
	if err == nil && !forced && bytes.Equal(b, r.last) {
		return
	}
	if err == nil {
		r.last = b
		err = r.apply(b)
	}
	if err != nil {
		r.metrics.reload(r.name, false)
		if r.log != nil {
			r.log.Printf("%s: kept the %s in force: %v", r.path, r.name, err)
		}
		return
	}
	r.metrics.reload(r.name, true)
	if r.log != nil {
		r.log.Printf("%s: %s loaded", r.path, r.name)
	}
}

// Run keeps the file in force until ctx ends: it reloads it on each value of
// hup, and each every.
func (r *Reloader) Run(ctx context.Context, hup <-chan os.Signal, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			r.reload(true)
		case <-t.C:
			r.reload(false)
		}
	}
}

// MaxVersionPolicy is the most of a version policy file read: a few KiB
// more than the largest the document's form allows, 64 deprecations and 64
// sunsets of the longest versions, written with indents
// (TestTheLargestPolicyFits).
const MaxVersionPolicy = 24 << 10

// The version policy's file name in the metrics.
const versionPolicyFile = "version-policy"

// ParseVersionPolicy reads b as a version policy file (serve
// --version-policy): a JSON object in the form GET /v1/ answers
// (PROTOCOL.md §11.18), its min_version, latest_version, deprecations and
// sunsets, each optional, and no member else; capabilities are the code's,
// and max_certificate_lifetime the setting's, not the policy's. It returns
// the document the server answers with the policy in force, the setting of
// l among it, held to the document's form (protocol.ServerDocument.Check).
// Its errors name a member at most, never a value.
func ParseVersionPolicy(b []byte, l Limits) (protocol.ServerDocument, error) {
	var d protocol.ServerDocument
	if err := protocol.UnmarshalRequest(b, &d); err != nil {
		if m := protocol.Member(err); m != "" {
			return protocol.ServerDocument{}, fmt.Errorf("its member %q is not one a version policy takes, or not of its form", m)
		}
		return protocol.ServerDocument{}, errors.New("it is not a JSON object of a version policy's form")
	}
	if d.Capabilities != nil {
		return protocol.ServerDocument{}, errors.New(`its member "capabilities" is the server's own, not a version policy's`)
	}
	if d.MaxCertificateLifetime != 0 {
		return protocol.ServerDocument{}, errors.New(`its member "max_certificate_lifetime" is the server's own setting (--max-certificate-lifetime), not a version policy's`)
	}
	d = policyOf(d, l)
	if err := d.Check(); err != nil {
		return protocol.ServerDocument{}, fmt.Errorf("its member %q breaks the server's document (PROTOCOL.md §11.17, §11.18)", protocol.Member(err))
	}
	return d, nil
}

// ReadVersionPolicy reads the version policy file at path, to
// MaxVersionPolicy bytes, and parses it with the limits l
// (ParseVersionPolicy); it returns the bytes read beside it, for the
// Reloader that keeps it in force.
func ReadVersionPolicy(path string, l Limits) (protocol.ServerDocument, []byte, error) {
	b, err := readBounded(path, MaxVersionPolicy)
	if err != nil {
		return protocol.ServerDocument{}, nil, err
	}
	d, err := ParseVersionPolicy(b, l)
	if err != nil {
		return protocol.ServerDocument{}, nil, err
	}
	return d, b, nil
}

// VersionPolicy is the Reloader of s's version policy from the file at path,
// whose bytes read at start were read: each policy it reads that parses
// replaces the one in force at once, for the next request.
func (s *Server) VersionPolicy(path string, read []byte) *Reloader {
	return &Reloader{name: versionPolicyFile, path: path, bound: MaxVersionPolicy, last: read, log: s.log, metrics: s.metrics,
		apply: func(b []byte) error {
			d, err := ParseVersionPolicy(b, s.limits)
			if err != nil {
				return err
			}
			s.policy.Store(&d)
			return nil
		}}
}
