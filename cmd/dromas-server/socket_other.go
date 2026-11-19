//go:build !unix

package main

import (
	"net"
	"os"
)

// listenOwn listens on a Unix socket at path, then chmods it 0600. On
// Windows os.Chmod uses only the owner's write bit, the read-only
// attribute, so the socket is not its user's alone there; elsewhere, with
// no umask here, another user may connect between the two.
func listenOwn(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
