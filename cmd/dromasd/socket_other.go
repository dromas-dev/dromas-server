//go:build !unix

package main

import (
	"net"
	"os"
)

// listenOwn listens on a Unix socket at path, then makes it 0600. With no
// umask here, another user may connect between the two.
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
