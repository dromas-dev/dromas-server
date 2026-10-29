//go:build unix

package main

import (
	"net"
	"syscall"
)

// listenOwn listens on a Unix socket at path that only this process's user
// can open from its bind on: it is bound under a umask that leaves its
// owner's bits alone, as systemd binds a socket unit's. A socket chmod'ed
// after its bind takes another user's connection until then
// (dromas-dev/dromas-server#47). The umask is the process's: this runs at
// start, before anything else makes a file.
func listenOwn(path string) (net.Listener, error) {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}
