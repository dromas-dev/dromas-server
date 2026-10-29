//go:build unix

package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
)

// The operator's socket is never open to another user, not for a moment,
// whatever the umask (dromas-dev/dromas-server#47): under umask 0000,
// its mode is watched while listenAdmin runs again and again, and never has
// a bit but its owner's; the umask is given back. A socket chmod'ed after
// its bind is seen at 0777 within a few starts.
func TestTheAdminSocketIsNeverTheUmasks(t *testing.T) {
	dir, err := os.MkdirTemp("", "dr") // a short path: sockaddr_un's sun_path is 108 bytes on Linux and 104 on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	var loose atomic.Uint32 // the first mode seen with another's bit
	var seen atomic.Int64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if fi, err := os.Lstat(path); err == nil {
				seen.Add(1)
				if m := uint32(fi.Mode().Perm()); m&0o077 != 0 {
					loose.CompareAndSwap(0, m)
				}
			}
		}
	}()
	for range 2000 {
		l, err := listenAdmin(path)
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		if loose.Load() != 0 {
			break
		}
	}
	close(stop)
	<-done
	if m := loose.Load(); m != 0 {
		t.Fatalf("the socket was %04o for a moment", m)
	}
	if seen.Load() == 0 {
		t.Fatal("the socket was never seen: nothing was watched")
	}
	if got := syscall.Umask(0); got != 0 {
		t.Errorf("listenAdmin left the umask at %04o, not the 0000 it was given", got)
	}
}
