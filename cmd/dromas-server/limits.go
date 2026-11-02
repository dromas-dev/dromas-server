package main

import (
	"context"
	"errors"
	"fmt"
	flag "github.com/spf13/pflag"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// listenAdmin listens on the Unix socket at path for the operator's
// commands, readable and writable by this process's user alone from the
// moment it is made (listenOwn). A socket left there by a process before
// this one is replaced; anything else at that path is an error.
func listenAdmin(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("--admin-socket %s: something that is not a socket is there", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("--admin-socket: %w", err)
		}
	}
	l, err := listenOwn(path)
	if err != nil {
		return nil, fmt.Errorf("--admin-socket: %w", err)
	}
	return l, nil
}

// limits runs one operator command on a running server's limits, through
// its --admin-socket: the counts are in that process's memory.
func limits(cmd string, args []string) error {
	fs := flag.NewFlagSet("limits "+cmd, flag.ContinueOnError)
	socket := fs.String("socket", "", "the running server's --admin-socket")
	switch cmd {
	case "clear":
		ip := fs.String("ip", "", "the caller's address: an IPv4 address, or any IPv6 address of the /64 the limits count")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *socket == "" || *ip == "" || fs.NArg() != 0 {
			return errors.New("name --socket and --ip")
		}
		return adminCall(*socket, http.MethodPost, "/limits/clear?ip="+url.QueryEscape(*ip), os.Stdout)
	case "top":
		limit := fs.String("limit", "", "the limit, by the name a refusal gives it: a rate_limited's quota_id, or the code of its own (mailbox_busy, fetch_paced)")
		count := fs.Int("count", 20, "how many keys, deepest in debt first")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *socket == "" || *limit == "" || fs.NArg() != 0 {
			return errors.New("name --socket and --limit")
		}
		return adminCall(*socket, http.MethodGet, "/limits/top?limit="+url.QueryEscape(*limit)+"&n="+strconv.Itoa(*count), os.Stdout)
	default:
		return fmt.Errorf("limits %s: the commands are clear and top", cmd)
	}
}

// adminCall calls method on path on the server listening at socket, and
// copies a 200's body to out.
func adminCall(socket, method, path string, out io.Writer) error {
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	// The host is fixed, and the dial goes to the operator's own socket alone.
	req, err := http.NewRequest(method, "http://dromas-server"+path, http.NoBody) //nolint:gosec // as above
	if err != nil {
		return err
	}
	resp, err := c.Do(req) //nolint:gosec // as above
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read to the end below
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the server answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_, err = out.Write(body)
	return err
}
