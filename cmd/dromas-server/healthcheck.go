package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	flag "github.com/spf13/pflag"
)

// healthcheck is a container's healthcheck of a serve process, for an image
// with no shell or curl in it, as Traefik's own healthcheck command is: it
// asks the API for the server's document, GET /v1/, which a process answers
// 503 until its store has loaded its memory, and reports success on a 200
// alone. The request is counted at the gate as any request from its address
// is, a few each minute against a budget sized for floods.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/v1/", "the server's document on one of serve's --listen addresses")
	timeout := fs.Duration("timeout", 2*time.Second, "how long to wait for the answer")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dromas-server healthcheck [--url URL] [--timeout D]")
		fmt.Fprintln(os.Stderr, "Exits 0 when serve answers GET /v1/ with 200, as a container's healthcheck asks: ready to take calls.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("healthcheck takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: no answer: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: the server answered %d, not ready", resp.StatusCode)
	}
	return nil
}
