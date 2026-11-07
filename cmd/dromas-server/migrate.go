package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"

	"github.com/dromas-dev/dromas-server/internal/server"
)

// migrate applies the migrations this build holds that the database has
// not, on the database libpq's environment names, as the role that owns its
// schema, and says what it applied.
func migrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dromas-server migrate")
		fmt.Fprintln(os.Stderr, "Brings the schema of the database libpq's environment names up to date, as its owner: run before serve.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("migrate takes no arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(server.Redacting(os.Stderr), "", log.LstdFlags|log.LUTC)
	applied, version, err := server.Migrate(ctx, "", "", logger)
	for _, v := range applied {
		logger.Printf("migrate: applied %d", v)
	}
	if err != nil {
		return err
	}
	logger.Printf("migrate: the schema is at version %d", version)
	return nil
}
