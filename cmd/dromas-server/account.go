package main

import (
	"context"
	"errors"
	"fmt"
	flag "github.com/spf13/pflag"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// account runs one operator command on accounts (PROTOCOL.md §11.16).
func account(cmd string, args []string) error {
	fs := flag.NewFlagSet("account "+cmd, flag.ContinueOnError)
	var run func(context.Context, *server.Memory) error
	switch cmd {
	case "create":
		id := fs.String("id", "", "the account's id: a name of ours (echo), or none to mint one")
		unmetered := fs.Bool("unmetered", false, "its mailboxes have no daily limit, the largest cap and new messages at the fastest any mailbox takes them, never charged (the echo account)")
		run = func(ctx context.Context, s *server.Memory) error {
			if *id == "" {
				var err error
				if *id, err = server.NewAccountID(); err != nil {
					return err
				}
			}
			a, err := server.NewAccount(*id, *unmetered)
			if err != nil {
				return err
			}
			if err := s.CreateAccount(ctx, a); err != nil {
				return fmt.Errorf("account %s: %w", a.ID, err)
			}
			fmt.Println(a.ID)
			return nil
		}
	case "key":
		id := fs.String("account", "", "the account the key adopts mailboxes into")
		uses := fs.Int("uses", 0, "how many mailboxes the key may adopt")
		ttl := fs.Duration("ttl", 0, "how long the key is good for")
		run = func(ctx context.Context, s *server.Memory) error {
			if *id == "" || *uses < 1 || *ttl <= 0 {
				return errors.New("name --account, --uses and --ttl")
			}
			if _, err := s.Account(ctx, *id); err != nil {
				return fmt.Errorf("account %s: %w", *id, err)
			}
			key, hash, err := server.NewAdoptKey(*id)
			if err != nil {
				return err
			}
			if err := s.PutAdoptKey(ctx, &server.AdoptKey{Account: *id, Hash: hash, Uses: *uses, Expires: time.Now().Add(*ttl)}); err != nil {
				return err
			}
			// The one time the key is shown: only its hash is kept.
			fmt.Println(key)
			return nil
		}
	case "drop":
		id := fs.String("account", "", "the account to drop the mailbox from")
		addr := fs.String("mailbox", "", "the mailbox's address")
		run = func(ctx context.Context, s *server.Memory) error {
			a, err := protocol.ParseAddress(*addr)
			if *id == "" || err != nil {
				return errors.New("name --account and --mailbox (an address)")
			}
			b, err := s.Mailbox(ctx, a)
			if err != nil {
				return fmt.Errorf("mailbox: %w", err)
			}
			if b.Account != *id {
				return fmt.Errorf("the mailbox is not in account %s", *id)
			}
			return s.Leave(ctx, b)
		}
	default:
		return fmt.Errorf("account %s: not create, key or drop", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := server.NewPostgresStore(ctx, server.PostgresConfig{})
	if err != nil {
		return err
	}
	return run(ctx, s)
}
