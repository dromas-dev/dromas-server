package main

import (
	"context"
	"errors"
	"fmt"
	flag "github.com/spf13/pflag"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
)

// account runs one operator command on accounts (PROTOCOL.md §11.16).
func account(cmd string, args []string) error {
	fs := flag.NewFlagSet("account "+cmd, flag.ContinueOnError)
	region := fs.String("region", "us-east-1", "the AWS region")
	accts := fs.String("accounts-table", "", "the DynamoDB table of accounts")
	var run func(context.Context, *server.Memory) error
	switch cmd {
	case "create":
		id := fs.String("id", "", "the account's id: a name of ours (echo), or none to mint one")
		unmetered := fs.Bool("unmetered", false, "its boxes have no daily limit, the largest cap and new mail at the fastest any box takes it, never charged (the echo account)")
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
		id := fs.String("account", "", "the account the key adopts boxes into")
		uses := fs.Int("uses", 0, "how many boxes the key may adopt")
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
		fs.String("boxes-table", "", "the DynamoDB table of boxes")
		id := fs.String("account", "", "the account to drop the box from")
		addr := fs.String("box", "", "the box's address")
		run = func(ctx context.Context, s *server.Memory) error {
			a, err := protocol.ParseAddress(*addr)
			if fs.Lookup("boxes-table").Value.String() == "" || *id == "" || err != nil {
				return errors.New("name --boxes-table, --account and --box (an address)")
			}
			b, err := s.Box(ctx, a)
			if err != nil {
				return fmt.Errorf("box: %w", err)
			}
			if b.Account != *id {
				return fmt.Errorf("the box is not in account %s", *id)
			}
			return s.Leave(ctx, b)
		}
	default:
		return fmt.Errorf("account %s: not create, key or drop", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *accts == "" {
		return errors.New("name --accounts-table")
	}
	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region), config.WithLogger(server.AWSLogger(os.Stderr)))
	if err != nil {
		return err
	}
	boxesTable := ""
	if f := fs.Lookup("boxes-table"); f != nil {
		boxesTable = f.Value.String()
	}
	return run(ctx, server.NewDynamoStore(server.DynamoConfig{AWS: awsCfg, BoxesTable: boxesTable, AccountsTable: *accts, ConsistentReads: true}))
}
