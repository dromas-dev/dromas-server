package server

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The accounts table (PROTOCOL.md §11.16): account is the account id's
// bytes; sk 0x00 is the account's record and 0x04 ‖ SHA-256 of the key an
// adopt key's state.
// Which boxes an account holds is the box records' to say: each names its
// account, and the boxes table's sparse index on it lists an account's
// boxes, so a box that leaves, or that DynamoDB's TTL takes, leaves nothing
// behind here.
const (
	skAccount  byte = 0x00
	skAdoptKey byte = 0x04
)

func accountKey(id string, sk ...byte) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"account": bin([]byte(id)), "sk": bin(sk)}
}

func adoptKeyKey(id string, hash [32]byte) map[string]types.AttributeValue {
	return accountKey(id, append([]byte{skAdoptKey}, hash[:]...)...)
}

func accountItem(a *Account) map[string]types.AttributeValue {
	it := accountKey(a.ID, skAccount)
	it["unmetered"] = &types.AttributeValueMemberBOOL{Value: a.Unmetered}
	it["rev"] = num(a.Rev)
	return it
}

// accountRecord reads the key of an item of the accounts table: its account
// id, and whether it is the account's record.
func accountRecord(it item) (string, bool, error) {
	id, err := it.bytes("account")
	if err != nil {
		return "", false, err
	}
	sk, err := it.bytes("sk")
	if err != nil {
		return "", false, err
	}
	return string(id), bytes.Equal(sk, []byte{skAccount}), nil
}

func decodeAccount(it item) (*Account, error) {
	id, _, err := accountRecord(it)
	if err != nil {
		return nil, err
	}
	rev, err := it.uint("rev")
	if err != nil {
		return nil, err
	}
	u, ok := it["unmetered"].(*types.AttributeValueMemberBOOL)
	if !ok {
		return nil, errors.New("item: unmetered is missing or not a boolean")
	}
	return &Account{ID: id, Unmetered: u.Value, Rev: rev}, nil
}

// Account implements Backend: a strongly consistent read, so a change made
// before it is in it.
func (s *dynamoBackend) Account(ctx context.Context, id string) (*Account, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.accts, Key: accountKey(id, skAccount), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	return decodeAccount(out.Item)
}

// CreateAccount implements Backend.
func (s *dynamoBackend) CreateAccount(ctx context.Context, a *Account) error {
	n := new(note)
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.accts,
		Item:                     accountItem(a),
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "account"},
	}, n.option())
	return written(err, n, ErrExists)
}

// PutAdoptKey implements Backend. Its expiry is also the item's TTL.
func (s *dynamoBackend) PutAdoptKey(ctx context.Context, k *AdoptKey) error {
	it := adoptKeyKey(k.Account, k.Hash)
	it["uses"] = num(uint64(k.Uses)) //nolint:gosec // uses are not negative
	it["expires"] = num(ms(k.Expires))
	it["expires_at"] = num(ttlSeconds(ms(k.Expires)))
	n := new(note)
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                &s.accts,
		Item:                     it,
		ConditionExpression:      aws.String("attribute_not_exists(#a)"),
		ExpressionAttributeNames: map[string]string{"#a": "account"},
	}, n.option())
	return written(err, n, ErrExists)
}

// AdoptKey implements Backend.
func (s *dynamoBackend) AdoptKey(ctx context.Context, account string, hash [32]byte) (*AdoptKey, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.accts, Key: adoptKeyKey(account, hash), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	it := item(out.Item)
	uses, err := it.uint("uses")
	if err != nil {
		return nil, err
	}
	exp, err := it.uint("expires")
	if err != nil {
		return nil, err
	}
	return &AdoptKey{Account: account, Hash: hash, Uses: int(uses), Expires: fromMs(exp)}, nil //nolint:gosec // uses are a count we wrote
}

// boxRevCheck is the update of a box record at b.Rev that bumps it.
func boxRevCheck(b *Box, expr string, names map[string]string, values map[string]types.AttributeValue) *types.Update {
	names["#rev"] = "rev"
	values[":old"], values[":new"] = num(b.Rev), num(b.Rev+1)
	return &types.Update{
		Key:                       boxKey(b.Addr),
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("#rev = :old"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}
}

// Adopt implements Backend: in one transaction, the box record names the
// account, and the key loses a use.
func (s *dynamoBackend) Adopt(ctx context.Context, b *Box, account string, key [32]byte) error {
	upd := boxRevCheck(b, "SET #acct = :acct, #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{":acct": bin([]byte(account))})
	upd.TableName = &s.boxes
	items := []types.TransactWriteItem{
		{Update: upd},
		{Update: &types.Update{
			TableName:                 &s.accts,
			Key:                       adoptKeyKey(account, key),
			UpdateExpression:          aws.String("SET #u = #u - :one"),
			ConditionExpression:       aws.String("#u >= :one AND #e > :now"),
			ExpressionAttributeNames:  map[string]string{"#u": "uses", "#e": "expires"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": num(1), ":now": num(s.nowMs())},
		}},
	}
	return s.transact(ctx, items, map[int]error{0: ErrStale, 1: ErrKeyRefused})
}

// Leave implements Backend: the box record names no account.
func (s *dynamoBackend) Leave(ctx context.Context, b *Box) error {
	upd := boxRevCheck(b, "REMOVE #acct SET #rev = :new", map[string]string{"#acct": "account"}, map[string]types.AttributeValue{})
	n := new(note)
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.boxes,
		Key:                       upd.Key,
		UpdateExpression:          upd.UpdateExpression,
		ConditionExpression:       upd.ConditionExpression,
		ExpressionAttributeNames:  upd.ExpressionAttributeNames,
		ExpressionAttributeValues: upd.ExpressionAttributeValues,
	}, n.option())
	return written(err, n, ErrStale)
}

// A transaction that meets another on one of its items is cancelled for a
// TransactionConflict, which the SDK does not retry (AWS, "Transaction
// conflict handling in DynamoDB"). It applied nothing and DynamoDB checks
// every condition again, so it is sent again as it is: by a new call, which
// carries a new client token. The tries and pauses are the SDK's own for
// DynamoDB under its newer retry behaviour (AWS_NEW_RETRIES_2026): four in
// all, each pause a random share of 25 ms, doubled after each try.
const (
	transactTries = 4
	transactPause = 25 * time.Millisecond
)

// transact writes items in one transaction, its calls sharing one note
// (note): an attempt of any of them that left open whether it was applied
// leaves the write open whatever came after, a throttle, an answer that the
// transaction is in progress, or the retry quota running out among them
// (dromas-dev/dromas-server#101). A condition that failed is the
// refusal named for its item in failed, whatever else met another; a
// conflict that lasts every try is ErrStale. The SDK gives one call's
// transaction a client token, the same on each of its attempts, and "if the
// original TransactWriteItems call was successful, then subsequent
// TransactWriteItems calls with the same client token return successfully
// without making any changes" (Amazon DynamoDB Developer Guide, Transaction
// APIs, Idempotency): so a failed condition is a refusal stated after an
// attempt of its own call, but not after one of an earlier call, which
// carried another token.
func (s *dynamoBackend) transact(ctx context.Context, items []types.TransactWriteItem, failed map[int]error) error {
	n := new(note)
	for try := 1; ; try++ {
		earlier := n.seen.Load() // an attempt of an earlier call, under another token
		_, err := s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}, n.option())
		var tc *types.TransactionCanceledException
		if !errors.As(err, &tc) {
			return written(err, n, nil)
		}
		conflict := false
		for i, r := range tc.CancellationReasons {
			switch aws.ToString(r.Code) {
			case "ConditionalCheckFailed":
				if e, ok := failed[i]; ok {
					if earlier { // a call before this one, under another token, may have been applied
						return written(err, n, nil)
					}
					return e
				}
			case "TransactionConflict":
				conflict = true
			}
		}
		if !conflict {
			return written(err, n, nil)
		}
		if try == transactTries {
			if n.seen.Load() { // a try before may have been applied
				return written(err, n, nil)
			}
			return ErrStale
		}
		pause := time.NewTimer(rand.N(transactPause << (try - 1))) //nolint:gosec // a pause's jitter, no secret
		select {
		case <-pause.C:
		case <-ctx.Done():
			pause.Stop()
			return written(ctx.Err(), n, nil)
		}
	}
}

// isTransactionConflict reports whether err is a write of one item that met a
// transaction on it, which the SDK does not retry either. The item changes if
// that transaction commits, so the write is answered as a failed condition.
func isTransactionConflict(err error) bool {
	var tc *types.TransactionConflictException
	return errors.As(err, &tc)
}
