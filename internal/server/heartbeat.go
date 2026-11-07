package server

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// The heartbeat (ARCHITECTURE.md § Following the stream): each process writes
// one item to each table at an interval of its own, a timestamp by its clock,
// and a follower is current only while the newest heartbeat it has applied
// is recent (feed.current). An empty page of a stream reads the same whether
// the stream is idle or behind; a heartbeat written after a stall reaches
// the follower only once it has read past the stall. pt-heartbeat measures
// a replica's delay the same way, by a timestamp row its source updates
// every interval (Percona Toolkit docs, read 2026-11-07).

// heartbeatKey is the heartbeat item's partition and sort key in every table:
// one byte, which no address (48 bytes), message id (32 bytes) or account id
// (a letter or a digit first) is. Every process writes the same item, so
// there is one a table, whatever the number of processes.
var heartbeatKey = []byte{0}

// beatTable is a table the heartbeat is written to: its name, its keys'
// names, and its follower.
type beatTable struct {
	table, pk, sk string
	f             *feed
}

func (s *dynamoBackend) beatTables() []beatTable {
	return []beatTable{{s.mailboxes, "addr", "sk", s.mailboxFeed}, {s.msgs, "box", "id", s.msgFeed}, {s.accts, "account", "sk", s.accFeed}}
}

// heartbeat writes each table's heartbeat item, dated at.
func (s *dynamoBackend) heartbeat(ctx context.Context, at time.Time) error {
	var errs []error
	for _, t := range s.beatTables() {
		_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &t.table, Item: map[string]types.AttributeValue{
			t.pk: bin(heartbeatKey), t.sk: bin(heartbeatKey), "at": num(ms(at)),
		}})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// beat writes the heartbeat at once and then each heartbeat interval, until
// ctx ends. A write that fails is logged; the next is the retry.
func (s *dynamoBackend) beat(ctx context.Context) {
	t := time.NewTicker(s.heartbeatEvery)
	defer t.Stop()
	for {
		if err := s.heartbeat(ctx, time.Now()); err != nil && ctx.Err() == nil {
			s.logf("heartbeat: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// heartbeatOf reads a stream record as a heartbeat of the table whose
// partition key is named pk: the date it carries, and whether it is one. A
// heartbeat whose date does not read dates nothing.
func heartbeatOf(r stypes.Record, pk string) (time.Time, bool) {
	if r.Dynamodb == nil {
		return time.Time{}, false
	}
	k, ok := r.Dynamodb.Keys[pk].(*stypes.AttributeValueMemberB)
	if !ok || !bytes.Equal(k.Value, heartbeatKey) {
		return time.Time{}, false
	}
	at, ok := r.Dynamodb.NewImage["at"].(*stypes.AttributeValueMemberN)
	if !ok {
		return time.Time{}, true
	}
	n, err := strconv.ParseInt(at.Value, 10, 64)
	if err != nil {
		return time.Time{}, true
	}
	return time.UnixMilli(n), true
}
