package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// heartbeatRecord is the stream's record of a heartbeat item of the table
// whose partition key is pk and sort key sk, dated at.
func heartbeatRecord(pk, sk string, at time.Time) stypes.Record {
	keys := map[string]stypes.AttributeValue{pk: &stypes.AttributeValueMemberB{Value: heartbeatKey}, sk: &stypes.AttributeValueMemberB{Value: heartbeatKey}}
	img := map[string]stypes.AttributeValue{"at": &stypes.AttributeValueMemberN{Value: strconv.FormatInt(at.UnixMilli(), 10)}}
	for k, v := range keys {
		img[k] = v
	}
	return stypes.Record{EventName: stypes.OperationTypeModify, Dynamodb: &stypes.StreamRecord{Keys: keys, NewImage: img}}
}

// A stream that stalls answers empty pages, which read as an idle stream's:
// without a heartbeat the follower stays current through the stall; with
// one, it is current only while it applies a heartbeat dated recently, so it
// is not current until it has read past the stall to one written after it.
func TestAStalledStreamIsNotCurrentWithAHeartbeat(t *testing.T) {
	t.Parallel()
	for _, beat := range []time.Duration{0, 15 * time.Second} {
		now := time.Now()
		fs := &fakeStream{}
		fs.open("only", "")
		var changed []Change
		d := &dynamoBackend{streams: fs, interval: time.Second, heartbeatEvery: beat, apply: func(c Change) { changed = append(changed, c) }}
		f := d.newFeed("mailboxes", "addr", mailboxStreamChange)
		f.clock = func() time.Time { return now }
		if err := f.position(context.Background(), "arn"); err != nil {
			t.Fatal(err)
		}
		// A minute of passes over a stalled stream, each an empty page.
		for range 60 {
			now = now.Add(time.Second)
			if err := f.once(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if beat == 0 {
			if !f.current(now) {
				t.Fatal("not current without a heartbeat: the stall reads as an idle stream")
			}
			continue
		}
		if f.current(now) {
			t.Fatalf("current after a minute of a stalled stream, with a heartbeat each %s", beat)
		}
		// The stream comes back: first the heartbeats written during the stall,
		// which date it, then one written now.
		fs.write("only", heartbeatRecord("addr", "sk", now.Add(-50*time.Second)))
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.current(now) {
			t.Fatal("current on a heartbeat written during the stall")
		}
		fs.write("only", heartbeatRecord("addr", "sk", now.Add(-time.Second)))
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !f.current(now) {
			t.Fatal("not current on a heartbeat written a second ago")
		}
		// A heartbeat is no change to memory, and an older one read late
		// moves nothing back.
		fs.write("only", heartbeatRecord("addr", "sk", now.Add(-time.Hour)))
		if err := f.once(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(changed) != 0 || !f.current(now) {
			t.Fatalf("%d changes applied, current %v: want none, and current", len(changed), f.current(now))
		}
	}
}

// Each table's heartbeat is read as one by its own follower, under its own
// partition key, and by no other.
func TestEachTablesHeartbeatIsItsFollowers(t *testing.T) {
	t.Parallel()
	at := time.UnixMilli(1792843200000)
	for _, b := range []struct{ pk, sk string }{{"addr", "sk"}, {"box", "id"}, {"account", "sk"}} {
		r := heartbeatRecord(b.pk, b.sk, at)
		for _, tb := range (&dynamoBackend{mailboxes: "m", msgs: "s", accts: "a"}).beatTables() {
			got, ok := heartbeatOf(r, tb.pk)
			if ok != (tb.pk == b.pk) || ok && !got.Equal(at) {
				t.Errorf("a heartbeat keyed %s read under %s: %v, %v", b.pk, tb.pk, got, ok)
			}
		}
	}
	// A mailbox's record, a message and an account are no heartbeat, even
	// dated as one.
	for _, b := range []struct {
		pk  string
		key []byte
	}{{"addr", make([]byte, 48)}, {"box", make([]byte, 48)}, {"account", []byte("an-account")}} {
		r := heartbeatRecord(b.pk, "sk", at)
		r.Dynamodb.Keys[b.pk] = &stypes.AttributeValueMemberB{Value: b.key}
		if _, ok := heartbeatOf(r, b.pk); ok {
			t.Errorf("an item keyed %s %x is read as a heartbeat", b.pk, b.key)
		}
	}
}
