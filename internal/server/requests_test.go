package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

var update = flag.Bool("update", false, "write testdata/aws-requests.golden again from what the store sends")

// Every store call sends AWS the requests it sent when
// testdata/aws-requests.golden was written: each operation, table, index,
// key, condition, update, projection, consistency and value, in order, read
// from the wire by the fake. What the store holds in memory and how it reads
// an outcome may change; what DynamoDB and S3 are asked may not, unless the
// change means to, and then `go test ./internal/server -run
// TestEveryStoreCallSendsAWSWhatItSentBefore -update` writes the file again
// and each changed line is read before it is committed. A transaction's
// client token is random, and left out.
func TestEveryStoreCallSendsAWSWhatItSentBefore(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	mailbox, other := protocol.Address{0xb0, 1}, protocol.Address{0xb1, 2}
	id := [32]byte{0x1d, 4}
	received := now.Add(-time.Hour)
	b64 := base64.StdEncoding.EncodeToString
	f := newFakeAWS()
	var mu sync.Mutex
	var got bytes.Buffer
	f.record = func(op string, r *http.Request, body []byte) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(op, "S3 ") {
			fmt.Fprintf(&got, "%s %s?%s", op, r.URL.Path, r.URL.Query().Encode())
			if v := r.Header.Get("Range"); v != "" {
				fmt.Fprintf(&got, " Range: %s", v)
			}
			if r.Method == http.MethodPost {
				fmt.Fprintf(&got, "\n%s", body)
			}
			got.WriteString("\n")
			return
		}
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			t.Errorf("%s: %v", op, err)
			return
		}
		delete(v, "ClientRequestToken")
		out, _ := json.MarshalIndent(v, "", " ")
		fmt.Fprintf(&got, "%s %s\n", op, out)
	}
	// A message of the mailbox's, live, as the live index and the messages table
	// hold it; every other DynamoDB call is answered {}.
	live := fmt.Sprintf(`"box":{"B":%q},"id":{"B":%q},"live":{"B":%q},"size":{"N":"100"}`,
		b64(mailbox[:]), b64(id[:]), b64(liveKey(ms(received), id)))
	// And a mailbox record, a registered mailbox's under the address other, to every
	// Query of the mailboxes table, so that a mailbox's load reads its live entries.
	_, _, held := heldRecord(t)
	held.Addr = other
	record, err := json.Marshal(map[string]any{"Count": 1, "Items": []any{avJSON(&types.AttributeValueMemberM{Value: mailboxItem(held)})["M"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.dynamo = func(op string, _ int, body []byte) answer {
		var in struct{ TableName, IndexName string }
		_ = json.Unmarshal(body, &in)
		switch {
		case op == "Query" && in.TableName == "mailboxes":
			return answer{status: http.StatusOK, body: string(record)}
		case op == "Query" && in.IndexName == liveIndex:
			return answer{status: http.StatusOK, body: `{"Count":1,"Items":[{` + live + `}]}`}
		case op == "GetItem" && in.TableName == "msgs":
			return answer{status: http.StatusOK, body: `{"Item":{` + live + `,"received_at":{"N":"` + strconv.FormatUint(ms(received), 10) + `"}}}`}
		}
		return answer{status: http.StatusOK, body: "{}"}
	}
	s := fakeStore(t, f)
	s.now = func() time.Time { return now }

	rec := &Mailbox{
		Addr: mailbox, Identity: []byte("an identity document"), State: Active,
		Statement: []byte("a prekey statement"), Signature: []byte("its signature"),
		Rank: 7, Signer: [32]byte{0xce, 5}, SenderKeyTypes: []string{"ssh-ed25519"},
		Retired: []Retired{{Type: protocol.PostQuantum, NotAfter: now.Add(24 * time.Hour), KeyHash: [32]byte{0x4b, 6}}},
		Rev:     3, Created: now.Add(-48 * time.Hour), Expires: now.Add(60 * 24 * time.Hour),
		ACL: &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{other})},
	}
	h := &Header{ID: id, Size: 100, ReceivedAt: received, ExpiresAt: received.Add(protocol.Retention)}
	ctx := t.Context()
	calls := []struct {
		name string
		call func()
	}{
		{"CreateMailbox", func() { c := cloneMailbox(rec); _ = s.CreateMailbox(ctx, c) }},
		{"UpdateMailbox", func() { c := cloneMailbox(rec); _ = s.UpdateMailbox(ctx, c) }},
		{"Revoke, the address and certificates through 9", func() {
			_ = s.Revoke(ctx, mailbox, &Revocations{Identity: rec.Identity, Address: []byte("a revocation"), Certs: []byte("certificates"), CertsSig: []byte("their signature"), Through: 9}, ExpectAnything)
		}},
		{"Revoke, the address alone", func() {
			_ = s.Revoke(ctx, mailbox, &Revocations{Identity: rec.Identity, Address: []byte("a revocation")}, ExpectAnything)
		}},
		{"Revoke, certificates through 9, where none is held (If-None-Match: *)", func() {
			_ = s.Revoke(ctx, mailbox, &Revocations{Identity: rec.Identity, Certs: []byte("certificates"), CertsSig: []byte("their signature"), Through: 9}, ExpectNone)
		}},
		{"Revoke, the address, where some are held (If-Match: *)", func() {
			_ = s.Revoke(ctx, mailbox, &Revocations{Identity: rec.Identity, Address: []byte("a revocation")}, ExpectHeld)
		}},
		{"Mailbox", func() { _, _ = s.Mailbox(ctx, other) }},
		{"Reread", func() { _, _ = s.Reread(ctx, other) }},
		{"Count, the mailbox's load", func() { _, _ = s.Count(ctx, other) }},
		{"Dedupe", func() { _, _ = s.Dedupe(ctx, mailbox, id) }},
		{"PutMessage", func() { _, _ = s.PutMessage(ctx, mailbox, h, []byte("a ciphertext")) }},
		{"List, from the start", func() { _, _ = s.List(ctx, mailbox, nil, 50, false) }},
		{"List, from the start, strongly consistent (a held list's)", func() { _, _ = s.List(ctx, mailbox, nil, 50, true) }},
		{"List, after a cursor", func() { _, _ = s.List(ctx, mailbox, &Cursor{ReceivedAt: received, ID: id}, 50, false) }},
		{"Message, whole", func() { _, _, _ = s.Message(ctx, mailbox, id, 0) }},
		{"Message, from byte 40", func() { _, _, _ = s.Message(ctx, mailbox, id, 40) }},
		{"DeleteMessage", func() { _ = s.DeleteMessage(ctx, mailbox, id) }},
		{"DeleteMessages", func() { _ = s.DeleteMessages(ctx, mailbox) }},
		{"DeleteMailbox", func() { _ = s.DeleteMailbox(ctx, mailbox) }},
		{"Account", func() { _, _ = s.Account(ctx, "an account") }},
		{"CreateAccount", func() { _ = s.CreateAccount(ctx, &Account{ID: "an account", Unmetered: true}) }},
		{"PutAdoptKey", func() {
			_ = s.PutAdoptKey(ctx, &AdoptKey{Account: "an account", Hash: [32]byte{0xad, 7}, Uses: 2, Expires: now.Add(time.Hour)})
		}},
		{"AdoptKey", func() { _, _ = s.AdoptKey(ctx, "an account", [32]byte{0xad, 7}) }},
		{"Adopt", func() { c := cloneMailbox(rec); _ = s.Adopt(ctx, c, "an account", [32]byte{0xad, 7}) }},
		{"Leave", func() { c := cloneMailbox(rec); c.Account = "an account"; _ = s.Leave(ctx, c) }},
	}
	for _, c := range calls {
		mu.Lock()
		fmt.Fprintf(&got, "## %s\n", c.name)
		mu.Unlock()
		c.call()
	}
	golden := filepath.Join("testdata", "aws-requests.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil { //nolint:gosec // a test's golden file
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v: write it with -update", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		gl, wl := strings.Split(got.String(), "\n"), strings.Split(string(want), "\n")
		for i := range max(len(gl), len(wl)) {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("the requests differ from %s at line %d:\n got: %s\nwant: %s", golden, i+1, g, w)
			}
		}
	}
}

// avJSON is an attribute value as DynamoDB's JSON protocol writes it.
func avJSON(v types.AttributeValue) map[string]any {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return map[string]any{"B": base64.StdEncoding.EncodeToString(v.Value)}
	case *types.AttributeValueMemberN:
		return map[string]any{"N": v.Value}
	case *types.AttributeValueMemberS:
		return map[string]any{"S": v.Value}
	case *types.AttributeValueMemberBOOL:
		return map[string]any{"BOOL": v.Value}
	case *types.AttributeValueMemberL:
		l := make([]any, 0, len(v.Value))
		for _, e := range v.Value {
			l = append(l, avJSON(e))
		}
		return map[string]any{"L": l}
	case *types.AttributeValueMemberM:
		m := make(map[string]any, len(v.Value))
		for k, e := range v.Value {
			m[k] = avJSON(e)
		}
		return map[string]any{"M": m}
	}
	panic(fmt.Sprintf("avJSON: %T", v))
}
