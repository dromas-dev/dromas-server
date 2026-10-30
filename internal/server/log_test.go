package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	"github.com/aws/smithy-go/logging"
	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// errorWithURL is the test store, but a read of mailbox's record fails with the
// text of an S3 transport error: the request's URL, which names the mailbox and
// a message id.
type errorWithURL struct {
	Store
	mailbox protocol.Address
	id      string
}

func (s errorWithURL) Known(a protocol.Address) (*Mailbox, bool) {
	if a == s.mailbox {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s errorWithURL) Mailbox(ctx context.Context, a protocol.Address) (*Mailbox, error) {
	if a == s.mailbox {
		return nil, fmt.Errorf(`operation error S3: PutObject, request send failed, Put "http://127.0.0.1:1/bucket/%s/%s?x-id=PutObject": dial tcp 127.0.0.1:1: connect: connection refused`, a, s.id)
	}
	return s.Store.Mailbox(ctx, a)
}

// deadS3 is the test store, but a send is stored by a store on DynamoDB whose S3
// is a closed port: its PutMessage fails as a real S3 client does when it
// cannot connect.
type deadS3 struct {
	Store
	d *Memory
}

func (s deadS3) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	return s.d.PutMessage(ctx, mailbox, h, body)
}

// No line the server logs carries an address or a message id
// (dromas-dev/dromas-server#9, SECURITY.md): not a store's
// error, whose text holds a request's URL, not a real S3 client's, and not
// a path that holds one inside a longer segment or in capitals. A line
// about the mailbox names it by the name redact gives it, so the store's error
// and the access line of its read match; a path's segment that is not the
// address is named as a whole (loggedPath), the address inside it unseen.
func TestNoLogLineCarriesAnAddress(t *testing.T) {
	t.Parallel()
	var logged bytes.Buffer
	var a protocol.Address
	a[0], a[31] = 0xab, 0xcd
	id := strings.Repeat("ef", 32)
	s := New(Config{Store: errorWithURL{NewMemStore(time.Now), a, id}, Limits: relaxed(), Now: time.Now, Log: log.New(&logged, "", 0)})
	h := apitest.Handler(t, s.Handler())
	for _, p := range []string{"/v1/" + a.String(), "/v1/" + a.String() + "x", "/v1/x" + strings.ToUpper(a.String())} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	name := string(redact([]byte(a.String())))
	if lines := strings.Count(logged.String(), name); strings.Contains(strings.ToLower(logged.String()), a.String()) || strings.Contains(strings.ToLower(logged.String()), id) || lines != 2 {
		t.Errorf("the log names the mailbox %d times, and holds it or the id in the clear:\n%s", lines, logged.String())
	}

	// A real S3 client's error, its URL as it writes it.
	var sdk bytes.Buffer
	d := NewDynamoStore(DynamoConfig{AWS: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		BaseEndpoint: aws.String("http://127.0.0.1:1"), RetryMaxAttempts: 1}, MailboxesTable: "b", MessagesTable: "m", AccountsTable: "a", Bucket: "bucket", Log: log.New(&sdk, "", 0)})
	logged.Reset()
	e := newEnv(t, relaxed(), func(c *Config) { c.Store, c.Log = deadS3{c.Store, d}, log.New(&logged, "", 0) })
	from, to := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	if _, err := from.Send(context.Background(), to.Address(), "never stored"); err == nil {
		t.Fatal("a send stored through a closed port")
	}
	var line string
	for l := range strings.Lines(logged.String()) {
		if strings.HasPrefix(l, "internal error: ") {
			line = l
		}
	}
	if !strings.Contains(line, "PutObject") || strings.Contains(line, to.Address().String()) || !strings.Contains(line, string(redact([]byte(to.Address().String())))) {
		t.Errorf("a real S3 client's error, logged: %q, in:\n%s", line, logged.String())
	}
}

// The access log writes one line a request, built from what the routers
// matched and never from the path as sent (dromas-dev/dromas-server#11,
// #62): a route's pattern, each wildcard's value as logName names it,
// whatever the value holds; a site's page as the site's pattern and its
// path's length; and a path no route answered by its length alone. So
// nothing a caller sent can end a line, pass for the server's own words,
// make it longer, or put an address in it past the redaction, an address
// with one character escaped among them, which the router decodes and a
// run of hex in the path as sent would split. A method is written as it
// came only in the form of the IANA method registry's, capitals and
// hyphens, and no longer than the longest method it lists; any other is
// written as its length alone, so it can carry no address split by a
// character a token may hold, no run of 63 hex, no name that reads as one
// redact gives (#79), and no run of 64 of the capitals A to F, which redact
// would write as such a name (dromas-dev/dromas-client#413 item 1).
// The server is not wrapped in apitest: a site's pages are a deployment's
// web server's, which api/openapi.yaml does not describe (site_test.go's
// are not either).
func TestTheAccessLogWritesWhatTheRoutersMatched(t *testing.T) {
	t.Parallel()
	site := t.TempDir()
	page := strings.Repeat("p", 200) + ".html"
	if err := os.WriteFile(filepath.Join(site, page), []byte("<p>a page</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	s := New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Now: time.Now, Log: log.New(&logged, "", log.LstdFlags), SiteBackend: backendOf(t, http.FileServer(http.Dir(site)))})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	request := func(method, path string) string {
		t.Helper()
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		logged.Reset()
		if _, err := fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", method, path); err != nil {
			t.Fatal(err)
		}
		if _, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(c).ReadString(0) // until the server has closed: the line is written
		if n := strings.Count(logged.String(), "\n"); n != 1 {
			t.Fatalf("%s %.80s: %d lines logged:\n%s", method, path, n, logged.String())
		}
		line := strings.SplitN(logged.String(), " ", 3)[2] // past the time
		if hexRun.MatchString(line) {
			t.Errorf("%s %.80s: a run of hex in the line: %q", method, path, line)
		}
		return line
	}
	var a protocol.Address
	a[0] = 1
	mailbox := logName([]byte(a.String()))
	id := strings.Repeat("ab", 32)
	forged := "/v1/x%0A2026/10/13%2012:00:00%20store%20throttled:%20boom%0D%00%1B[2J%E2%80%AE"
	for _, c := range []struct{ method, path, want string }{
		{"GET", forged, fmt.Sprintf("GET (a path of %d bytes) 404 ", len(forged))},
		{"GET", "/v1/" + a.String() + "/messages/" + id, "GET /v1/" + mailbox + "/messages/" + logName([]byte(id)) + " "},
		{"GET", "/v1/" + a.String()[:20] + "%" + fmt.Sprintf("%02x", a.String()[20]) + a.String()[21:] + "/messages", "GET /v1/" + mailbox + "/messages "},
		{"GET", "/v1/" + strings.ToUpper(a.String()) + "/acl", "GET /v1/" + mailbox + "/acl "},
		{"GET", "/v1/%2e%2e/x", "GET (a path of 12 bytes) 404 "},
		{"GET", "/v1/x%2Fy", "GET /v1/" + logName([]byte("x/y")) + " "},
		{"GET", "/v1/%41", "GET /v1/" + logName([]byte("A")) + " "},
		{"GET", "/" + page, "GET / (a path of 206 bytes) 200 "},
		{"GET", "/" + strings.Repeat("q/", 150), "GET / (a path of 301 bytes) 404 "},
		{"GET", "/v1/" + strings.Repeat(a.String(), 1<<12), fmt.Sprintf("GET /v1/%s ", logName([]byte(strings.Repeat(a.String(), 1<<12))))},
		{strings.Repeat("A", 1<<16), "/v1/x", fmt.Sprintf("(a method of %d bytes) (a path of 5 bytes) ", 1<<16)},
		{"PROPFIND", "/v1/x", "PROPFIND (a path of 5 bytes) 405 "},
		{"VERSION-CONTROL", "/v1/x", "VERSION-CONTROL (a path of 5 bytes) 405 "},
		{"UPDATEREDIRECTREF", "/v1/x", "UPDATEREDIRECTREF (a path of 5 bytes) 405 "},
		{"UPDATEREDIRECTREFS", "/v1/x", "(a method of 18 bytes) (a path of 5 bytes) 405 "},
		{strings.Repeat("ABCDEF", 11), "/v1/x", "(a method of 66 bytes) (a path of 5 bytes) 405 "},
		{strings.Repeat("FACADE", 11) + "-" + strings.Repeat("DECADE", 11), "/v1/x", "(a method of 133 bytes) (a path of 5 bytes) 405 "},
		{a.String()[:32] + "-" + a.String()[32:], "/v1/x", "(a method of 65 bytes) (a path of 5 bytes) 405 "},
		{a.String()[:32] + "." + a.String()[32:], "/v1/x", "(a method of 65 bytes) (a path of 5 bytes) 405 "},
		{a.String()[:32] + "_" + a.String()[32:], "/v1/x", "(a method of 65 bytes) (a path of 5 bytes) 405 "},
		{a.String()[:63], "/v1/x", "(a method of 63 bytes) (a path of 5 bytes) 405 "},
		{mailbox, "/v1/x", "(a method of 17 bytes) (a path of 5 bytes) 405 "},
		{"get", "/v1/x", "(a method of 3 bytes) (a path of 5 bytes) 405 "},
	} {
		if got := request(c.method, c.path); !strings.HasPrefix(got, c.want) {
			t.Errorf("%.20s %.80s: %q, want it from %q", c.method, c.path, got, c.want)
		}
	}
}

// AWSLogger writes the AWS SDK's own lines through the redaction
// (dromas-dev/dromas-server#72). That serve and account load their
// configuration with it is held in cmd/dromas-server, where they run
// (TestServeAndAccountWriteTheSDKsLinesRedacted, #81).
func TestTheAWSSDKsLinesAreRedacted(t *testing.T) {
	t.Parallel()
	var logged bytes.Buffer
	run := strings.Repeat("ab", 32)
	AWSLogger(&logged).Logf(logging.Warn, "a response's Date: %s", run)
	if strings.Contains(logged.String(), run) || !strings.Contains(logged.String(), logName([]byte(run))) {
		t.Errorf("the SDK's line: %q", logged.String())
	}
}

// panicStreams is a stream that panics, with a message id in its words.
type panicStreams struct{ streamsAPI }

func (panicStreams) DescribeStream(context.Context, *dynamodbstreams.DescribeStreamInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error) {
	panic("boom at " + strings.Repeat("cd", 32))
}

// A stream follower that panics is logged through the store's log, which
// redacts, and ends the process as a lost place does, so a restart rebuilds
// memory: never its words on stderr, past the redaction.
func TestAFollowersPanicIsLoggedRedactedAndEndsTheProcess(t *testing.T) {
	t.Parallel()
	var logged bytes.Buffer
	l := redacting(log.New(&logged, "", 0))
	f := &feed{streams: panicStreams{}, interval: time.Hour, logf: l.Printf, shards: map[string]*shard{}}
	var ended error
	f.run(context.Background(), func(err error) { ended = err })
	if ended == nil || !strings.Contains(ended.Error(), "panic") {
		t.Fatalf("the follower's panic ended nothing: %v", ended)
	}
	if !strings.Contains(logged.String(), "stream: panic") || strings.Contains(logged.String(), strings.Repeat("cd", 32)) {
		t.Errorf("the panic's line: %q", logged.String())
	}
}
