package server

// A local fake of DynamoDB's JSON protocol and S3's path-style object calls,
// on 127.0.0.1, for the DynamoDB backend to run against through the AWS SDK
// at the module's version: its retries, its retry quota, its error types,
// its HTTP client. Nothing calls AWS: the SDK's HTTP client refuses any other host.
// It came with the audit of IronGall-dev/irongall-client#349
// (IronGall-dev/irongall-server#89, #90, #91).

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// fakeAWS answers DynamoDB's JSON 1.0 protocol (POST with X-Amz-Target) and
// S3's path-style object calls on one listener. dynamo answers the n-th call
// (from 1) of an operation, s3 the n-th of a method: a status and a body, or
// drop to close the connection once the request is read (an answer lost
// after the request went out), or hang to answer nothing until the request
// or the test ends, or stall to send the status, the headers and the body,
// and then hold the rest of a body it says is longer. With no dynamo, every DynamoDB call is answered 200 {};
// with no s3, every S3 call is answered 200 and applied.
type fakeAWS struct {
	mu      sync.Mutex
	calls   map[string]int
	applied map[string]int
	dynamo  func(op string, n int, body []byte) answer
	s3      func(method string, n int) answer
	release chan struct{}
	once    sync.Once
	// record, if set, is told of each request as it arrives: its operation
	// as calls counts it, and its body.
	record func(op string, r *http.Request, body []byte)
}

type answer struct {
	status int
	body   string
	drop   bool
	hang   bool
	stall  bool
	apply  bool // the call's write is applied, whatever is answered
}

func newFakeAWS() *fakeAWS {
	return &fakeAWS{calls: map[string]int{}, applied: map[string]int{}, release: make(chan struct{})}
}

// count is how many calls of op were made, and how many of them applied.
func (f *fakeAWS) count(op string) (calls, applied int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op], f.applied[op]
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	op, kind := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "DynamoDB_20120810."), "application/x-amz-json-1.0"
	if op == "" {
		op, kind = "S3 "+r.Method, "application/xml"
	}
	f.mu.Lock()
	f.calls[op]++
	n := f.calls[op]
	f.mu.Unlock()
	if f.record != nil {
		f.record(op, r, body)
	}
	a := answer{status: http.StatusOK, body: "{}"}
	switch {
	case strings.HasPrefix(op, "S3 ") && f.s3 != nil:
		a = f.s3(r.Method, n)
	case strings.HasPrefix(op, "S3 "):
		a.body, a.apply = "", true
	case f.dynamo != nil:
		a = f.dynamo(op, n, body)
	}
	if a.apply {
		f.mu.Lock()
		f.applied[op]++
		f.mu.Unlock()
	}
	switch {
	case a.hang:
		select {
		case <-f.release:
		case <-r.Context().Done():
		}
		// Never an answer, even as the test ends: a handler that returned
		// would answer 200 with no body, which the SDK reads as a success.
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
		return
	case a.drop:
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
		return
	}
	w.Header().Set("Content-Type", kind)
	if strings.HasPrefix(op, "S3 ") && a.status == http.StatusOK {
		w.Header().Set("ETag", `"0"`)
	}
	if a.stall {
		w.Header().Set("Content-Length", strconv.Itoa(len(a.body)+1))
	}
	w.WriteHeader(a.status)
	_, _ = io.WriteString(w, a.body)
	if a.stall {
		w.(http.Flusher).Flush()
		select {
		case <-f.release:
		case <-r.Context().Done():
		}
	}
}

// dynErr is DynamoDB's error body for code, as its JSON protocol writes it;
// extra is more members, each led by a comma.
func dynErr(code string, extra string) string {
	ns := "com.amazonaws.dynamodb.v20120810#"
	if code == "ValidationException" {
		ns = "com.amazon.coral.validate#"
	}
	return fmt.Sprintf(`{"__type":"%s%s","message":"%s"%s}`, ns, code, code, extra)
}

// s3Err is S3's error body for code.
func s3Err(code string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>` + code + `</Message><RequestId>fake</RequestId></Error>`
}

// onlyHost refuses any request to a host but the fake's.
type onlyHost struct {
	host string
	rt   http.RoundTripper
}

func (o onlyHost) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != o.host {
		return nil, fmt.Errorf("fakeAWS: refused a request to %s", r.URL.Host)
	}
	return o.rt.RoundTrip(r)
}

// fakeStore is the store on DynamoDB over f, with a record cache and the
// SDK's default retryer, as irongalld's config.LoadDefaultConfig leaves it:
// its attempts, quota and what it retries, with no pause between attempts, so
// a test of a retried write waits for nothing the SDK's jitter would add.
func fakeStore(t testing.TB, f *fakeAWS) *Memory {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(func() {
		f.once.Do(func() { close(f.release) })
		srv.Close()
	})
	host := strings.TrimPrefix(srv.URL, "http://")
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	t.Cleanup(tr.CloseIdleConnections)
	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDFAKE", "fake", ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   &http.Client{Transport: onlyHost{host: host, rt: tr}},
		Retryer: func() aws.Retryer {
			return retry.AddWithMaxBackoffDelay(retry.NewStandard(), time.Millisecond)
		},
	}
	s := NewDynamoStore(DynamoConfig{AWS: cfg, BoxesTable: "boxes", MsgsTable: "msgs", AccountsTable: "accounts", Bucket: "bodies", BoxCache: 16})
	s.dynamo().s3 = newS3(cfg, func(o *s3.Options) { o.UsePathStyle = true })
	return s
}

// heldRecord is a registered box's record, from the suite's store.
func heldRecord(t *testing.T) (*env, *raw, *Box) {
	t.Helper()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	b, err := e.store.Box(t.Context(), r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	return e, r, b
}

// faultOf is err's API error code and the fault the SDK gave it.
func faultOf(err error) string {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return "no APIError"
	}
	return fmt.Sprintf("%s fault %d", api.ErrorCode(), api.ErrorFault())
}
