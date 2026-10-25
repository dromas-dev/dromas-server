package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The AWS SDK's own lines are written through the redaction as serve and
// account create run them, not as AWSLogger alone does
// (dromas-dev/dromas-server#72, #81): each command, with its stderr
// read, loads its configuration and calls an endpoint of the test's own,
// which answers every call with a Date of 64 hex that the SDK quotes in a
// warning. Neither writes the run in the clear. No AWS is reached: the
// endpoint is local, and the keys made up.
func TestServeAndAccountWriteTheSDKsLinesRedacted(t *testing.T) {
	run := strings.Repeat("ab", 32)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", run)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), "DescribeTable") {
			_, _ = io.WriteString(w, `{"Table":{"TableName":"b"}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(endpoint.Close)
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "example", "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "",
		"AWS_ENDPOINT_URL": endpoint.URL, "AWS_CONFIG_FILE": os.DevNull, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_MAX_ATTEMPTS": "1",
		"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1", "HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "", "https_proxy": "",
	} {
		t.Setenv(k, v)
	}
	for _, c := range []struct {
		name string
		call func() error
	}{
		{"serve", func() error {
			return serve([]string{"-boxes-table", "b", "-msgs-table", "m", "-accounts-table", "a", "-bucket", "bk", "-names", "x.example", "-listen", "127.0.0.1:0"})
		}},
		{"account create", func() error { return account("create", []string{"-accounts-table", "a"}) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := stderrOf(t, c.call)
			if !strings.Contains(got, "SDK ") {
				t.Fatalf("the SDK wrote nothing, so this tests nothing:\n%s", got)
			}
			if regexp.MustCompile(`[0-9A-Fa-f]{64}`).MatchString(got) {
				t.Errorf("a run of 64 hex in the clear:\n%.600s", got)
			}
		})
	}
}

// stderrOf runs call with os.Stderr read into what it returns, and os.Stdout
// discarded: what a command writes to either it reads when it is called.
func stderrOf(t *testing.T, call func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	read := make(chan struct{})
	go func() { _, _ = io.Copy(&got, r); close(read) }()
	stderr, stdout := os.Stderr, os.Stdout
	os.Stderr, os.Stdout = w, null
	_ = call() // the commands end at the endpoint's answers: what they wrote on the way is the test
	os.Stderr, os.Stdout = stderr, stdout
	_ = w.Close()
	_ = null.Close()
	<-read
	_ = r.Close()
	return got.String()
}
