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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// The AWS SDK's own lines are written through the redaction with the
// configuration serve makes for --bucket (loadAWS; dromas-dev/dromas-server#72,
// #81): a call of a bucket at an endpoint of the test's own, which answers
// with a Date of 64 hex that the SDK quotes in a warning, writes the run in
// the clear nowhere. No AWS is reached: the endpoint is local, and the keys
// made up.
func TestServeWritesTheSDKsLinesRedacted(t *testing.T) {
	run := strings.Repeat("ab", 32)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", run)
		w.WriteHeader(http.StatusNotFound)
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
	got := stderrOf(t, func() error {
		cfg, err := loadAWS(t.Context(), "us-east-1")
		if err != nil {
			return err
		}
		_, err = s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true }).GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String("bk"), Key: aws.String("k")})
		return err
	})
	if !strings.Contains(got, "SDK ") {
		t.Fatalf("the SDK wrote nothing, so this tests nothing:\n%s", got)
	}
	if regexp.MustCompile(`[0-9A-Fa-f]{64}`).MatchString(got) {
		t.Errorf("a run of 64 hex in the clear:\n%.600s", got)
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
