package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/dromas-dev/dromas-client/protocol"
)

// bodies keeps messages' bodies outside the database, each under a key
// unique to its send (bodyKey): an S3 bucket (s3Bodies) or a directory
// (dirBodies). A body's row is the authority on whether a message is live;
// a body no row names is an orphan, deleted by age (ARCHITECTURE.md
// § Storage).
type bodies interface {
	// Put stores a body under key.
	Put(ctx context.Context, key string, body []byte) error
	// Get reads a body from byte from on, where from is inside it, and
	// otherwise whole; errNoBody if there is none.
	Get(ctx context.Context, key string, from int64, size int) ([]byte, error)
	// Delete deletes bodies; one already gone is no error.
	Delete(ctx context.Context, keys ...string) error
}

// bodyKey is where a send's body is kept: its mailbox's address in its text
// form, the id, when it was received, in ms, and a nonce random to the send.
// Every send is its own key, so no write or delete of one send's body ever
// meets another's.
func bodyKey(mailbox protocol.Address, id [32]byte, receivedMs uint64, nonce []byte) string {
	return mailbox.String() + "/" + hexID(id) + "/" + strconv.FormatUint(receivedMs, 10) + "." + hex.EncodeToString(nonce)
}

// keyReceived reads when a body's send was received, from its key's last
// element; false for a name that is no body's key.
func keyReceived(name string) (time.Time, bool) {
	ms, _, ok := strings.Cut(path.Base(name), ".")
	n, err := strconv.ParseInt(ms, 10, 64)
	if !ok || err != nil || n < 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(n), true
}

// newS3 is an S3 client on cfg, each call bounded (bound).
func newS3(cfg aws.Config, opts ...func(*s3.Options)) *s3.Client {
	return s3.NewFromConfig(cfg, append([]func(*s3.Options){func(o *s3.Options) { o.APIOptions = append(o.APIOptions, bound) }}, opts...)...)
}

// bound is the one bound on each call made to S3, its retries included,
// whatever context its caller handed it: storeTimeout, as the first step of
// every operation's stack, which the SDK's documented way to change every
// call of a client is (its APIOptions). A body S3 answers with is read after
// its call returns, within the same bound, which ends when the body is
// closed.
func bound(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("dromasBound", func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
		ctx, cancel := context.WithTimeout(ctx, storeTimeout)
		out, md, err := next.HandleInitialize(ctx, in)
		if o, ok := out.Result.(*s3.GetObjectOutput); ok && err == nil && o.Body != nil {
			o.Body = cancelOnClose{o.Body, cancel}
			return out, md, err
		}
		cancel()
		return out, md, err
	}), middleware.Before)
}

// cancelOnClose is a body read within its call's bound, which ends when the
// body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

// s3Bodies keeps bodies in an S3 bucket, a directory bucket or an unversioned
// general purpose one, each call bounded (bound). Orphans go by the bucket's
// lifecycle rule.
type s3Bodies struct {
	s3     *s3.Client
	bucket string
}

func (b s3Bodies) Put(ctx context.Context, key string, body []byte) error {
	_, err := b.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: &b.bucket, Key: &key, Body: bytes.NewReader(body)})
	return err
}

// Get reads the body's bytes from byte from on with the same range
// (GetObject's Range, RFC 9110 §14.2), so a fetch that resumes moves only
// the rest out of S3.
func (b s3Bodies) Get(ctx context.Context, key string, from int64, size int) ([]byte, error) {
	in := &s3.GetObjectInput{Bucket: &b.bucket, Key: &key}
	if from > 0 && from < int64(size) {
		in.Range = aws.String(protocol.RangeAsk(from))
	}
	out, err := b.s3.GetObject(ctx, in)
	if isNoSuchKey(err) {
		return nil, errNoBody
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

func (b s3Bodies) Delete(ctx context.Context, keys ...string) error {
	for chunk := range slices.Chunk(keys, 1000) {
		objs := make([]s3types.ObjectIdentifier, 0, len(chunk))
		for _, k := range chunk {
			objs = append(objs, s3types.ObjectIdentifier{Key: aws.String(k)})
		}
		out, err := b.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &b.bucket, Delete: &s3types.Delete{Objects: objs, Quiet: aws.Bool(true)}})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			return fmt.Errorf("deleting bodies: %s", aws.ToString(out.Errors[0].Message))
		}
	}
	return nil
}

// IsThrottle reports whether err is AWS refusing for capacity: a throttle,
// or the SDK's own retry quota running out.
func IsThrottle(err error) bool {
	var q ratelimit.QuotaExceededError
	if errors.As(err, &q) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		_, ok := retry.DefaultThrottleErrorCodes[api.ErrorCode()]
		return ok
	}
	return false
}

func isNoSuchKey(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

// dataBodies is where the data directory dir keeps bodies: its bodies/.
func dataBodies(dir string) string { return filepath.Join(dir, "bodies") }

// bodySpan is how much time one directory of a dirBodies holds: the bodies
// of the sends received in one hour.
const bodySpan = time.Hour

// dirBodies keeps bodies in a directory, one file a body, at its key's path
// under the hour its send was received in (hourName), every operation held
// inside it (os.Root), a symlink placed in it included. Each is written to a
// temporary file, flushed, renamed into place and its directory flushed, so
// a body is whole or absent. A delete takes the directories it leaves empty
// with it, up to its hour's; collect removes an hour whole, once all of it
// is past its cutoff (PRECEDENTS.md Part 3, in the client repo).
type dirBodies struct{ root *os.Root }

// newDirBodies is the bodies kept under dir, made if it is not there.
func newDirBodies(dir string) (*dirBodies, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &dirBodies{root}, nil
}

// hourName is the name of the directory that holds the bodies of the sends
// received in at's hour: the hour's start, in ms since the Unix epoch, as a
// key names its send's time.
func hourName(at time.Time) string {
	ms := at.UnixMilli()
	return strconv.FormatInt(ms-ms%bodySpan.Milliseconds(), 10)
}

// file is where key's body is kept: under the hour its key names.
func (b *dirBodies) file(key string) (string, error) {
	at, ok := keyReceived(key)
	if !ok {
		return "", fmt.Errorf("no body's key: %q", key)
	}
	return hourName(at) + "/" + key, nil
}

func (b *dirBodies) Put(_ context.Context, key string, body []byte) error {
	name, err := b.file(key)
	if err != nil {
		return err
	}
	dir := path.Dir(name)
	tmp := path.Join(dir, ".put-"+randomHex(8))
	var f *os.File
	for range 2 { // a delete may take the directory, empty, between the two
		if err = b.root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if f, err = b.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	if err != nil {
		return err
	}
	defer func() { _ = b.root.Remove(tmp) }() // gone once renamed
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := b.root.Rename(tmp, name); err != nil {
		return err
	}
	d, err := b.root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func (b *dirBodies) Get(_ context.Context, key string, from int64, size int) ([]byte, error) {
	name, err := b.file(key)
	if err != nil {
		return nil, err
	}
	f, err := b.root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoBody
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if from > 0 && from < int64(size) {
		if _, err := f.Seek(from, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(f)
}

// Delete deletes each body, then each directory above it that it leaves
// empty, up to its hour's, which collect removes.
func (b *dirBodies) Delete(_ context.Context, keys ...string) error {
	for _, k := range keys {
		name, err := b.file(k)
		if err != nil {
			return err
		}
		if err := b.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for dir := path.Dir(name); strings.Contains(dir, "/"); dir = path.Dir(dir) {
			if b.root.Remove(dir) != nil { // not empty, or gone
				break
			}
		}
	}
	return nil
}

// collect removes, whole, each hour whose every send was received before
// cutoff, with whatever else is in it (a temporary file a crash left); a
// name that is no hour's is left alone. cutoff is the database's clock's, so
// no process's clock decides. It reads one directory, a name an hour, and
// several processes may collect it at once: an hour two remove is removed.
func (b *dirBodies) collect(cutoff time.Time) error {
	f, err := b.root.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		ms, err := strconv.ParseInt(n, 10, 64)
		if err != nil || ms < 0 || n != hourName(time.UnixMilli(ms)) || time.UnixMilli(ms).Add(bodySpan).After(cutoff) {
			continue
		}
		if err := b.root.RemoveAll(n); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
