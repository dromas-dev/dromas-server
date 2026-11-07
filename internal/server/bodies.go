package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
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
// form, the id, and when it was received, in ms. The same ciphertext sent
// again is a new key, so no write or delete of one send's body ever meets
// another's.
func bodyKey(mailbox protocol.Address, id [32]byte, receivedMs uint64) string {
	return mailbox.String() + "/" + hexID(id) + "/" + strconv.FormatUint(receivedMs, 10)
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

// s3Bodies keeps bodies in an S3 bucket, a directory bucket or a general
// purpose one, each call bounded (bound). Orphans go by the bucket's
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

// dirBodies keeps bodies in a directory, one file a body at its key's path,
// every operation held inside it (os.Root), a symlink placed in it included.
// Each is written to a temporary file, flushed, renamed into place and its
// directory flushed, so a body is whole or absent. Orphans go by collect.
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

func (b *dirBodies) Put(_ context.Context, key string, body []byte) error {
	dir := path.Dir(key)
	tmp := path.Join(dir, ".put-"+randomHex(8))
	var f *os.File
	var err error
	for range 2 { // collect may take the directory, empty, between the two
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
	if err := b.root.Rename(tmp, key); err != nil {
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
	f, err := b.root.Open(key)
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

func (b *dirBodies) Delete(_ context.Context, keys ...string) error {
	for _, k := range keys {
		if err := b.root.Remove(k); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// collect deletes every body last written before cutoff, and the
// directories left empty: an orphan, or a body whose message has expired.
// Several processes may collect one directory at once.
func (b *dirBodies) collect(cutoff time.Time) error {
	return fs.WalkDir(b.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return err
		case d.IsDir():
			if p != "." {
				_ = b.root.Remove(p) // only if empty; a later pass takes one emptied now
			}
			return nil
		}
		info, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.ModTime().Before(cutoff) {
			if err := b.root.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
}
