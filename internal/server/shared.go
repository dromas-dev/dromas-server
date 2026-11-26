package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
)

// SharedWait bounds each call to the shared store, which is a round trip to
// a store in memory beside the processes: past it, the store is slow, and
// the count is the process's own (sharedBuckets). It is a send's wait at
// most, beside a send's own write to the database. Every call is made, as
// Let's Encrypt's Boulder makes each to its Redis with a timeout of its own
// and no circuit breaker (ratelimits/source_redis.go): so while the store
// hangs, each take waits up to SharedWait, and so does each give-back.
const SharedWait = 50 * time.Millisecond

// sharedBuckets keeps the times of a bucket set in Valkey, which every
// process of a deployment reaches: a key's bucket is then one across them
// all, as Let's Encrypt's Boulder keeps each key's GCRA time in Redis for
// every instance (ratelimits/source_redis.go), where a process's own buckets
// give each process a bucket of its own. Each time is the key's value, in
// whole microseconds since the Unix epoch, and the key expires when the
// bucket is full again: a key that is gone is a full bucket, as in memory
// (buckets.prune). The store holds nothing on disk (its persistence is off,
// ARCHITECTURE.md § The shared store).
//
// A call that fails or takes past SharedWait is counted in the process's own
// buckets instead, as if there were no store: the process's own buckets
// count every take either way, so what they hold then is what that process
// alone has spent.
type sharedBuckets struct {
	c      valkey.Client
	prefix string
	log    *log.Logger
	m      *Metrics
	// wait bounds each call: SharedWait.
	wait time.Duration
	// down is set while the store has not answered since it failed.
	down atomic.Bool
}

// OpenValkey is the client of the Valkey at url (valkey://[user@]host:port),
// with password, when set, as its password: given apart from the URL, so a
// secret need not sit in a command line or a file that names the store, and
// refused where the URL carries one too. It is made whether or not the store
// answers yet: a call to it that fails is counted by the process alone
// (Config.Valkey), and the client dials again on its next call. A store that
// answers and refuses the password is an operator's misconfiguration, and
// refuses the start. A client-side cache is off, since every read must be
// the store's; retries are off, since a failed call falls back at once.
func OpenValkey(url, password string) (valkey.Client, error) {
	opt, err := valkey.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if password != "" {
		if opt.Password != "" {
			return nil, errors.New("a password in the URL and another given apart: give one")
		}
		opt.Password = password
	}
	opt.ForceSingleClient = true
	opt.DisableCache = true
	opt.DisableRetry = true
	opt.Dialer.Timeout = SharedWait
	c, err := valkey.NewClient(opt)
	if c == nil {
		return nil, fmt.Errorf("no client: %w", err)
	}
	if _, refused := valkey.IsValkeyErr(err); refused {
		c.Close()
		return nil, fmt.Errorf("the store refused this client: %w", err)
	}
	return c, nil // any other err, a first dial that failed, is the first call's to report
}

func newSharedBuckets(c valkey.Client, name string, l *log.Logger, m *Metrics) *sharedBuckets {
	return &sharedBuckets{c: c, prefix: "dromas:" + name + ":", log: l, m: m, wait: SharedWait}
}

// takeScript takes a token for KEYS[1] at ARGV[1], a bucket of ARGV[3]
// tokens, one back each ARGV[2] microseconds: buckets.next, in one step of
// the store. It answers {1, 0} for a token taken and {0, over} for none,
// over being how far past a full bucket the take would have put it.
var takeScript = valkey.NewLuaScript(`
local now, every, n = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local full = tonumber(redis.call('GET', KEYS[1]) or '0')
if full < now then full = now end
local nxt = full + every
local over = nxt - now - n * every
if over > 0 then return {0, over} end
redis.call('SET', KEYS[1], string.format('%d', nxt), 'PXAT', string.format('%d', math.ceil(nxt / 1000)))
return {1, 0}
`)

// giveScript puts back a token of KEYS[1] at ARGV[1], ARGV[2] microseconds
// each: buckets.giveLocked, in one step of the store.
var giveScript = valkey.NewLuaScript(`
local now, every = tonumber(ARGV[1]), tonumber(ARGV[2])
local full = tonumber(redis.call('GET', KEYS[1]))
if not full then return 0 end
full = full - every
if full > now then
  redis.call('SET', KEYS[1], string.format('%d', full), 'PXAT', string.format('%d', math.ceil(full / 1000)))
else
  redis.call('DEL', KEYS[1])
end
return 1
`)

// up reports whether a call to the store is made: sh is set.
func (sh *sharedBuckets) up() bool { return sh != nil }

// done records a call's outcome. A failure, the store's own error or its
// deadline, leaves the call to the process's own count, and the log says so
// once until the store answers again.
func (sh *sharedBuckets) done(op string, start time.Time, err error) error {
	sh.m.sharedCall(op, err, time.Since(start))
	if err == nil {
		if sh.down.Swap(false) && sh.log != nil {
			sh.log.Printf("the shared store answers again: %scounted across processes", sh.prefix)
		}
		return nil
	}
	if !sh.down.Swap(true) && sh.log != nil {
		sh.log.Printf("the shared store failed (%v): %scounted by each process alone until it answers", err, sh.prefix)
	}
	return err
}

func micros(t time.Time) string       { return strconv.FormatInt(t.UnixMicro(), 10) }
func microsOf(d time.Duration) string { return strconv.FormatInt(d.Microseconds(), 10) }

// take takes a token for key at now, in a bucket of n, one back every
// interval, as buckets.next does: ok, or how long until a token is due.
func (sh *sharedBuckets) take(ctx context.Context, key string, n int, every time.Duration, now time.Time) (ok bool, over time.Duration, err error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, sh.wait)
	defer cancel()
	res, err := takeScript.Exec(ctx, sh.c, []string{sh.prefix + key}, []string{micros(now), microsOf(every), strconv.Itoa(n)}).AsIntSlice()
	if err == nil && len(res) != 2 {
		err = fmt.Errorf("the take answered %d values", len(res))
	}
	if err = sh.done("take", start, err); err != nil {
		return false, 0, err
	}
	return res[0] == 1, time.Duration(res[1]) * time.Microsecond, nil
}

// give puts back a token taken for key, as buckets.giveLocked does. A give
// that fails is not made again: that token stays spent.
func (sh *sharedBuckets) give(key string, every time.Duration, now time.Time) {
	if !sh.up() {
		return
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sh.wait)
	defer cancel()
	err := giveScript.Exec(ctx, sh.c, []string{sh.prefix + key}, []string{micros(now), microsOf(every)}).Error()
	_ = sh.done("give", start, err)
}

// full is the time key's bucket is full again, the zero time for a full
// one, and whether the store answered.
func (sh *sharedBuckets) full(key string) (time.Time, bool) {
	if !sh.up() {
		return time.Time{}, false
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sh.wait)
	defer cancel()
	v, err := sh.c.Do(ctx, sh.c.B().Get().Key(sh.prefix+key).Build()).AsInt64()
	if valkey.IsValkeyNil(err) {
		_ = sh.done("read", start, nil)
		return time.Time{}, true
	}
	if sh.done("read", start, err) != nil {
		return time.Time{}, false
	}
	return time.UnixMicro(v), true
}

// clear fills key's bucket, and reports whether the store held one.
func (sh *sharedBuckets) clear(key string) bool {
	if !sh.up() {
		return false
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sh.wait)
	defer cancel()
	n, err := sh.c.Do(ctx, sh.c.B().Del().Key(sh.prefix+key).Build()).AsInt64()
	return sh.done("clear", start, err) == nil && n > 0
}

// sharedOutcome is a call's outcome as the metrics name it: ok, timeout
// (past SharedWait) or error.
func sharedOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "error"
}
