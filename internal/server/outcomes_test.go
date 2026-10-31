package server

// What a write AWS answered with an error is taken to have done: applied,
// or possibly so, and the count reserved for it is kept; or refused, as AWS
// or the store stated, and the count is given back (LIMITS.md rule 4;
// dromas-dev/dromas-server#14, #89, #90). awsfake_test.go has the fake.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/dromas-dev/dromas-client/protocol"
)

const (
	codeISE  = "InternalServerError"
	codeCCF  = "ConditionalCheckFailedException"
	codePTEE = "ProvisionedThroughputExceededException"
)

var (
	answer500  = answer{status: http.StatusInternalServerError, body: dynErr(codeISE, "")}
	answerCCF  = answer{status: http.StatusBadRequest, body: dynErr(codeCCF, "")}
	answerPTEE = answer{status: http.StatusBadRequest, body: dynErr(codePTEE, "")}
)

// scripted answers the n-th call of op with answers[n-1], and every other
// call, and each past the script, with a fault of AWS's own.
func scripted(op string, answers ...answer) func(string, int, []byte) answer {
	return func(o string, n int, _ []byte) answer {
		if o != op || n > len(answers) {
			return answer500
		}
		return answers[n-1]
	}
}

// applied is a, with the call's write applied.
func applied(a answer) answer { a.apply = true; return a }

// A write the SDK retried after an attempt whose answer leaves open whether
// it was applied (a fault of AWS's own, a lost answer) may have been applied
// whatever its last attempt answered, a failed condition or a throttle among
// them (dromas-dev/dromas-server#89): the fake applies the first
// UpdateItem and answers it with a 500, or drops its answer, and the retry is
// answered as DynamoDB answers a retry of an applied conditional write, or
// throttled; and the same for a send's PutItem, throttled after a 500. The
// controls: every attempt a fault; a failed condition or throttles alone,
// nothing applied.
func TestAWriteRetriedAfterAnAmbiguousAttemptMayHaveBeenApplied(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	msg := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	cases := []struct {
		name    string
		op      string   // UpdateItem, by UpdateMailbox, or PutItem, by PutMessage
		answers []answer // the n-th call's
		want    bool     // mayHaveApplied
	}{
		{"applied and answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, true},
		{"applied and its answer lost, then the retry's failed condition", "UpdateItem", []answer{applied(answer{drop: true}), answerCCF}, true},
		{"applied and answered 500, then throttled twice", "UpdateItem", []answer{applied(answer500), answerPTEE, answerPTEE}, true},
		{"a send's item applied and answered 500, then throttled twice", "PutItem", []answer{applied(answer500), answerPTEE, answerPTEE}, true},
		{"control: applied and answered 500 three times", "UpdateItem", []answer{applied(answer500), answer500, answer500}, true},
		{"control: a failed condition, nothing applied", "UpdateItem", []answer{answerCCF}, false},
		{"control: throttled three times, nothing applied", "UpdateItem", []answer{answerPTEE, answerPTEE, answerPTEE}, false},
		{"control: a send's item throttled three times, nothing applied", "PutItem", []answer{answerPTEE, answerPTEE, answerPTEE}, false},
	}
	fakes, errs := make([]*fakeAWS, len(cases)), make([]error, len(cases))
	var wg sync.WaitGroup // every write at once, each on a fake of its own, then each judged
	for i, c := range cases {
		fakes[i] = newFakeAWS()
		fakes[i].dynamo = scripted(c.op, c.answers...)
		s := fakeStore(t, fakes[i])
		ctx := context.WithoutCancel(t.Context())
		wg.Go(func() {
			if c.op == "PutItem" {
				_, errs[i] = s.PutMessage(ctx, mailbox.Addr, msg, []byte("abc"))
				return
			}
			errs[i] = s.UpdateMailbox(ctx, cloneMailbox(mailbox))
		})
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := errs[i]
			calls, applied := fakes[i].count(c.op)
			got := mayHaveApplied(err)
			t.Logf("%d %s calls, %d applied; err %v (ErrStale %v, %s, throttle %v); mayHaveApplied %v",
				calls, c.op, applied, err, errors.Is(err, ErrStale), faultOf(err), IsThrottle(err), got)
			if got != c.want {
				t.Errorf("mayHaveApplied %v for a write the fake applied %d times: the count would be %s", got, applied, map[bool]string{true: "kept", false: "given back"}[got])
			}
		})
	}
}

// The SDK draws on its retry quota only after an attempt failed with an
// error it retries, a 500 among them, and once the quota is out it returns
// that attempt's error joined with the quota's, which reads as a throttle: a
// write the fake applied and answered 500 on a client whose quota is drained
// may have been applied all the same. The control is the same write on a
// fresh client: three attempts.
func TestADrainedRetryQuotaHidesNoAppliedWrite(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	for _, drained := range []bool{false, true} {
		t.Run(fmt.Sprintf("drained=%v", drained), func(t *testing.T) {
			f := newFakeAWS()
			var phase atomic.Int32 // 0 draining, 1 the write
			f.dynamo = func(string, int, []byte) answer {
				if phase.Load() == 0 {
					return answerPTEE
				}
				return applied(answer500)
			}
			s := fakeStore(t, f)
			ctx := context.WithoutCancel(t.Context())
			if drained {
				var wg sync.WaitGroup
				for range 60 {
					wg.Go(func() { _ = s.UpdateMailbox(ctx, cloneMailbox(mailbox)) })
				}
				wg.Wait()
			}
			phase.Store(1)
			before, _ := f.count("UpdateItem")
			err := s.UpdateMailbox(ctx, cloneMailbox(mailbox))
			after, _ := f.count("UpdateItem")
			got := mayHaveApplied(err)
			t.Logf("%d attempts of the write, the first applied; err %v; throttle %v; mayHaveApplied %v", after-before, err, IsThrottle(err), got)
			if !got {
				t.Errorf("a write the fake applied and answered 500 is taken for a refusal AWS stated (%v)", err)
			}
		})
	}
}

// putItemOfItsOwn answers the first PutItem as applied with first, and every
// later one with a failed condition that returns, as ALL_OLD, the item the
// first wrote: what DynamoDB answers a retry of a conditional put it applied.
func putItemOfItsOwn(first answer) func(string, int, []byte) answer {
	return putItemMeets(applied(first), nil)
}

// putItemMeets answers the first PutItem with first, and every later one
// with a failed condition that returns, as ALL_OLD, the item the first
// carried, changed by change if it is not nil.
func putItemMeets(first answer, change func(item map[string]any)) func(string, int, []byte) answer {
	var mu sync.Mutex
	var item []byte
	return func(op string, n int, body []byte) answer {
		if op != "PutItem" {
			return answer{status: http.StatusBadRequest, body: dynErr("ValidationException", "")}
		}
		mu.Lock()
		defer mu.Unlock()
		if n == 1 {
			var in struct{ Item map[string]any }
			_ = json.Unmarshal(body, &in)
			if change != nil {
				change(in.Item)
			}
			item, _ = json.Marshal(in.Item)
			return first
		}
		return answer{status: http.StatusBadRequest, body: dynErr(codeCCF, `,"Item":`+string(item))}
	}
}

// A send's PutItem applied and answered 500 meets, retried, its own item:
// the failed condition returns the item this write made (its time), so the
// message is stored, and memory has its mark (dromas-dev/dromas-server#89).
// The controls: the same write answered 200, stored; and a retry whose
// failed condition returns a live item of another time, a send of those
// bytes that got there first, which this write did not make.
func TestAPutRetriedOntoItsOwnItemIsStored(t *testing.T) {
	t.Parallel()
	to := protocol.Address{1, 2, 3}
	for _, c := range []struct {
		name   string
		dynamo func() func(string, int, []byte) answer
		stored bool
	}{
		{"answered 200", func() func(string, int, []byte) answer {
			return scripted("PutItem", applied(answer{status: http.StatusOK, body: "{}"}))
		}, true},
		{"applied and answered 500, then its own item", func() func(string, int, []byte) answer { return putItemOfItsOwn(answer500) }, true},
		{"control: answered 500, then a live item of another time", func() func(string, int, []byte) answer {
			return putItemMeets(answer500, func(it map[string]any) {
				it["received_at"] = map[string]string{"N": strconv.FormatUint(ms(time.Now())-1000, 10)}
			})
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAWS()
			f.dynamo = c.dynamo()
			s := fakeStore(t, f)
			if err := s.idx.ensure(t.Context(), to, func() (mailboxRead, error) {
				return mailboxRead{exists: true, st: Standing{State: Active}, rev: 1}, nil
			}); err != nil {
				t.Fatal(err)
			}
			now := s.now().UTC().Truncate(time.Millisecond)
			h := &Header{ID: [32]byte{9}, Size: 10, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
			orig, err := s.PutMessage(context.WithoutCancel(t.Context()), to, h, []byte("0123456789"))
			calls, applied := f.count("PutItem")
			marks := s.idx.count(to, s.nowMs())
			t.Logf("%d PutItem calls, %d applied; orig %v; err %v; marks in memory %d", calls, applied, orig != nil, err, marks)
			if err != nil || (orig == nil) != c.stored || (marks == 1) != c.stored || marks > 1 {
				t.Errorf("answered as orig %v, err %v, with %d marks in memory; want stored %v", orig != nil, err, marks, c.stored)
			}
		})
	}
}

// A refusal AWS stated, of a write it did not apply, gives the count back
// whatever fault the SDK gives it (dromas-dev/dromas-server#90):
// DynamoDB's refusals that the SDK does not model (ValidationException,
// AccessDeniedException) come back with no fault, and are refusals all the
// same; and a send whose body's PUT failed, whatever S3 answered, wrote no
// item, so nothing is stored. The control: a refusal the SDK models,
// ResourceNotFound.
func TestARefusalAWSStatedGivesTheCountBack(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	t.Run("UpdateItem", func(t *testing.T) {
		for _, code := range []string{"ValidationException", "AccessDeniedException", "ResourceNotFoundException"} {
			t.Run(code, func(t *testing.T) {
				f := newFakeAWS()
				f.dynamo = func(string, int, []byte) answer { return answer{status: http.StatusBadRequest, body: dynErr(code, "")} }
				s := fakeStore(t, f)
				err := s.UpdateMailbox(context.WithoutCancel(t.Context()), cloneMailbox(mailbox))
				calls, applied := f.count("UpdateItem")
				got := mayHaveApplied(err)
				t.Logf("%d calls, %d applied; %s; mayHaveApplied %v", calls, applied, faultOf(err), got)
				if got {
					t.Errorf("a refusal DynamoDB stated, nothing applied, keeps the count (%s)", faultOf(err))
				}
			})
		}
	})
	t.Run("PutMessage", func(t *testing.T) {
		for _, c := range []struct {
			name string
			a    answer
		}{
			{"S3 403 AccessDenied", answer{status: http.StatusForbidden, body: s3Err("AccessDenied")}},
			{"S3 500 InternalError", answer{status: http.StatusInternalServerError, body: s3Err("InternalError")}},
		} {
			t.Run(c.name, func(t *testing.T) {
				f := newFakeAWS()
				f.s3 = func(string, int) answer { return c.a }
				s := fakeStore(t, f)
				now := s.now().UTC().Truncate(time.Millisecond)
				h := &Header{ID: [32]byte{7}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
				_, err := s.PutMessage(context.WithoutCancel(t.Context()), protocol.Address{4}, h, []byte("abc"))
				items, _ := f.count("PutItem")
				got := mayHaveApplied(err)
				t.Logf("PutItem calls %d; %s; mayHaveApplied %v", items, faultOf(err), got)
				if got || items != 0 {
					t.Errorf("a send whose item was never written keeps its counts (%s, %d PutItem calls)", faultOf(err), items)
				}
			})
		}
	})
}

// A write to what is held of an address whose answer leaves open whether it
// was applied leaves memory holding nothing of the address, as forget does:
// the record cache counts it as a write and keeps no copy, so a read begun
// before it puts nothing after it, and the index forgets the mailbox, so its
// standing from before the write checks no pass; the next use reads the
// table (recCache.write; dromas-dev/dromas-server#89). The controls: a
// refusal AWS stated, one the SDK models or one it gives no fault (#90),
// changes nothing in memory; a failed condition with nothing applied evicts
// the cached copy, counted as a write, since the store holds what this
// process never applied, so a read begun before it puts nothing, and leaves
// the index (Memory.write). Its caller is told the write may have been
// applied, so the count reserved for it is kept, and a refusal stated is
// not (mayHaveApplied).
func TestAWriteThatMayHaveBeenAppliedForgetsItsAddress(t *testing.T) {
	t.Parallel()
	_, r, mailbox := heldRecord(t)
	notFound := answer{status: http.StatusBadRequest, body: dynErr("ResourceNotFoundException", "")}
	validation := answer{status: http.StatusBadRequest, body: dynErr("ValidationException", "")}
	raise := func(ctx context.Context, s *Memory) error {
		return s.Revoke(ctx, mailbox.Addr, &Revocations{Identity: r.id.Document(), Certs: []byte("c"), CertsSig: []byte("s"), Through: 7}, ExpectAnything)
	}
	update := func(ctx context.Context, s *Memory) error { return s.UpdateMailbox(ctx, cloneMailbox(mailbox)) }
	cases := []struct {
		name            string
		op              string
		answers         []answer
		write           func(context.Context, *Memory) error
		evicted, counts bool
		timeout         time.Duration // the write's caller's, if not 0
		kept            bool          // the index keeps the mailbox: a refusal stated
	}{
		{"UpdateMailbox timed out, its one attempt unanswered", "UpdateItem", []answer{{hang: true}}, update, true, true, 300 * time.Millisecond, false},
		{"a raise timed out, its one attempt unanswered", "UpdateItem", []answer{{hang: true}}, raise, true, true, 300 * time.Millisecond, false},
		{"UpdateMailbox answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500}, update, true, true, 0, false},
		{"UpdateMailbox applied, answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, update, true, true, 0, false},
		{"UpdateMailbox's answer lost every attempt", "UpdateItem", []answer{applied(answer{drop: true}), {drop: true}, {drop: true}}, update, true, true, 0, false},
		{"a raise answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500}, raise, true, true, 0, false},
		{"a raise applied, answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, raise, true, true, 0, false},
		{"CreateMailbox answered 500 every attempt", "PutItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *Memory) error { return s.CreateMailbox(ctx, cloneMailbox(mailbox)) }, true, true, 0, false},
		{"DeleteMailbox answered 500 every attempt", "DeleteItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *Memory) error { return s.DeleteMailbox(ctx, mailbox.Addr) }, true, true, 0, false},
		{"Adopt answered 500 every attempt", "TransactWriteItems", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *Memory) error {
				return s.Adopt(ctx, cloneMailbox(mailbox), "acct", [32]byte{1})
			}, true, true, 0, false},
		{"Leave answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *Memory) error { return s.Leave(ctx, cloneMailbox(mailbox)) }, true, true, 0, false},
		{"control: UpdateMailbox refused, a ResourceNotFoundException", "UpdateItem", []answer{notFound}, update, false, false, 0, true},
		{"control: UpdateMailbox refused, a ValidationException, which the SDK gives no fault", "UpdateItem", []answer{validation}, update, false, false, 0, true},
		{"control: UpdateMailbox's failed condition, nothing applied", "UpdateItem", []answer{answerCCF}, update, true, true, 0, true},
	}
	// Every write at once, each on a fake of its own, then each judged.
	type outcome struct {
		err                   error
		held, filled, indexed bool
		cachedFirst           bool
	}
	outs := make([]outcome, len(cases))
	var wg sync.WaitGroup
	for i, c := range cases {
		f := newFakeAWS()
		f.dynamo = scripted(c.op, c.answers...)
		s := fakeStore(t, f)
		s.cache.fill(cloneMailbox(mailbox), s.cache.begin(mailbox.Addr))
		_, outs[i].cachedFirst = s.cache.get(mailbox.Addr)
		st, _, err := mailbox.standing()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.idx.ensure(t.Context(), mailbox.Addr, func() (mailboxRead, error) { return mailboxRead{exists: true, st: st, rev: mailbox.Rev}, nil }); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithoutCancel(t.Context()), func() {}
		if c.timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
		}
		wg.Go(func() {
			defer cancel()
			tok := s.cache.begin(mailbox.Addr) // a read of the address begun before the write
			outs[i].err = c.write(ctx, s)
			_, outs[i].held = s.cache.get(mailbox.Addr)
			s.cache.fill(cloneMailbox(mailbox), tok) // that read's copy, from before the write
			_, outs[i].filled = s.cache.get(mailbox.Addr)
			_, outs[i].indexed = s.Held(mailbox.Addr)
		})
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err, held, filled := outs[i].err, outs[i].held, outs[i].filled
			if !outs[i].cachedFirst {
				t.Fatal("the cache does not hold the record put in it")
			}
			t.Logf("err %v (mayHaveApplied %v); after it the record is held %v; the read begun before it puts its copy %v; the index holds the mailbox %v",
				err, mayHaveApplied(err), held, filled, outs[i].indexed)
			if err == nil {
				t.Fatal("the write did not fail")
			}
			if mayHaveApplied(err) == c.kept {
				t.Errorf("mayHaveApplied %v, want %v: the count reserved for the write would be %s", mayHaveApplied(err), !c.kept, map[bool]string{true: "kept", false: "given back"}[mayHaveApplied(err)])
			}
			if held == c.evicted {
				t.Errorf("after the write the cache holds the record read before it %v; want %v", held, !c.evicted)
			}
			if filled == c.counts && c.evicted {
				t.Errorf("a read begun before the write puts its copy after it %v; want %v: the write is counted %v", filled, !c.counts, !filled)
			}
			if outs[i].indexed != c.kept {
				t.Errorf("after the write the index holds the mailbox's standing from before it %v; want %v", outs[i].indexed, c.kept)
			}
		})
	}
}

// overFake makes the next write of the suite's store, then answers it as a
// store on DynamoDB answers the same write when AWS answers as the fake scripts
// it: its error, made by the SDK, so a handler meets the store's own
// statement of a write AWS applied and then answered with a fault. hook runs
// first.
type overFake struct {
	Store
	t      *testing.T
	armed  atomic.Bool
	hook   func()
	dynamo func(string, int, []byte) answer
}

func (s *overFake) fake() *Memory {
	f := newFakeAWS()
	f.dynamo = s.dynamo
	return fakeStore(s.t, f)
}

func (s *overFake) UpdateMailbox(ctx context.Context, b *Mailbox) error {
	if !s.armed.Swap(false) {
		return s.Store.UpdateMailbox(ctx, b)
	}
	read := cloneMailbox(b)
	if err := s.Store.UpdateMailbox(ctx, b); err != nil {
		return err
	}
	return s.fake().UpdateMailbox(ctx, read)
}

func (s *overFake) Leave(ctx context.Context, b *Mailbox) error {
	if !s.armed.Swap(false) {
		return s.Store.Leave(ctx, b)
	}
	read := cloneMailbox(b)
	if err := s.Store.Leave(ctx, b); err != nil {
		return err
	}
	return s.fake().Leave(ctx, read)
}

func (s *overFake) PutMessage(ctx context.Context, mailbox protocol.Address, h *Header, body []byte) (*Header, error) {
	if !s.armed.Swap(false) {
		return s.Store.PutMessage(ctx, mailbox, h, body)
	}
	if s.hook != nil {
		s.hook()
	}
	if orig, err := s.Store.PutMessage(ctx, mailbox, h, body); err != nil || orig != nil {
		return orig, err
	}
	return s.fake().PutMessage(ctx, mailbox, h, body)
}

// A renewal the store applied, whose first attempt AWS answered with a
// fault and whose retry met its own write's failed condition, is counted:
// with one renewal a day, the next is refused (dromas-dev/dromas-server#89).
// The control: a renewal answered with a fault every attempt.
func TestARenewalTheStoreMayHaveAppliedIsCounted(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		answers []answer
	}{
		{"applied and answered 500, then the retry's failed condition", []answer{applied(answer500), answerCCF}},
		{"control: applied and answered 500 every attempt", []answer{applied(answer500), answer500, answer500}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := relaxed()
			l.RenewalsPerDay = 1
			s := &overFake{t: t, dynamo: scripted("UpdateItem", c.answers...)}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			r.prekeyUnder(r.work[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			s.armed.Store(true)
			first := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1))
			b, _ := e.store.Mailbox(t.Context(), r.id.Address())
			again := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1))
			r.prekeyUnder(r.work[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			next := e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1))
			t.Logf("renewal %d %s, the mailbox at prekey %d; identical retry %d; next renewal %d %s", first.status, first.code(), b.Prekey.Serial, again.status, next.status, next.code())
			if next.status != http.StatusTooManyRequests {
				t.Errorf("a renewal the store applied was not counted: the next one is %d %s", next.status, next.code())
			}
		})
	}
}

// A send whose PutItem the store applied, whose first attempt AWS answered
// with a fault and whose retry met its own item, is stored: answered 201
// and counted, with one send a day; and where its recipient's address was
// revoked before the write, what it wrote is deleted and it is answered
// 410 (dromas-dev/dromas-server#89, #15). The controls are the same
// sends whose write AWS answered 200.
func TestASendWhoseWriteWasRetriedIsStored(t *testing.T) {
	t.Parallel()
	for _, retried := range []bool{false, true} {
		dynamo := func() func(string, int, []byte) answer {
			if retried {
				return putItemOfItsOwn(answer500)
			}
			return scripted("PutItem", applied(answer{status: http.StatusOK, body: "{}"}))
		}
		t.Run(fmt.Sprintf("counted/retried=%v", retried), func(t *testing.T) {
			l := relaxed()
			l.SendsPerDay = 1
			s := &overFake{t: t, dynamo: dynamo()}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			s.armed.Store(true)
			first := e.sendTo(to, 1, from, 1)
			n, _ := e.store.Count(t.Context(), to.id.Address())
			next := e.sendTo(to, 1, from, 1)
			t.Logf("send %d %s, the mailbox holds %d; next send %d %s", first.status, first.code(), n, next.status, next.code())
			if first.status != http.StatusCreated || next.status != http.StatusTooManyRequests {
				t.Errorf("a stored send answered %d, and the next one %d: want 201, then 429", first.status, next.status)
			}
		})
		t.Run(fmt.Sprintf("revoked/retried=%v", retried), func(t *testing.T) {
			s := &overFake{t: t, dynamo: dynamo()}
			e := newEnv(t, relaxed(), func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			owner, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			sig, err := protocol.SignRevocation(owner.signer, owner.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			s.hook = func() {
				e.want(e.do("PUT", owner.path("/revocations"), protocol.Revocations{Identity: owner.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
			}
			s.armed.Store(true)
			got := e.sendTo(owner, 1, from, 1)
			n, _ := e.store.Count(t.Context(), owner.id.Address())
			t.Logf("a send that wrote after its recipient's revocation: %d %s; the revoked mailbox holds %d", got.status, got.code(), n)
			if got.status != http.StatusGone || n != 0 {
				t.Errorf("a send that wrote after its recipient's revocation is answered %d and leaves %d messages; want 410 and none", got.status, n)
			}
		})
	}
}

// mailboxesTable is a fake of the mailboxes table, enough for a registration, a
// mailbox's load and its reads: a PutItem keeps its item, a Query of an address
// returns that address's items, the messages table holds nothing, and update
// answers each UpdateItem, keeping what it applies (keep).
type mailboxesTable struct {
	mu     sync.Mutex
	items  map[string]map[string]any // by addr and sk, as DynamoDB's JSON writes them
	update func(b *mailboxesTable, n int) answer
}

// asJSON is v as DynamoDB's JSON protocol reads it back: binary as base64.
func asJSON(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m
}

func attrB(it map[string]any, name string) string {
	v, _ := it[name].(map[string]any)
	s, _ := v["B"].(string)
	return s
}

func (b *mailboxesTable) keep(it map[string]any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[attrB(it, "addr")+"/"+attrB(it, "sk")] = it
}

func (b *mailboxesTable) answer(op string, n int, body []byte) answer {
	var in struct {
		TableName                 string
		Item                      map[string]any
		ExpressionAttributeValues map[string]map[string]any
	}
	_ = json.Unmarshal(body, &in)
	ok := func(v any) answer { j, _ := json.Marshal(v); return answer{status: http.StatusOK, body: string(j)} }
	switch {
	case op == "PutItem" && in.TableName == "mailboxes":
		b.keep(in.Item)
		return ok(map[string]any{})
	case op == "Query" && in.TableName == "mailboxes":
		a, _ := in.ExpressionAttributeValues[":a"]["B"].(string)
		b.mu.Lock()
		defer b.mu.Unlock()
		items := []any{}
		for _, it := range b.items {
			if attrB(it, "addr") == a {
				items = append(items, it)
			}
		}
		return ok(map[string]any{"Items": items, "Count": len(items), "ScannedCount": len(items)})
	case op == "Query":
		return ok(map[string]any{"Items": []any{}, "Count": 0, "ScannedCount": 0})
	case op == "GetItem":
		return ok(map[string]any{})
	case op == "UpdateItem":
		return b.update(b, n)
	}
	return answer500
}

// A raise of a revocation of certificates whose write AWS applied, and whose
// answer was lost, leaves memory holding nothing of the address, the index
// as the cache (Memory.write): the next call with a pass under the revoked
// certificate is refused at once, from the record read again. Before, the
// index's standing from before the write took that pass until the stream's
// echo. The control: a raise AWS refused leaves the index standing, and the
// same pass is taken (dromas-dev/dromas-server#89).
func TestARevocationWhoseAnswerWasLostIsInTheNextPassCheck(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		applied bool
		status  int
		code    protocol.Code
	}{
		{"applied and its answer lost, then the retry's failed condition", true, http.StatusUnauthorized, protocol.CodeCertificateRevoked},
		{"control: refused, a ValidationException", false, http.StatusOK, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			tb := &mailboxesTable{items: map[string]map[string]any{}}
			f := newFakeAWS()
			f.dynamo = tb.answer
			s := fakeStore(t, f)
			e := newEnv(t, relaxed(), func(cfg *Config) { cfg.Store, cfg.Ready = s, nil })
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			a := r.id.Address()
			e.want(e.do("GET", r.path("/messages"), nil, r.pass(1)), http.StatusOK, "")
			if _, held := s.Held(a); !held {
				t.Fatal("the mailbox is not loaded")
			}
			rv := r.certs(1)
			list, err := protocol.ParseRevokedCertificates(rv.RevokedCertificates)
			if err != nil {
				t.Fatal(err)
			}
			item := asJSON(itemJSON(map[string]types.AttributeValue{
				"addr": bin(a[:]), "sk": bin([]byte{skRevocations}), "identity": bin(rv.Identity),
				"revoked_certs": bin(rv.RevokedCertificates), "revoked_certs_sig": bin(rv.RevokedCertificatesSignature), "through": num(list.Through),
			}))
			tb.update = func(b *mailboxesTable, n int) answer {
				switch {
				case !c.applied:
					return answer{status: http.StatusBadRequest, body: dynErr("ValidationException", "")}
				case n == 1:
					b.keep(item)
					return answer{drop: true}
				}
				return answerCCF
			}
			err = s.Revoke(context.WithoutCancel(t.Context()), a, &Revocations{Identity: rv.Identity, Certs: rv.RevokedCertificates, CertsSig: rv.RevokedCertificatesSignature, Through: list.Through}, ExpectAnything)
			_, held := s.Held(a)
			got := e.do("GET", r.path("/messages"), nil, r.pass(1))
			t.Logf("the raise: %v (mayHaveApplied %v); the index holds the mailbox %v; then a pass under certificate 1: %d %s", err, mayHaveApplied(err), held, got.status, got.code())
			if got.status != c.status || got.code() != c.code {
				t.Errorf("a pass under certificate 1 after the raise: %d %s; want %d %s", got.status, got.code(), c.status, c.code)
			}
		})
	}
}

// Every conditional write of the store is no stated refusal when its retry's
// condition fails after an attempt that left open whether it was applied:
// the fake applies the first attempt and answers it with a 500, and the
// retry fails its condition, as DynamoDB answers a retry of an applied
// conditional write (dromas-dev/dromas-server#89). So too a delete,
// which has no condition, throttled after a 500. The controls: the same
// write's failed condition, or throttles, alone, a refusal stated as before;
// and Adopt's transaction cancelled for a failed condition after a 500, a
// refusal stated, since its retry carries its first attempt's token
// (TestAnAdoptsRetriesCarryItsFirstAttemptsToken).
func TestEveryConditionalWriteRetriedAfterAnAmbiguousAttemptMayHaveBeenApplied(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	createMailbox := func(ctx context.Context, s *Memory) error { return s.CreateMailbox(ctx, cloneMailbox(mailbox)) }
	leave := func(ctx context.Context, s *Memory) error { return s.Leave(ctx, cloneMailbox(mailbox)) }
	deleteMailbox := func(ctx context.Context, s *Memory) error { return s.DeleteMailbox(ctx, mailbox.Addr) }
	ack := func(ctx context.Context, s *Memory) error { return s.DeleteMessage(ctx, mailbox.Addr, [32]byte{7}) }
	account := func(ctx context.Context, s *Memory) error { return s.CreateAccount(ctx, &Account{ID: "acct"}) }
	adoptKey := func(ctx context.Context, s *Memory) error {
		return s.PutAdoptKey(ctx, &AdoptKey{Account: "acct", Hash: [32]byte{1}, Uses: 1, Expires: time.Now().Add(time.Hour)})
	}
	adopt := func(ctx context.Context, s *Memory) error {
		return s.Adopt(ctx, cloneMailbox(mailbox), "acct", [32]byte{1})
	}
	cancelled := answer{status: http.StatusBadRequest, body: dynErr("TransactionCanceledException", `,"CancellationReasons":[{"Code":"ConditionalCheckFailed"},{"Code":"None"}]`)}
	cases := []struct {
		name    string
		op      string
		answers []answer
		write   func(context.Context, *Memory) error
		stated  error // the refusal the write states, or nil for one that may have been applied
	}{
		{"CreateMailbox applied and answered 500, then the retry's failed condition", "PutItem", []answer{applied(answer500), answerCCF}, createMailbox, nil},
		{"Leave applied and answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, leave, nil},
		{"DeleteMailbox applied and answered 500, then throttled twice", "DeleteItem", []answer{applied(answer500), answerPTEE, answerPTEE}, deleteMailbox, nil},
		{"an ack's item applied and answered 500, then the retry's failed condition", "DeleteItem", []answer{applied(answer500), answerCCF}, ack, nil},
		{"CreateAccount applied and answered 500, then the retry's failed condition", "PutItem", []answer{applied(answer500), answerCCF}, account, nil},
		{"PutAdoptKey applied and answered 500, then the retry's failed condition", "PutItem", []answer{applied(answer500), answerCCF}, adoptKey, nil},
		{"control: CreateMailbox's failed condition", "PutItem", []answer{answerCCF}, createMailbox, ErrExists},
		{"control: Leave's failed condition", "UpdateItem", []answer{answerCCF}, leave, ErrStale},
		{"control: DeleteMailbox throttled three times", "DeleteItem", []answer{answerPTEE, answerPTEE, answerPTEE}, deleteMailbox, nil},
		{"control: an ack's failed condition", "DeleteItem", []answer{answerCCF}, ack, ErrNotFound},
		{"control: CreateAccount's failed condition", "PutItem", []answer{answerCCF}, account, ErrExists},
		{"control: PutAdoptKey's failed condition", "PutItem", []answer{answerCCF}, adoptKey, ErrExists},
		{"control: Adopt answered 500, then its transaction cancelled for the mailbox's condition", "TransactWriteItems", []answer{answer500, cancelled}, adopt, ErrStale},
	}
	fakes, errs := make([]*fakeAWS, len(cases)), make([]error, len(cases))
	var wg sync.WaitGroup // every write at once, each on a fake of its own, then each judged
	for i, c := range cases {
		fakes[i] = newFakeAWS()
		fakes[i].dynamo = scripted(c.op, c.answers...)
		s := fakeStore(t, fakes[i])
		wg.Go(func() { errs[i] = c.write(context.WithoutCancel(t.Context()), s) })
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := errs[i]
			calls, applied := fakes[i].count(c.op)
			want := c.stated == nil && !strings.HasPrefix(c.name, "control:")
			t.Logf("%d %s calls, %d applied; err %v; mayHaveApplied %v", calls, c.op, applied, err, mayHaveApplied(err))
			if err == nil || mayHaveApplied(err) != want || (c.stated != nil && !errors.Is(err, c.stated)) || (want && (errors.Is(err, ErrExists) || errors.Is(err, ErrStale) || errors.Is(err, ErrNotFound))) {
				t.Errorf("err %v, mayHaveApplied %v; want a write that may have been applied %v, the refusal %v", err, mayHaveApplied(err), want, c.stated)
			}
		})
	}
}

// Adopt is the conditional write that needs no note of its attempts: its
// transaction carries a client token, the same on every attempt of one call,
// so DynamoDB answers the retry of an applied attempt as that attempt
// succeeded, and a failed condition there is a refusal stated (Amazon
// DynamoDB Developer Guide, Transaction APIs, Idempotency; transact). The
// fake answers every attempt with a 500 and keeps each one's token.
func TestAnAdoptsRetriesCarryItsFirstAttemptsToken(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	var mu sync.Mutex
	var tokens []string
	f := newFakeAWS()
	f.dynamo = func(op string, n int, body []byte) answer {
		var in struct{ ClientRequestToken string }
		_ = json.Unmarshal(body, &in)
		mu.Lock()
		tokens = append(tokens, in.ClientRequestToken)
		mu.Unlock()
		return answer500
	}
	err := fakeStore(t, f).Adopt(context.WithoutCancel(t.Context()), cloneMailbox(mailbox), "acct", [32]byte{1})
	mu.Lock()
	defer mu.Unlock()
	t.Logf("%d attempts, tokens %q; err %v", len(tokens), tokens, err)
	if len(tokens) < 2 || tokens[0] == "" || slices.ContainsFunc(tokens, func(tok string) bool { return tok != tokens[0] }) {
		t.Errorf("the attempts of one Adopt carry tokens %q; want one token, on each", tokens)
	}
}

// A Leave the store applied, whose first attempt AWS answered with a fault
// and whose retry met its own write's failed condition, is answered as any
// write whose outcome is unknown, 503, never 409 mailbox_changed. The control:
// a Leave whose condition failed alone is 409 (dromas-dev/dromas-server#89).
func TestALeaveTheStoreMayHaveAppliedIsNot409(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		answers []answer
		status  int
		code    protocol.Code
	}{
		{"applied and answered 500, then the retry's failed condition", []answer{applied(answer500), answerCCF}, http.StatusServiceUnavailable, protocol.CodeUnavailable},
		{"control: a failed condition, nothing applied", []answer{answerCCF}, http.StatusConflict, protocol.CodeMailboxChanged},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			s := &overFake{t: t, dynamo: scripted("UpdateItem", c.answers...)}
			e := newEnv(t, relaxed(), func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			acc, key := accountEnv(t, e, false, 1)
			_, hash, _ := parseAdopt(key)
			rec, err := e.store.Mailbox(ctx, r.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			if err := e.store.Adopt(ctx, rec, acc.ID, hash); err != nil {
				t.Fatal(err)
			}
			s.armed.Store(true)
			got := e.do("DELETE", r.path("/account"), nil, r.pass(1))
			t.Logf("the leave: %d %s", got.status, got.code())
			if got.status != c.status || got.code() != c.code {
				t.Errorf("the leave is answered %d %s; want %d %s", got.status, got.code(), c.status, c.code)
			}
		})
	}
}

// An adopt whose first attempt AWS applied, and answered with a fault or not
// at all, may have been applied whatever came after it: throttles, a
// TransactionInProgressException, which DynamoDB answers to an attempt with
// the same token while the first is still in progress and the SDK retries as
// a throttle, or the SDK's retry quota drained, or a failed condition met
// by a later call of its transaction, which carries another client token.
// Its transaction's calls share one note of such an attempt, so the store
// states no refusal: the count is kept, and memory forgets the mailbox, the
// record cache and the index (dromas-dev/dromas-server#101). The
// control: a fault at every attempt.
func TestAnAdoptAfterAnAmbiguousAttemptMayHaveBeenApplied(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	inProgress := answer{status: http.StatusBadRequest, body: dynErr("TransactionInProgressException", "")}
	// A cancellation the SDK does not retry: for a conflict on the key's
	// item, which the store sends again by a new call, under a new token;
	// then for the mailbox's condition, which that call's token does not cover.
	conflict := answer{status: http.StatusBadRequest, body: dynErr("TransactionCanceledException", `,"CancellationReasons":[{"Code":"None"},{"Code":"TransactionConflict"}]`)}
	condition := answer{status: http.StatusBadRequest, body: dynErr("TransactionCanceledException", `,"CancellationReasons":[{"Code":"ConditionalCheckFailed"},{"Code":"None"}]`)}
	cases := []struct {
		name    string
		answers []answer
		drained bool // the client's retry quota drained first
	}{
		{"applied and answered 500, then throttled twice", []answer{applied(answer500), answerPTEE, answerPTEE}, false},
		{"applied and its answer lost, then in progress twice", []answer{applied(answer{drop: true}), inProgress, inProgress}, false},
		{"applied and answered 500 on a drained retry quota", nil, true},
		{"applied and answered 500, then cancelled for a conflict, then a new call's failed condition", []answer{applied(answer500), conflict, condition}, false},
		{"control: applied and answered 500 every attempt", []answer{applied(answer500), answer500, answer500}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAWS()
			f.dynamo = scripted("TransactWriteItems", c.answers...)
			s := fakeStore(t, f)
			ctx := context.WithoutCancel(t.Context())
			if c.drained {
				var phase atomic.Int32 // 0 draining, 1 the write
				f.dynamo = func(string, int, []byte) answer {
					if phase.Load() == 0 {
						return answerPTEE
					}
					return applied(answer500)
				}
				var wg sync.WaitGroup
				for range 60 {
					wg.Go(func() { _ = s.Adopt(ctx, cloneMailbox(mailbox), "acct", [32]byte{1}) })
				}
				wg.Wait()
				phase.Store(1)
			}
			s.cache.fill(cloneMailbox(mailbox), s.cache.begin(mailbox.Addr))
			st, _, err := mailbox.standing()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.idx.ensure(t.Context(), mailbox.Addr, func() (mailboxRead, error) { return mailboxRead{exists: true, st: st, rev: mailbox.Rev}, nil }); err != nil {
				t.Fatal(err)
			}
			calls0, applied0 := f.count("TransactWriteItems")
			err = s.Adopt(ctx, cloneMailbox(mailbox), "acct", [32]byte{1})
			calls, applied := f.count("TransactWriteItems")
			_, cached := s.cache.get(mailbox.Addr)
			_, held := s.Held(mailbox.Addr)
			t.Logf("%d attempts, %d applied; err %v; mayHaveApplied %v; the cache holds the record from before it %v; the index holds the mailbox %v",
				calls-calls0, applied-applied0, err, mayHaveApplied(err), cached, held)
			if !mayHaveApplied(err) || cached || held {
				t.Errorf("an adopt the fake applied: mayHaveApplied %v (the count kept), memory holds the record from before it %v, the index %v; want true, false, false", mayHaveApplied(err), cached, held)
			}
		})
	}
}

// A registration whose write's outcome is unknown, its first attempt
// applied and answered 500 and its retry's condition failed on that write,
// is answered from the record, which it reads as it does after a failed
// condition: with one registration an hour, neither it nor its client's
// retry is 503, then 429 (dromas-dev/dromas-client#411 item 2).
func TestARegistrationWhoseOutcomeIsUnknownIsAnsweredFromTheRecord(t *testing.T) {
	t.Parallel()
	tb := &mailboxesTable{items: map[string]map[string]any{}}
	var puts atomic.Int32
	f := newFakeAWS()
	f.dynamo = func(op string, n int, body []byte) answer {
		var in struct {
			TableName string
			Item      map[string]any
		}
		_ = json.Unmarshal(body, &in)
		if op == "PutItem" && in.TableName == "mailboxes" {
			if puts.Add(1) == 1 {
				tb.keep(in.Item)
				return answer500
			}
			return answerCCF
		}
		return tb.answer(op, n, body)
	}
	s := fakeStore(t, f)
	l := relaxed()
	l.RegistrationsPerHour = 1
	e := newEnv(t, l, func(cfg *Config) { cfg.Store, cfg.Ready = s, nil })
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	first := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
	again := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
	t.Logf("%d PutItem calls; the registration %d %s; its retry %d %s", puts.Load(), first.status, first.code(), again.status, again.code())
	if first.status != http.StatusOK || again.status != http.StatusOK {
		t.Errorf("a registration the store applied, its outcome unknown: %d %s, then its retry %d %s; want each answered from the record, 200", first.status, first.code(), again.status, again.code())
	}
}

// An ack whose body's DELETE failed has changed nothing a reader of the list
// sees: it is one write of the store with a send's two steps, whose outcome
// is its item's (ARCHITECTURE.md § The store), so it is a refusal, its
// retire is never sent, and memory keeps the mailbox loaded with the message,
// and its record cached. The control: the DELETE answered, then the
// retire's answer lost at every attempt, which may have been applied: the
// mailbox is forgotten.
func TestAnAckWhoseBodyWasNotDeletedChangesNothing(t *testing.T) {
	t.Parallel()
	_, _, mailbox := heldRecord(t)
	id := [32]byte{7}
	for _, c := range []struct {
		name    string
		s3      answer
		dynamo  []answer
		refused bool
	}{
		{"the body's DELETE answered 500", answer{status: http.StatusInternalServerError, body: s3Err("InternalError")}, nil, true},
		{"control: the DELETE answered, the retire's answer lost", answer{status: http.StatusNoContent}, []answer{applied(answer{drop: true}), {drop: true}, {drop: true}}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAWS()
			f.s3 = func(string, int) answer { return c.s3 }
			f.dynamo = scripted("DeleteItem", c.dynamo...)
			s := fakeStore(t, f)
			s.cache.fill(cloneMailbox(mailbox), s.cache.begin(mailbox.Addr))
			st, _, err := mailbox.standing()
			if err != nil {
				t.Fatal(err)
			}
			now := s.nowMs()
			if err := s.idx.ensure(t.Context(), mailbox.Addr, func() (mailboxRead, error) {
				return mailboxRead{exists: true, st: st, rev: mailbox.Rev, marks: []mark{s.idx.newMark(id, now+ttlMs)}}, nil
			}); err != nil {
				t.Fatal(err)
			}
			err = s.DeleteMessage(context.WithoutCancel(t.Context()), mailbox.Addr, id)
			retires, _ := f.count("DeleteItem")
			_, cached := s.cache.get(mailbox.Addr)
			held := s.idx.holdsMailbox(mailbox.Addr) && s.idx.count(mailbox.Addr, now) == 1
			t.Logf("err %v; refused %v, mayHaveApplied %v; %d retires sent; the mailbox held with its message %v, its record cached %v", err, isRefusal(err), mayHaveApplied(err), retires, held, cached)
			switch {
			case c.refused && (!isRefusal(err) || mayHaveApplied(err) || retires != 0 || !held || !cached):
				t.Errorf("an ack whose body was not deleted: refused %v, %d retires sent, the mailbox held with its message %v, its record cached %v; want a refusal, none, true, true", isRefusal(err), retires, held, cached)
			case !c.refused && (!mayHaveApplied(err) || held || cached):
				t.Errorf("an ack whose retire may have been applied: mayHaveApplied %v, the mailbox held %v, its record cached %v; want true, false, false", mayHaveApplied(err), held, cached)
			}
		})
	}
}

// A message retired by another write between DeleteAll's Query and its own
// retire, acked or retired by a fetch that found no body, is skipped, and the
// rest are retired: a message already gone is no error (Backend.DeleteAll;
// dromas-dev/dromas-client#453 item 1). The fake answers the Query with two
// messages, the first one's retire as DynamoDB answers a delete of an item an
// ack has deleted, a failed condition, and the second one's as applied.
func TestDeleteAllSkipsAMessageRetiredMeanwhile(t *testing.T) {
	t.Parallel()
	mailbox := protocol.Address{4}
	now := time.Now().UTC().Truncate(time.Millisecond)
	acked := &Header{ID: [32]byte{1}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	left := &Header{ID: [32]byte{2}, Size: 3, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	query, err := json.Marshal(map[string]any{"Items": []any{itemJSON(msgItem(mailbox, acked)), itemJSON(msgItem(mailbox, left))}, "Count": 2, "ScannedCount": 2})
	if err != nil {
		t.Fatal(err)
	}
	retire, err := json.Marshal(map[string]any{"Attributes": itemJSON(map[string]types.AttributeValue{"live": bin(liveKey(ms(now), left.ID))})})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeAWS()
	f.dynamo = func(op string, _ int, body []byte) answer {
		switch {
		case op == "Query":
			return answer{status: http.StatusOK, body: string(query)}
		case op == "DeleteItem" && strings.Contains(string(body), base64.StdEncoding.EncodeToString(acked.ID[:])):
			return answerCCF
		case op == "DeleteItem":
			return applied(answer{status: http.StatusOK, body: string(retire)})
		}
		return answer500
	}
	s := fakeStore(t, f)
	var retired [][32]byte
	err = s.dynamo().DeleteAll(context.WithoutCancel(t.Context()), mailbox, func(id [32]byte, _ time.Time) {
		retired = append(retired, id)
	})
	retires, _ := f.count("DeleteItem")
	t.Logf("err %v; %d retires sent; retired %x", err, retires, retired)
	if err != nil || retires != 2 || len(retired) != 1 || retired[0] != left.ID {
		t.Errorf("a delete of the mailbox's messages, one message acked meanwhile: err %v, %d retires sent, retired %x; want no error, 2, and the other message alone", err, retires, retired)
	}
}
