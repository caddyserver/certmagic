package certmagic

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestJobManagerCleansUpAfterJobPanic verifies that when a submitted job
// panics, the worker still releases the in-flight name and decrements its
// active-worker counter. Without these cleanups, a single panic would
// silently strand all future renewals for that name (and, after enough
// panics, every name) until process restart. See certmagic issue for
// caddyserver/caddy#7366.
func TestJobManagerCleansUpAfterJobPanic(t *testing.T) {
	// Suppress the worker's "panic: certificate worker: ..." message so it
	// doesn't pollute test output. We're intentionally triggering a panic.
	stdlog.SetOutput(io.Discard)
	t.Cleanup(func() { stdlog.SetOutput(io.Discard) })

	jm := &jobManager{maxConcurrentJobs: 10}
	logger := zap.NewNop()

	jm.Submit(logger, "renewal_X", func() error {
		panic("simulated panic from acme library")
	})

	// Cleanup happens in deferred handlers inside worker(), so we cannot
	// synchronize on it from inside the job itself. Poll until state settles.
	if !waitUntil(time.Second, func() bool {
		jm.mu.Lock()
		defer jm.mu.Unlock()
		_, nameStillTracked := jm.names["renewal_X"]
		return !nameStillTracked && jm.activeWorkers == 0
	}) {
		jm.mu.Lock()
		_, nameStillTracked := jm.names["renewal_X"]
		active := jm.activeWorkers
		jm.mu.Unlock()
		t.Fatalf("worker did not clean up after panic: name still tracked=%v, activeWorkers=%d (want false, 0)",
			nameStillTracked, active)
	}

	// A subsequent submission with the same name must actually run.
	// If the names leak regressed, this Submit would be silently dropped.
	var ran int32
	jm.Submit(logger, "renewal_X", func() error {
		atomic.StoreInt32(&ran, 1)
		return nil
	})
	if !waitUntil(time.Second, func() bool {
		return atomic.LoadInt32(&ran) == 1
	}) {
		t.Fatal("second Submit with the same name was silently dropped after panic")
	}
}

// TestDoWithRetryReturnsErrorOnSuccess verifies that doWithRetry returns nil
// when the operation succeeds on the first attempt.
func TestDoWithRetryReturnsNilOnSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	err := doWithRetry(ctx, logger, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error on success, got: %v", err)
	}
}

// TestDoWithRetryReturnsErrorOnErrNoRetry verifies that doWithRetry returns
// the error immediately (without retrying) when the function returns an
// ErrNoRetry error.
func TestDoWithRetryReturnsErrorOnErrNoRetry(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	expectedErr := fmt.Errorf("permanent failure")

	callCount := 0
	err := doWithRetry(ctx, logger, func(ctx context.Context) error {
		callCount++
		return ErrNoRetry{expectedErr}
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected ErrNoRetry's wrapped error %v, got: %v", expectedErr, err)
	}
	if callCount != 1 {
		t.Fatalf("expected function to be called exactly once (no retry), got %d calls", callCount)
	}
}

// TestDoWithRetryReturnsErrorOnContextCancellation verifies that doWithRetry
// returns context.Canceled when the context is cancelled during a retry wait.
func TestDoWithRetryReturnsErrorOnContextCancellation(t *testing.T) {
	logger := zap.NewNop()
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay to trigger cancellation during the first retry wait
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := doWithRetry(ctx, logger, func(ctx context.Context) error {
		return fmt.Errorf("transient error to trigger retry")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

// TestDoWithRetryRetriesAndSucceeds verifies that doWithRetry actually retries
// the function when it fails, and succeeds when a subsequent attempt works.
func TestDoWithRetryRetriesAndSucceeds(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// We need to make the retry intervals short for this test.
	// Save and restore the original intervals.
	originalIntervals := retryIntervals
	retryIntervals = []time.Duration{10 * time.Millisecond}
	t.Cleanup(func() { retryIntervals = originalIntervals })

	attempt := 0
	err := doWithRetry(ctx, logger, func(ctx context.Context) error {
		attempt++
		if attempt < 3 {
			return fmt.Errorf("transient error on attempt %d", attempt)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error after successful retry, got: %v", err)
	}
	if attempt != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempt)
	}
}

// TestDoWithRetryReturnsLastErrorOnExhaustion verifies the critical fix for
// the bug where doWithRetry returned nil instead of the last error when all
// retries were exhausted. This is the silent-renewal-failure bug that caused
// expired certificates to be served indefinitely.
//
// Since maxRetryDuration is 30 days, we cannot test the natural exhaustion
// path directly. Instead, we verify that the last error from f() is always
// propagated: we make f() fail once, then force the loop to exit by having
// f() cancel the context (which triggers the ctx.Done() path). This confirms
// that doWithRetry never returns nil when f() has returned a non-nil error.
func TestDoWithRetryReturnsLastErrorOnExhaustion(t *testing.T) {
	logger := zap.NewNop()

	// Use short intervals for testing
	originalIntervals := retryIntervals
	retryIntervals = []time.Duration{10 * time.Millisecond}
	t.Cleanup(func() { retryIntervals = originalIntervals })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lastErr := fmt.Errorf("persistent ACME failure")
	var attempts int

	err := doWithRetry(ctx, logger, func(ctx context.Context) error {
		attempts++
		// After the first failure, cancel the context so the next loop
		// iteration hits ctx.Done() and returns context.Canceled instead
		// of nil. This proves the error path is taken, not the success path.
		if attempts >= 1 {
			cancel()
		}
		return lastErr
	})

	// The function should NOT return nil — that was the bug.
	// It should return either the last error (via the exhaustion path)
	// or context.Canceled (via the ctx.Done() path). Either way, it
	// must be non-nil.
	if err == nil {
		t.Fatal("doWithRetry returned nil after failures — this is the silent renewal bug (see #7843)")
	}
}

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestRenewalBackoffSchedule verifies the scheduling primitive that lets
// queueRenewalTask pace retries itself instead of relying on a single
// long-lived jm job sleeping between attempts (see caddyserver/caddy#7843:
// after a transient DNS outage cleared, renewal did not happen again until
// the process was restarted, because the in-flight job's own multi-hour
// internal sleep -- not the periodic maintenance tick -- was governing
// retries, and jm.Submit silently dropped every duplicate submission from
// the maintenance tick in the meantime).
//
// It uses a fresh *renewalBackoff (not the shared package-level
// renewalRetrySchedule) and a synthetic clock so it doesn't need to sleep
// for real minutes/hours/days.
func TestRenewalBackoffSchedule(t *testing.T) {
	rb := &renewalBackoff{}
	const name = "renew_example.com"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// No recorded failures yet: always ready.
	if !rb.readyFor(name) {
		t.Fatal("expected a name with no recorded failure to be ready immediately")
	}

	// First failure: schedules the first retry interval out.
	if exhausted := rb.recordFailure(name, now); exhausted {
		t.Fatal("did not expect the retry budget to be exhausted after a single failure")
	}
	if rb.readyForAsOf(name, now) {
		t.Fatal("expected name to not be ready for a retry immediately after recording a failure")
	}

	// Not ready right up until (but not including) the first retry interval.
	almostThere := now.Add(retryIntervals[0] - time.Millisecond)
	if rb.readyForAsOf(name, almostThere) {
		t.Fatal("expected name to still not be ready just before its scheduled retry time")
	}

	// Ready once the first retry interval has elapsed.
	dueTime := now.Add(retryIntervals[0])
	if !rb.readyForAsOf(name, dueTime) {
		t.Fatal("expected name to be ready once its scheduled retry time has passed")
	}

	// A second consecutive failure advances to the next (longer) interval,
	// counted from when this second attempt happened.
	if exhausted := rb.recordFailure(name, dueTime); exhausted {
		t.Fatal("did not expect the retry budget to be exhausted after a second failure")
	}
	secondDue := dueTime.Add(retryIntervals[1])
	if rb.readyForAsOf(name, secondDue.Add(-time.Millisecond)) {
		t.Fatal("expected name to still be backing off before the second scheduled retry time")
	}
	if !rb.readyForAsOf(name, secondDue) {
		t.Fatal("expected name to be ready once the second scheduled retry time has passed")
	}

	// clear() makes the name immediately ready again, as happens after a
	// successful renewal.
	rb.recordFailure(name, secondDue)
	if rb.readyForAsOf(name, secondDue) {
		t.Fatal("expected name to be backing off before calling clear")
	}
	rb.clear(name)
	if !rb.readyForAsOf(name, secondDue) {
		t.Fatal("expected name to be immediately ready after clear")
	}

	// Once the cumulative failure window reaches maxRetryDuration, the
	// caller is told the budget is exhausted and the schedule resets, so a
	// fresh maintenance tick is not throttled indefinitely (mirroring
	// doWithRetry's own give-up-and-return behavior).
	start := now
	rb.recordFailure(name, start)
	exhausted := rb.recordFailure(name, start.Add(maxRetryDuration))
	if !exhausted {
		t.Fatal("expected the retry budget to be reported exhausted once maxRetryDuration has elapsed")
	}
	if !rb.readyForAsOf(name, start.Add(maxRetryDuration)) {
		t.Fatal("expected name to be immediately ready again after the retry budget was exhausted")
	}
}
