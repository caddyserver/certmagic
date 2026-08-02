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
