package certmagic

import (
	"context"
	"errors"
	"log"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

var jm = &jobManager{maxConcurrentJobs: 1000}

type jobManager struct {
	mu                sync.Mutex
	maxConcurrentJobs int
	activeWorkers     int
	queue             []namedJob
	names             map[string]struct{}
}

type namedJob struct {
	name   string
	job    func() error
	logger *zap.Logger
}

// Submit enqueues the given job with the given name. If name is non-empty
// and a job with the same name is already enqueued or running, this is a
// no-op. If name is empty, no duplicate prevention will occur. The job
// manager will then run this job as soon as it is able.
func (jm *jobManager) Submit(logger *zap.Logger, name string, job func() error) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if jm.names == nil {
		jm.names = make(map[string]struct{})
	}
	if name != "" {
		// prevent duplicate jobs
		if _, ok := jm.names[name]; ok {
			return
		}
		jm.names[name] = struct{}{}
	}
	jm.queue = append(jm.queue, namedJob{name, job, logger})
	if jm.activeWorkers < jm.maxConcurrentJobs {
		jm.activeWorkers++
		go jm.worker()
	}
}

func (jm *jobManager) worker() {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic: certificate worker: %v\n%s", err, buf)
		}
		// Decrement activeWorkers here (rather than inline at the
		// queue-empty branch) so that the counter is correctly released
		// even when the worker exits via a recovered panic. Otherwise the
		// counter drifts upward and eventually no new workers ever spawn.
		jm.mu.Lock()
		jm.activeWorkers--
		jm.mu.Unlock()
	}()

	for {
		jm.mu.Lock()
		if len(jm.queue) == 0 {
			jm.mu.Unlock()
			return
		}
		next := jm.queue[0]
		jm.queue = jm.queue[1:]
		jm.mu.Unlock()
		// Run the job inside a closure so that the name is always removed
		// from jm.names, even if the job panics. Otherwise the name would
		// stay in the in-flight set and future Submit() calls for the same
		// name would be silently dropped until process restart.
		func() {
			defer func() {
				if next.name != "" {
					jm.mu.Lock()
					delete(jm.names, next.name)
					jm.mu.Unlock()
				}
			}()
			if err := next.job(); err != nil {
				next.logger.Error("job failed", zap.Error(err))
			}
		}()
	}
}

// renewalBackoff tracks, per certificate name, when the next renewal
// attempt driven by the periodic maintenance loop is allowed to run. It
// exists so that queueRenewalTask can make a single renewal attempt per
// call (via renewCertOnce) instead of submitting a job to jm that loops
// internally through retryIntervals for up to maxRetryDuration -- which
// would otherwise occupy jm's dedup slot for that name and cause
// subsequent maintenance ticks to silently no-op via jm.Submit until the
// long-lived job's own internal sleep happens to wake up (up to 6 hours
// later). By moving the schedule here, the periodic maintenance tick
// (which already runs every RenewCheckInterval and only proceeds if the
// certificate still needs renewal) becomes the actual retry driver, while
// still following the same backoff schedule as doWithRetry.
type renewalBackoff struct {
	mu    sync.Mutex
	state map[string]*renewalBackoffState
}

type renewalBackoffState struct {
	nextAttempt  time.Time
	intervalIdx  int // -1 until the first failed attempt
	firstAttempt time.Time
}

var renewalRetrySchedule = &renewalBackoff{}

// readyFor reports whether name is currently allowed to attempt a renewal.
// It is always true for a name with no recorded failure.
func (rb *renewalBackoff) readyFor(name string) bool {
	return rb.readyForAsOf(name, time.Now())
}

// readyForAsOf is like readyFor but evaluates readiness as of the given
// time instead of time.Now(); it exists so tests can exercise the backoff
// schedule without sleeping for real minutes/hours/days.
func (rb *renewalBackoff) readyForAsOf(name string, asOf time.Time) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	st, ok := rb.state[name]
	if !ok {
		return true
	}
	return !asOf.Before(st.nextAttempt)
}

// recordFailure schedules the next allowed attempt for name using the same
// retryIntervals/maxRetryDuration schedule as doWithRetry. It reports
// whether the overall retry budget (maxRetryDuration since the first
// recorded failure in this cycle) has been exhausted. If exhausted, the
// backoff cycle for name is reset (mirroring doWithRetry's own behavior of
// giving up and returning), so the next maintenance tick will attempt
// immediately rather than being throttled forever; if the certificate still
// needs renewal by then, a fresh backoff cycle begins.
func (rb *renewalBackoff) recordFailure(name string, now time.Time) (exhausted bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.state == nil {
		rb.state = make(map[string]*renewalBackoffState)
	}
	st, ok := rb.state[name]
	if !ok {
		st = &renewalBackoffState{intervalIdx: -1, firstAttempt: now}
		rb.state[name] = st
	}
	if now.Sub(st.firstAttempt) >= maxRetryDuration {
		delete(rb.state, name)
		return true
	}
	if st.intervalIdx < len(retryIntervals)-1 {
		st.intervalIdx++
	}
	st.nextAttempt = now.Add(retryIntervals[st.intervalIdx])
	return false
}

// clear forgets any recorded backoff state for name, e.g. after a
// successful renewal or once the certificate no longer needs renewing.
func (rb *renewalBackoff) clear(name string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	delete(rb.state, name)
}

func doWithRetry(ctx context.Context, log *zap.Logger, f func(context.Context) error) error {
	var attempts int
	ctx = context.WithValue(ctx, AttemptsCtxKey, &attempts)

	// the initial intervalIndex is -1, signaling
	// that we should not wait for the first attempt
	start, intervalIndex := time.Now(), -1
	var err error

	for time.Since(start) < maxRetryDuration {
		var wait time.Duration
		if intervalIndex >= 0 {
			wait = retryIntervals[intervalIndex]
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Canceled
		case <-timer.C:
			err = f(ctx)
			attempts++
			if err == nil || errors.Is(err, context.Canceled) {
				return err
			}
			var errNoRetry ErrNoRetry
			if errors.As(err, &errNoRetry) {
				return err
			}
			if intervalIndex < len(retryIntervals)-1 {
				intervalIndex++
			}
			if time.Since(start) < maxRetryDuration {
				log.Error("will retry",
					zap.Error(err),
					zap.Int("attempt", attempts),
					zap.Duration("retrying_in", retryIntervals[intervalIndex]),
					zap.Duration("elapsed", time.Since(start)),
					zap.Duration("max_duration", maxRetryDuration))
			} else {
				log.Error("final attempt; giving up",
					zap.Error(err),
					zap.Int("attempt", attempts),
					zap.Duration("elapsed", time.Since(start)),
					zap.Duration("max_duration", maxRetryDuration))
				return err
			}
		}
	}
	return err
}

// ErrNoRetry is an error type which signals
// to stop retries early.
type ErrNoRetry struct{ Err error }

// Unwrap makes it so that e wraps e.Err.
func (e ErrNoRetry) Unwrap() error { return e.Err }
func (e ErrNoRetry) Error() string { return e.Err.Error() }

type retryStateCtxKey struct{}

// AttemptsCtxKey is the context key for the value
// that holds the attempt counter. The value counts
// how many times the operation has been attempted.
// A value of 0 means first attempt.
var AttemptsCtxKey retryStateCtxKey

// retryIntervals are based on the idea of exponential
// backoff, but weighed a little more heavily to the
// front. We figure that intermittent errors would be
// resolved after the first retry, but any errors after
// that would probably require at least a few minutes
// or hours to clear up: either for DNS to propagate, for
// the administrator to fix their DNS or network config,
// or some other external factor needs to change. We
// chose intervals that we think will be most useful
// without introducing unnecessary delay. The last
// interval in this list will be used until the time
// of maxRetryDuration has elapsed.
var retryIntervals = []time.Duration{
	1 * time.Minute,
	2 * time.Minute,
	2 * time.Minute,
	5 * time.Minute, // elapsed: 10 min
	10 * time.Minute,
	10 * time.Minute,
	10 * time.Minute,
	20 * time.Minute, // elapsed: 1 hr
	20 * time.Minute,
	20 * time.Minute,
	20 * time.Minute, // elapsed: 2 hr
	30 * time.Minute,
	30 * time.Minute, // elapsed: 3 hr
	30 * time.Minute,
	30 * time.Minute, // elapsed: 4 hr
	30 * time.Minute,
	30 * time.Minute, // elapsed: 5 hr
	1 * time.Hour,    // elapsed: 6 hr
	1 * time.Hour,
	1 * time.Hour, // elapsed: 8 hr
	2 * time.Hour,
	2 * time.Hour, // elapsed: 12 hr
	3 * time.Hour,
	3 * time.Hour, // elapsed: 18 hr
	6 * time.Hour, // repeat for up to maxRetryDuration
}

// maxRetryDuration is the maximum duration to try
// doing retries using the above intervals.
const maxRetryDuration = 24 * time.Hour * 30
