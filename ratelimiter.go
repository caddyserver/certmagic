package certmagic

import (
	"sync"
	"time"
)

// NewRateLimiter returns a rate limiter that allows up to
// maxEvents in a sliding window of size window.
func NewRateLimiter(maxEvents int, window time.Duration) *RingBufferRateLimiter {
	return &RingBufferRateLimiter{
		window: window,
		ring:   make([]time.Time, maxEvents),
	}
}

// RingBufferRateLimiter uses a ring to enforce rate limits
// consisting of a maximum number of events within a single
// sliding window of a given duration. An empty value is
// not valid; use NewRateLimiter to get one.
type RingBufferRateLimiter struct {
	window time.Duration
	ring   []time.Time
	cursor int // always points to the oldest timestamp
	mu     sync.Mutex
}

// Allow returns true if the event is allowed to
// happen right now. It does not wait. If the event
// is allowed, a reservation is made.
func (r *RingBufferRateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.ring[r.cursor]) >= r.window {
		r.reserve(time.Now())
		return true
	}
	return false
}

// Wait makes a reservation then blocks until the
// event is allowed to occur.
func (r *RingBufferRateLimiter) Wait() {
	r.mu.Lock()
	if r.ring[r.cursor].IsZero() {
		r.reserve(time.Now())
		r.mu.Unlock()
		return
	}
	then := r.ring[r.cursor].Add(r.window)
	r.reserve(then)
	r.mu.Unlock()
	time.Sleep(time.Until(then))
}

// SetMaxEvents changes the maximum number of events that are
// allowed in the sliding window. If the new limit is lower,
// the oldest events will be forgotten. If the new limit is
// higher, the window will suddenly have capacity for new
// reservations.
func (r *RingBufferRateLimiter) SetMaxEvents(maxEvents int) {
	newRing := make([]time.Time, maxEvents)
	r.mu.Lock()
	defer r.mu.Unlock()

	// the new ring may be smaller; fast-forward to the
	// oldest timestamp that will be kept in the new
	// ring so the oldest ones are forgotten and the
	// newest ones will be remembered
	sizeDiff := len(r.ring) - maxEvents
	for i := 0; i < sizeDiff; i++ {
		r.advance()
	}

	// copy timestamps into the new ring until we
	// have either copied all of them or have reached
	// the capacity of the new ring
	startCursor := r.cursor
	for i := 0; i < len(newRing); i++ {
		newRing[i] = r.ring[r.cursor]
		r.advance()
		if r.cursor == startCursor {
			// new ring is larger than old one;
			// "we've come full circle"
			break
		}
	}

	r.ring = newRing
	r.cursor = 0
}

// SetWindow changes r's sliding window duration to window.
// Goroutines that are already blocked on a call to Wait()
// will not be affected.
func (r *RingBufferRateLimiter) SetWindow(window time.Duration) {
	r.mu.Lock()
	r.window = window
	r.mu.Unlock()
}

// reserve claims the current spot at the head of
// the window. It is NOT safe for concurrent use,
// so it must be called inside a lock on r.mu.
func (r *RingBufferRateLimiter) reserve(when time.Time) {
	r.ring[r.cursor] = when
	r.advance()
}

// advance moves the cursor to the next position.
// It is NOT safe for concurrent use, so it must
// be called inside a lock on r.mu.
func (r *RingBufferRateLimiter) advance() {
	r.cursor++
	if r.cursor >= len(r.ring) {
		r.cursor = 0
	}
}
