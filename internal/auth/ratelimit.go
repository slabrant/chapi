package auth

import (
	"sync"
	"time"
)

// RateLimiter is a per-key token bucket, used to slow password guessing at
// /login.
//
// This is the one place in the server that takes a lock. It is deliberately
// not hub state: it is touched once per login attempt, never on the message
// path, so channel-owned state would buy nothing here.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	burst     float64
	refill    float64 // tokens per second
	idle      time.Duration
	lastSweep time.Time

	now func() time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// NewRateLimiter allows burst attempts immediately, refilling to full over the
// given window.
func NewRateLimiter(burst int, window time.Duration) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now
	return &RateLimiter{
		buckets:   make(map[string]*bucket),
		burst:     float64(burst),
		refill:    float64(burst) / window.Seconds(),
		idle:      window * 4,
		lastSweep: now(),
		now:       now,
	}
}

// Allow consumes a token for key, reporting whether one was available.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.sweepLocked(now)

	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: r.burst}
		r.buckets[key] = b
	} else {
		b.tokens = min(r.burst, b.tokens+now.Sub(b.seen).Seconds()*r.refill)
	}
	b.seen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have sat idle long enough to have refilled,
// so a long uptime does not accumulate an entry per address ever seen.
func (r *RateLimiter) sweepLocked(now time.Time) {
	if now.Sub(r.lastSweep) < r.idle {
		return
	}
	r.lastSweep = now
	for key, b := range r.buckets {
		if now.Sub(b.seen) >= r.idle {
			delete(r.buckets, key)
		}
	}
}
