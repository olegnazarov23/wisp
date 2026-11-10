package stats

import (
	"net"
	"sync"
	"time"
)

// ThrottledConn wraps a net.Conn with rate limiting.
// Uses a token bucket algorithm — simple, no jitter, minimal CPU overhead.
type ThrottledConn struct {
	net.Conn
	limiter *RateLimiter
}

// WrapThrottled wraps a connection with both byte counting and speed limiting. The limit is the
// user's: all their connections share it.
func WrapThrottled(conn net.Conn, username string, bytesPerSec int64) *ThrottledConn {
	counted := WrapConn(conn, username)
	var limiter *RateLimiter
	if bytesPerSec > 0 {
		limiter = counted.stats.rateLimiter(bytesPerSec)
	}
	return &ThrottledConn{Conn: counted, limiter: limiter}
}

// rateLimiter returns the user's limiter, made on first use.
func (s *UserStats) rateLimiter(bytesPerSec int64) *RateLimiter {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	if s.limiter == nil {
		s.limiter = NewRateLimiter(bytesPerSec)
	}
	return s.limiter
}

func (c *ThrottledConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.limiter != nil {
		c.limiter.Wait(n)
	}
	return n, err
}

func (c *ThrottledConn) Write(b []byte) (int, error) {
	if c.limiter != nil {
		c.limiter.Wait(len(b))
	}
	return c.Conn.Write(b)
}

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per nanosecond
	lastRefill time.Time
}

// NewRateLimiter creates a limiter that allows bytesPerSec throughput.
// Burst size is set to 2x the per-second rate for smooth streaming.
func NewRateLimiter(bytesPerSec int64) *RateLimiter {
	burst := float64(bytesPerSec) * 2
	return &RateLimiter{
		tokens:     burst, // Start full.
		maxTokens:  burst,
		refillRate: float64(bytesPerSec) / float64(time.Second),
		lastRefill: time.Now(),
	}
}

// Wait blocks until enough tokens are available for n bytes.
func (r *RateLimiter) Wait(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refill()

	needed := float64(n)
	for r.tokens < needed {
		// Calculate wait time for enough tokens.
		deficit := needed - r.tokens
		waitTime := time.Duration(deficit / r.refillRate)
		if waitTime < time.Millisecond {
			waitTime = time.Millisecond
		}
		r.mu.Unlock()
		time.Sleep(waitTime)
		r.mu.Lock()
		r.refill()
	}

	r.tokens -= needed
}

func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)
	r.tokens += float64(elapsed) * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefill = now
}
