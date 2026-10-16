// Package httpx holds small helpers shared by the outbound HTTP adapters.
package httpx

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// MaxResponseBytes caps how much of any upstream response is read.
const MaxResponseBytes = 2 << 20

func ReadLimited(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, MaxResponseBytes))
}

// NewClient returns an HTTP client with a total timeout and no redirect
// following (webhook and API endpoints never legitimately redirect; following
// redirects would let a compromised endpoint bounce requests elsewhere).
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Limiter spaces calls at least interval apart (a minimal token bucket of
// size 1). It holds per-instance; Cloud Run runs with --max-instances 1.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
}

func NewLimiter(perMinute int) *Limiter {
	if perMinute <= 0 {
		perMinute = 1
	}
	return &Limiter{interval: time.Minute / time.Duration(perMinute), now: time.Now}
}

// Wait blocks until the caller may proceed or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.now()
	start := l.next
	if start.Before(now) {
		start = now
	}
	l.next = start.Add(l.interval)
	l.mu.Unlock()

	d := start.Sub(now)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Backoff returns the delay before retry attempt n (1-based): exponential
// with full jitter, capped.
func Backoff(n int, base, cap time.Duration) time.Duration {
	d := base << (n - 1)
	if d > cap || d <= 0 {
		d = cap
	}
	return time.Duration(rand.Int64N(int64(d)/2+1)) + d/2
}

// RetryAfter parses a Retry-After header in seconds (HTTP-date form ignored).
func RetryAfter(h http.Header) time.Duration {
	if s := h.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

// Sleep waits d or until ctx is done.
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
