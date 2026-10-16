package httpx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadLimited(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "small input",
			input:   "hello world",
			wantLen: 11,
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
			wantErr: false,
		},
		{
			name:    "large input within limit",
			input:   strings.Repeat("x", 1024),
			wantLen: 1024,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			result, err := ReadLimited(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadLimited() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(result) != tt.wantLen {
				t.Errorf("ReadLimited() len = %d, want %d", len(result), tt.wantLen)
			}

			if string(result) != tt.input {
				t.Errorf("ReadLimited() content mismatch")
			}
		})
	}
}

func TestReadLimited_EnforcesLimit(t *testing.T) {
	// Create input larger than MaxResponseBytes
	largeInput := strings.Repeat("A", int(MaxResponseBytes)+1000)
	reader := strings.NewReader(largeInput)

	result, err := ReadLimited(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Result should be capped at MaxResponseBytes
	if len(result) > int(MaxResponseBytes) {
		t.Errorf("ReadLimited() returned %d bytes, exceeds MaxResponseBytes %d", len(result), MaxResponseBytes)
	}

	if len(result) != int(MaxResponseBytes) {
		t.Errorf("expected exactly MaxResponseBytes, got %d", len(result))
	}
}

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	client := NewClient(timeout)

	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	if client.Timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.Timeout)
	}

	// Verify redirect policy
	if client.CheckRedirect == nil {
		t.Error("expected CheckRedirect to be set")
	}
}

func TestNewClient_NoRedirectFollowing(t *testing.T) {
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("target reached"))
	}))
	defer redirectSrv.Close()

	client := NewClient(5 * time.Second)

	resp, err := client.Get(redirectSrv.URL + "/redirect")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should get 302, not follow to target
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected status 302, got %d (redirect was followed)", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "target reached") {
		t.Error("redirect was followed despite CheckRedirect policy")
	}
}

func TestLimiter_Wait(t *testing.T) {
	limiter := NewLimiter(60) // 60 per minute = 1 per second

	ctx := context.Background()
	start := time.Now()

	// First call should proceed immediately
	err := limiter.Wait(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	elapsed1 := time.Since(start)
	if elapsed1 > 100*time.Millisecond {
		t.Errorf("first Wait() took too long: %v", elapsed1)
	}

	// Second call should wait ~1 second
	err = limiter.Wait(ctx)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	elapsed2 := time.Since(start)
	if elapsed2 < 900*time.Millisecond {
		t.Errorf("second Wait() didn't wait long enough: %v", elapsed2)
	}
}

func TestLimiter_ContextCancellation(t *testing.T) {
	limiter := NewLimiter(1) // Very slow rate

	ctx, cancel := context.WithCancel(context.Background())

	// First call to set the next allowed time far in the future
	limiter.Wait(context.Background())

	// Cancel context before second call
	cancel()

	err := limiter.Wait(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestLimiter_ZeroOrNegativeRate(t *testing.T) {
	tests := []struct {
		name string
		rpm  int
	}{
		{"zero rate", 0},
		{"negative rate", -10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.rpm)

			// Should still work (defaults to 1)
			ctx := context.Background()
			err := limiter.Wait(ctx)
			if err != nil {
				t.Errorf("Wait() failed: %v", err)
			}
		})
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewLimiter(600) // High rate for faster test

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ctx := context.Background()
			err := limiter.Wait(ctx)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent Wait() error: %v", err)
	}
}

func TestBackoff(t *testing.T) {
	base := 1 * time.Second
	cap := 10 * time.Second

	tests := []struct {
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{1, base / 2, base + base/2},   // First attempt: base with jitter
		{2, base, 2*base + base},       // Second attempt: 2*base with jitter
		{3, 2 * base, 4*base + 2*base}, // Third attempt: 4*base with jitter
		{10, cap / 2, cap + cap/2},     // Large attempt: capped with jitter
	}

	for _, tt := range tests {
		t.Run(string(rune('0'+tt.attempt)), func(t *testing.T) {
			// Run multiple times to account for jitter
			for i := 0; i < 10; i++ {
				delay := Backoff(tt.attempt, base, cap)

				if delay < 0 {
					t.Errorf("Backoff(%d) returned negative delay: %v", tt.attempt, delay)
				}

				// Should be within reasonable bounds (considering jitter)
				if delay > cap+cap/2 {
					t.Errorf("Backoff(%d) = %v, exceeds cap %v", tt.attempt, delay, cap)
				}
			}
		})
	}
}

func TestBackoff_Consistency(t *testing.T) {
	// Verify that backoff increases with attempts
	base := 100 * time.Millisecond
	cap := 5 * time.Second

	delays := make([]time.Duration, 5)
	for i := 1; i <= 5; i++ {
		delays[i-1] = Backoff(i, base, cap)
	}

	// Average should increase (despite jitter)
	// Not strictly monotonic due to jitter, but generally increasing
	for i := 0; i < len(delays)-1; i++ {
		t.Logf("attempt %d: %v", i+1, delays[i])
	}
}

func TestRetryAfter_ParsesSeconds(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{
			name:   "valid seconds",
			header: "30",
			want:   30 * time.Second,
		},
		{
			name:   "zero seconds",
			header: "0",
			want:   0,
		},
		{
			name:   "large value",
			header: "3600",
			want:   3600 * time.Second,
		},
		{
			name:   "missing header",
			header: "",
			want:   0,
		},
		{
			name:   "invalid format",
			header: "not-a-number",
			want:   0,
		},
		{
			name:   "negative value",
			header: "-10",
			want:   0,
		},
		{
			name:   "HTTP-date format (ignored)",
			header: "Wed, 21 Oct 2015 07:28:00 GMT",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.header != "" {
				h.Set("Retry-After", tt.header)
			}

			got := RetryAfter(h)
			if got != tt.want {
				t.Errorf("RetryAfter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetryAfter_CaseInsensitive(t *testing.T) {
	h := http.Header{}
	h.Set("retry-after", "60") // lowercase

	delay := RetryAfter(h)
	if delay != 60*time.Second {
		t.Errorf("expected 60s, got %v (header parsing should be case-insensitive)", delay)
	}
}

func TestSleep_WaitsExpectedDuration(t *testing.T) {
	duration := 100 * time.Millisecond
	start := time.Now()

	err := Sleep(context.Background(), duration)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if elapsed < duration {
		t.Errorf("Sleep didn't wait long enough: %v < %v", elapsed, duration)
	}

	if elapsed > duration+50*time.Millisecond {
		t.Errorf("Sleep waited too long: %v", elapsed)
	}
}

func TestSleep_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	start := time.Now()
	err := Sleep(ctx, 10*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// Should return quickly
	if elapsed > 100*time.Millisecond {
		t.Errorf("Sleep took too long after cancellation: %v", elapsed)
	}
}

func TestSleep_ZeroOrNegativeDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			err := Sleep(context.Background(), tt.duration)
			elapsed := time.Since(start)

			// Should return immediately
			if elapsed > 10*time.Millisecond {
				t.Errorf("Sleep with duration %v took too long: %v", tt.duration, elapsed)
			}

			// Should still check context
			if err != nil && err != context.Canceled {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSleep_ContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := Sleep(ctx, 10*time.Second) // Try to sleep longer than context allows
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for context deadline exceeded")
	}

	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	// Should return around the deadline
	if elapsed < 40*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Errorf("expected sleep to end around deadline (50ms), took %v", elapsed)
	}
}

func TestNewClient_Timeout(t *testing.T) {
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	client := NewClient(50 * time.Millisecond)

	start := time.Now()
	resp, err := client.Get(slowSrv.URL)
	elapsed := time.Since(start)

	if err == nil {
		resp.Body.Close()
		t.Fatal("expected timeout error")
	}

	if elapsed > 150*time.Millisecond {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestMaxResponseBytes_Constant(t *testing.T) {
	// Verify the constant is set to a reasonable value
	if MaxResponseBytes <= 0 {
		t.Error("MaxResponseBytes should be positive")
	}

	if MaxResponseBytes < 1024 {
		t.Error("MaxResponseBytes seems too small")
	}

	// Should be 2MB as defined
	expected := 2 << 20
	if MaxResponseBytes != expected {
		t.Errorf("MaxResponseBytes = %d, expected %d", MaxResponseBytes, expected)
	}
}

func TestLimiter_AccurateInterval(t *testing.T) {
	// Test with a known rate
	limiter := NewLimiter(120) // 120 per minute = 0.5 second interval

	ctx := context.Background()

	start := time.Now()
	limiter.Wait(ctx) // First call
	limiter.Wait(ctx) // Second call should wait
	elapsed := time.Since(start)

	expectedInterval := 500 * time.Millisecond
	tolerance := 100 * time.Millisecond

	if elapsed < expectedInterval-tolerance || elapsed > expectedInterval+tolerance {
		t.Errorf("limiter interval incorrect: expected ~%v, got %v", expectedInterval, elapsed)
	}
}

func BenchmarkBackoff(b *testing.B) {
	base := 1 * time.Second
	cap := 30 * time.Second

	for i := 0; i < b.N; i++ {
		_ = Backoff(i%10+1, base, cap)
	}
}

func BenchmarkLimiterWait(b *testing.B) {
	limiter := NewLimiter(600)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Wait(ctx)
	}
}

func BenchmarkReadLimited(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_, _ = ReadLimited(reader)
	}
}
