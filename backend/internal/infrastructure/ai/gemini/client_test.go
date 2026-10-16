package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sec_ops/internal/domain/interfaces"
)

func TestGenerateJSON_HappyPath(t *testing.T) {
	responseText := `{"risk": "High", "summary": "Multiple login failures detected"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []map[string]any{
				{
					"content": map[string]any{
						"parts": []map[string]any{
							{"text": responseText},
						},
					},
					"finishReason": "STOP",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 3,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "Analyze this log",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(result) != responseText {
		t.Errorf("expected %q, got %q", responseText, string(result))
	}
}

func TestGenerateJSON_APIKeyInHeaderNotQuery(t *testing.T) {
	const testKey = "secret-api-key-12345"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the API key is in the header
		headerKey := r.Header.Get("x-goog-api-key")
		if headerKey != testKey {
			t.Errorf("expected x-goog-api-key header = %q, got %q", testKey, headerKey)
		}
		// Verify the API key is NOT in the query string
		if strings.Contains(r.URL.RawQuery, testKey) {
			t.Errorf("API key leaked in query string: %s", r.URL.RawQuery)
		}
		if strings.Contains(r.URL.RawQuery, "key=") {
			t.Errorf("found 'key=' in query string, API key may be exposed: %s", r.URL.RawQuery)
		}

		resp := map[string]any{
			"candidates": []map[string]any{
				{"content": map[string]any{"parts": []map[string]any{{"text": `{"ok":true}`}}}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      testKey,
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	_, err := client.GenerateJSON(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateJSON_Retry429WithRetryInfo(t *testing.T) {
	var callCount atomic.Int32
	retryDelay := "2s"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count <= 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			errResp := map[string]any{
				"error": map[string]any{
					"code":   429,
					"status": "RESOURCE_EXHAUSTED",
					"details": []map[string]any{
						{
							"@type":      "type.googleapis.com/google.rpc.RetryInfo",
							"retryDelay": retryDelay,
						},
					},
				},
			}
			json.NewEncoder(w).Encode(errResp)
			return
		}
		// Third attempt succeeds
		resp := map[string]any{
			"candidates": []map[string]any{
				{"content": map[string]any{"parts": []map[string]any{{"text": `{"success":true}`}}}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 3,
	})
	// Override sleep to avoid waiting
	client.sleep = func(ctx context.Context, d time.Duration) error {
		// Verify retry delay is respected (should be at least 2s from RetryInfo)
		if d < 2*time.Second {
			t.Errorf("expected retry delay >= 2s, got %v", d)
		}
		return nil
	}

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	start := time.Now()
	result, err := client.GenerateJSON(context.Background(), req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected eventual success, got error: %v", err)
	}
	if !strings.Contains(string(result), "success") {
		t.Errorf("unexpected result: %s", result)
	}
	if callCount.Load() != 3 {
		t.Errorf("expected 3 calls (2 failures + 1 success), got %d", callCount.Load())
	}
	// Should complete quickly since we mocked sleep
	if elapsed > 1*time.Second {
		t.Errorf("test took too long, sleep override may not be working: %v", elapsed)
	}
}

func TestGenerateJSON_Retry429WithRetryAfterHeader(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": 429, "status": "RESOURCE_EXHAUSTED"},
			})
			return
		}
		// Second attempt succeeds
		resp := map[string]any{
			"candidates": []map[string]any{
				{"content": map[string]any{"parts": []map[string]any{{"text": `{"ok":true}`}}}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 2,
	})
	client.sleep = func(ctx context.Context, d time.Duration) error {
		// Should use Retry-After value (3s) if it's larger than backoff
		if d < 3*time.Second {
			t.Errorf("expected retry delay >= 3s from Retry-After, got %v", d)
		}
		return nil
	}

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	_, err := client.GenerateJSON(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 calls, got %d", callCount.Load())
	}
}

func TestGenerateJSON_Persistent500ReturnsUpstreamUnavailable(t *testing.T) {
	var callCount atomic.Int32
	const maxAttempts = 3

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: maxAttempts,
	})
	client.sleep = func(ctx context.Context, d time.Duration) error { return nil }

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error, got result: %s", result)
	}
	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}
	if callCount.Load() != int32(maxAttempts) {
		t.Errorf("expected %d attempts, got %d", maxAttempts, callCount.Load())
	}
}

func TestGenerateJSON_400DoesNotRetry(t *testing.T) {
	var callCount atomic.Int32
	requestBodySample := "sensitive-data-should-not-leak"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		// Echo back request body to simulate server including it in error
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    400,
				"message": "Invalid request: " + requestBodySample,
			},
		})
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 3,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: requestBodySample,
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error, got result: %s", result)
	}

	// Verify exactly one request was made (no retry)
	if callCount.Load() != 1 {
		t.Errorf("expected exactly 1 request (no retry), got %d", callCount.Load())
	}

	// Verify the error does NOT leak the request body
	errMsg := err.Error()
	if strings.Contains(errMsg, requestBodySample) {
		t.Errorf("error message leaked request body: %v", err)
	}

	// Verify error is not wrapped with retryable sentinels
	if errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("400 error should not be ErrUpstreamUnavailable")
	}
	if errors.Is(err, interfaces.ErrQuotaExceeded) {
		t.Errorf("400 error should not be ErrQuotaExceeded")
	}
}

func TestGenerateJSON_BlockReasonProducesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []map[string]any{},
			"promptFeedback": map[string]any{
				"blockReason": "SAFETY",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for blocked prompt, got result: %s", result)
	}
	if !strings.Contains(err.Error(), "blocked") || !strings.Contains(err.Error(), "SAFETY") {
		t.Errorf("expected error mentioning block reason, got: %v", err)
	}
}

func TestGenerateJSON_MultipleParts(t *testing.T) {
	// Test that multiple parts are concatenated correctly
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []map[string]any{
				{
					"content": map[string]any{
						"parts": []map[string]any{
							{"text": `{"part": 1,`},
							{"text": ` "more": "data"}`},
						},
					},
					"finishReason": "STOP",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the parts were concatenated
	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed["part"] != float64(1) || parsed["more"] != "data" {
		t.Errorf("parts not concatenated correctly: %s", result)
	}
}

func TestGenerateJSON_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []map[string]any{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for empty response, got: %s", result)
	}
	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}
}

func TestGenerateJSON_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []map[string]any{
				{
					"content": map[string]any{
						"parts": []map[string]any{
							{"text": `not valid json {`},
						},
					},
					"finishReason": "MAX_TOKENS",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got: %s", result)
	}
	if !strings.Contains(err.Error(), "non-JSON") {
		t.Errorf("expected error about non-JSON output, got: %v", err)
	}
}

func TestGenerateJSON_Unconfigured(t *testing.T) {
	client := New(Config{
		APIKey:      "", // empty = unconfigured
		BaseURL:     "http://unused",
		RPM:         600,
		MaxAttempts: 1,
	})

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for unconfigured client, got: %s", result)
	}
	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected error to mention configuration, got: %v", err)
	}
}

func TestGenerateJSON_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := map[string]any{
			"candidates": []map[string]any{
				{"content": map[string]any{"parts": []map[string]any{{"text": `{"ok":true}`}}}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(Config{
		APIKey:      "test-key",
		BaseURL:     srv.URL,
		RPM:         600,
		MaxAttempts: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := interfaces.JSONGenerationRequest{
		Prompt: "test",
		Schema: map[string]any{"type": "object"},
	}

	result, err := client.GenerateJSON(ctx, req)
	if err == nil {
		t.Fatalf("expected context cancellation error, got result: %s", result)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestConfigured(t *testing.T) {
	tests := []struct {
		name   string
		client *Client
		want   bool
	}{
		{
			name:   "configured with API key",
			client: New(Config{APIKey: "test-key", BaseURL: "http://test"}),
			want:   true,
		},
		{
			name:   "unconfigured without API key",
			client: New(Config{APIKey: "", BaseURL: "http://test"}),
			want:   false,
		},
		{
			name:   "nil client",
			client: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.client.Configured(); got != tt.want {
				t.Errorf("Configured() = %v, want %v", got, tt.want)
			}
		})
	}
}
