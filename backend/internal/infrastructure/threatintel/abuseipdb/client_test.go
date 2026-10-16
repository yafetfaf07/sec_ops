package abuseipdb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sec_ops/internal/domain/interfaces"
)

func TestCheck_HappyPath(t *testing.T) {
	const testIP = "192.0.2.42"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the API key is sent via Key header
		if key := r.Header.Get("Key"); key != "test-api-key" {
			t.Errorf("expected Key header = 'test-api-key', got %q", key)
		}

		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            testIP,
				"abuseConfidenceScore": 75,
				"countryCode":          "US",
				"totalReports":         23,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New("test-api-key", srv.URL, nil)
	// Mock time for deterministic testing
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }

	result, err := client.Check(context.Background(), testIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IP != testIP {
		t.Errorf("expected IP %q, got %q", testIP, result.IP)
	}
	if result.AbuseConfidence != 75 {
		t.Errorf("expected AbuseConfidence = 75, got %d", result.AbuseConfidence)
	}
	if result.Country != "US" {
		t.Errorf("expected Country = 'US', got %q", result.Country)
	}
	if result.TotalReports != 23 {
		t.Errorf("expected TotalReports = 23, got %d", result.TotalReports)
	}
	if !result.FetchedAt.Equal(now) {
		t.Errorf("expected FetchedAt = %v, got %v", now, result.FetchedAt)
	}

	// ExpiresAt should be ~24h after FetchedAt
	expectedExpiry := now.Add(24 * time.Hour)
	if !result.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("expected ExpiresAt = %v, got %v", expectedExpiry, result.ExpiresAt)
	}
}

func TestCheck_InvalidIPReturnsValidationError(t *testing.T) {
	var httpCallMade bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCallMade = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New("test-api-key", srv.URL, nil)

	tests := []struct {
		name      string
		ip        string
		wantError string
	}{
		{
			name:      "empty string",
			ip:        "",
			wantError: "invalid IP",
		},
		{
			name:      "malformed IP",
			ip:        "not-an-ip",
			wantError: "invalid IP",
		},
		{
			name:      "partial IP",
			ip:        "192.0.2",
			wantError: "invalid IP",
		},
		{
			name:      "out of range",
			ip:        "999.999.999.999",
			wantError: "invalid IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpCallMade = false
			result, err := client.Check(context.Background(), tt.ip)

			if err == nil {
				t.Fatalf("expected error, got result: %+v", result)
			}

			if !errors.Is(err, interfaces.ErrValidation) {
				t.Errorf("expected ErrValidation, got: %v", err)
			}

			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("expected error containing %q, got: %v", tt.wantError, err)
			}

			if httpCallMade {
				t.Error("HTTP call was made despite invalid IP (should fail fast)")
			}
		})
	}
}

func TestCheck_429ReturnsQuotaExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{
				{"detail": "Daily rate limit exceeded"},
			},
		})
	}))
	defer srv.Close()

	client := New("test-api-key", srv.URL, nil)

	result, err := client.Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatalf("expected error, got result: %+v", result)
	}

	if !errors.Is(err, interfaces.ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got: %v", err)
	}

	if !strings.Contains(err.Error(), "daily limit") {
		t.Errorf("expected error mentioning daily limit, got: %v", err)
	}
}

func TestCheck_500ReturnsUpstreamUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer srv.Close()

	client := New("test-api-key", srv.URL, nil)

	result, err := client.Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatalf("expected error, got result: %+v", result)
	}

	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}

	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected error mentioning status code, got: %v", err)
	}
}

func TestCheck_503ReturnsUpstreamUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}))
	defer srv.Close()

	client := New("test-api-key", srv.URL, nil)

	result, err := client.Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatalf("expected error, got result: %+v", result)
	}

	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}
}

func TestCheck_APIKeySentViaKeyHeader(t *testing.T) {
	const testKey = "secret-abuseipdb-key-xyz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyHeader := r.Header.Get("Key")
		if keyHeader != testKey {
			t.Errorf("expected Key header = %q, got %q", testKey, keyHeader)
		}

		// Verify it's not sent in other ways
		if auth := r.Header.Get("Authorization"); strings.Contains(auth, testKey) {
			t.Errorf("API key leaked in Authorization header: %s", auth)
		}
		if strings.Contains(r.URL.RawQuery, testKey) {
			t.Errorf("API key leaked in query string: %s", r.URL.RawQuery)
		}

		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            "192.0.2.1",
				"abuseConfidenceScore": 0,
				"countryCode":          "",
				"totalReports":         0,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New(testKey, srv.URL, nil)
	_, err := client.Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheck_ScoreClampingAndNegativeHandling(t *testing.T) {
	tests := []struct {
		name          string
		serverScore   int
		serverReports int
		wantScore     int
		wantReports   int
	}{
		{
			name:          "normal score",
			serverScore:   50,
			serverReports: 10,
			wantScore:     50,
			wantReports:   10,
		},
		{
			name:          "over 100 clamped",
			serverScore:   150,
			serverReports: 5,
			wantScore:     100,
			wantReports:   5,
		},
		{
			name:          "negative score clamped to 0",
			serverScore:   -1,
			serverReports: 0,
			wantScore:     0,
			wantReports:   0,
		},
		{
			name:          "negative reports clamped to 0",
			serverScore:   25,
			serverReports: -5,
			wantScore:     25,
			wantReports:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]any{
					"data": map[string]any{
						"ipAddress":            "192.0.2.1",
						"abuseConfidenceScore": tt.serverScore,
						"countryCode":          "XX",
						"totalReports":         tt.serverReports,
					},
				}
				json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()

			client := New("test-key", srv.URL, nil)
			result, err := client.Check(context.Background(), "192.0.2.1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.AbuseConfidence != tt.wantScore {
				t.Errorf("expected AbuseConfidence = %d, got %d", tt.wantScore, result.AbuseConfidence)
			}
			if result.TotalReports != tt.wantReports {
				t.Errorf("expected TotalReports = %d, got %d", tt.wantReports, result.TotalReports)
			}
		})
	}
}

func TestCheck_IPv6Support(t *testing.T) {
	testIP := "2001:db8::1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query parameter
		if !strings.Contains(r.URL.RawQuery, "2001%3Adb8%3A%3A1") && !strings.Contains(r.URL.RawQuery, "2001:db8::1") {
			t.Errorf("expected IPv6 address in query, got: %s", r.URL.RawQuery)
		}

		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            testIP,
				"abuseConfidenceScore": 10,
				"countryCode":          "US",
				"totalReports":         1,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New("test-key", srv.URL, nil)
	result, err := client.Check(context.Background(), testIP)
	if err != nil {
		t.Fatalf("unexpected error for valid IPv6: %v", err)
	}

	if result.IP != testIP {
		t.Errorf("expected IP %q, got %q", testIP, result.IP)
	}
}

func TestCheck_MalformedJSONReturnsUpstreamUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	client := New("test-key", srv.URL, nil)
	result, err := client.Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got result: %+v", result)
	}

	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}

	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected error mentioning malformed response, got: %v", err)
	}
}

func TestCheck_Unconfigured(t *testing.T) {
	client := New("", "http://unused", nil)

	result, err := client.Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatalf("expected error for unconfigured client, got result: %+v", result)
	}

	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}

	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected error mentioning configuration, got: %v", err)
	}
}

func TestCheck_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            "192.0.2.1",
				"abuseConfidenceScore": 0,
				"countryCode":          "",
				"totalReports":         0,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New("test-key", srv.URL, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := client.Check(ctx, "192.0.2.1")
	if err == nil {
		t.Fatalf("expected context cancellation error, got result: %+v", result)
	}

	// Context errors should be returned as-is or wrapped
	if !errors.Is(err, context.Canceled) && !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected context.Canceled or ErrUpstreamUnavailable, got: %v", err)
	}
}

func TestCheck_QueryParameters(t *testing.T) {
	testIP := "198.51.100.42"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query parameters are correctly set
		query := r.URL.Query()
		if ip := query.Get("ipAddress"); ip != testIP {
			t.Errorf("expected ipAddress=%s, got %s", testIP, ip)
		}
		if maxAge := query.Get("maxAgeInDays"); maxAge != "90" {
			t.Errorf("expected maxAgeInDays=90, got %s", maxAge)
		}

		resp := map[string]any{
			"data": map[string]any{
				"ipAddress":            testIP,
				"abuseConfidenceScore": 0,
				"countryCode":          "",
				"totalReports":         0,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := New("test-key", srv.URL, nil)
	_, err := client.Check(context.Background(), testIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
			client: New("test-key", "http://test", nil),
			want:   true,
		},
		{
			name:   "unconfigured without API key",
			client: New("", "http://test", nil),
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
