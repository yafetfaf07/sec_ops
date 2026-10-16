package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestSlackWebhook_Send_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %s", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	score := 75
	msg := interfaces.AlertMessage{
		IncidentID:        "inc_123",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskHigh,
		Summary:           "Multiple failed logins detected",
		AbuseIPDBScore:    &score,
		RecommendedAction: "Review and block IP",
		TopIP:             "192.0.2.42",
		Country:           "US",
		Link:              "https://app.example.com/incidents/inc_123",
	}

	status, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func TestDiscordWebhook_Send_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %s", ct)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	webhook := NewDiscord(srv.URL, nil)
	score := 85
	msg := interfaces.AlertMessage{
		IncidentID:        "inc_456",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskCritical,
		Summary:           "Privilege escalation attempt",
		AbuseIPDBScore:    &score,
		RecommendedAction: "Immediate investigation required",
		TopIP:             "198.51.100.1",
		Country:           "CN",
		Link:              "https://app.example.com/incidents/inc_456",
	}

	status, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", status)
	}
}

func TestWebhook_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid webhook format"))
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	msg := interfaces.AlertMessage{
		IncidentID: "inc_123",
		Timestamp:  time.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Test",
	}

	status, err := webhook.Send(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if status != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", status)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected error to mention status code, got: %v", err)
	}
}

func TestWebhook_ErrorDoesNotLeakURL(t *testing.T) {
	// Test various error scenarios to ensure webhook URL never appears in error messages
	tests := []struct {
		name   string
		setup  func() *httptest.Server
		errMsg string
	}{
		{
			name: "non-2xx response",
			setup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			errMsg: "status 500",
		},
		{
			name: "404 not found",
			setup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			errMsg: "status 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := tt.setup()
			defer srv.Close()

			webhook := NewSlack(srv.URL, nil)
			msg := interfaces.AlertMessage{
				IncidentID: "inc_test",
				Timestamp:  time.Now(),
				RiskScore:  enums.RiskMedium,
				Summary:    "Test incident",
			}

			_, err := webhook.Send(context.Background(), msg)
			if err == nil {
				t.Fatal("expected error")
			}

			errStr := err.Error()
			// Webhook URLs are secrets and must never leak into error messages
			if strings.Contains(errStr, srv.URL) {
				t.Errorf("error message leaked webhook URL: %v", err)
			}
			// Also check for any part of the URL
			if strings.Contains(errStr, "127.0.0.1") || strings.Contains(errStr, "localhost") {
				t.Errorf("error message leaked server address: %v", err)
			}
		})
	}
}

func TestWebhook_UnreachableDoesNotLeakURL(t *testing.T) {
	// Use a URL that will fail to connect
	webhook := NewSlack("http://localhost:1", nil) // port 1 won't be listening
	msg := interfaces.AlertMessage{
		IncidentID: "inc_test",
		Timestamp:  time.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Test",
	}

	_, err := webhook.Send(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}

	if !errors.Is(err, interfaces.ErrUpstreamUnavailable) {
		t.Errorf("expected ErrUpstreamUnavailable, got: %v", err)
	}

	errStr := err.Error()
	// Verify the error doesn't contain the URL or address
	if strings.Contains(errStr, "localhost:1") || strings.Contains(errStr, "127.0.0.1") {
		t.Errorf("error message leaked webhook URL/address: %v", err)
	}
	// Should have generic message
	if !strings.Contains(errStr, "unreachable") {
		t.Errorf("expected error about unreachable webhook, got: %v", err)
	}
}

func TestWebhook_SanitizesMentions(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tests := []struct {
		name          string
		summary       string
		action        string
		topIP         string
		shouldNotFind []string
		webhook       *Webhook
	}{
		{
			name:          "sanitize @everyone in slack",
			summary:       "Alert @everyone about this breach",
			action:        "Contact @here immediately",
			topIP:         "192.0.2.1",
			shouldNotFind: []string{"@everyone", "@here"},
			webhook:       NewSlack(srv.URL, nil),
		},
		{
			name:          "sanitize @everyone in discord",
			summary:       "@everyone see this attack",
			action:        "Notify @here right away",
			topIP:         "198.51.100.1",
			shouldNotFind: []string{"@everyone", "@here"},
			webhook:       NewDiscord(srv.URL, nil),
		},
		{
			name:          "sanitize markdown injection attempts",
			summary:       "Attack from <!channel> users",
			action:        "Block <@U123456> access",
			topIP:         "203.0.113.1",
			shouldNotFind: []string{"<!", "<@"},
			webhook:       NewSlack(srv.URL, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedBody = nil
			msg := interfaces.AlertMessage{
				IncidentID:        "inc_sanitize",
				Timestamp:         time.Now(),
				RiskScore:         enums.RiskHigh,
				Summary:           tt.summary,
				RecommendedAction: tt.action,
				TopIP:             tt.topIP,
			}

			_, err := tt.webhook.Send(context.Background(), msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if receivedBody == nil {
				t.Fatal("no request body captured")
			}

			bodyStr := string(receivedBody)
			for _, forbidden := range tt.shouldNotFind {
				if strings.Contains(bodyStr, forbidden) {
					t.Errorf("sanitization failed: payload contains %q: %s", forbidden, bodyStr)
				}
			}

			// Verify the sanitized versions are present instead
			if strings.Contains(tt.summary, "@everyone") && !strings.Contains(bodyStr, "everyone") {
				t.Error("sanitized 'everyone' not found in payload")
			}
			if strings.Contains(tt.action, "@here") && !strings.Contains(bodyStr, "here") {
				t.Error("sanitized 'here' not found in payload")
			}
		})
	}
}

func TestWebhook_SanitizeCodeBlockAttempts(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	msg := interfaces.AlertMessage{
		IncidentID:        "inc_code",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskMedium,
		Summary:           "Attack with ```code block``` injection",
		RecommendedAction: "Review ```malicious``` content",
	}

	_, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bodyStr := string(receivedBody)
	// Triple backticks should be replaced with triple single quotes
	if strings.Contains(bodyStr, "```") {
		t.Errorf("payload contains unsanitized code block markers: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "'''") {
		t.Error("expected triple single quotes as replacement for code blocks")
	}
}

func TestWebhook_TruncatesLongContent(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)

	// Create a very long summary
	longSummary := strings.Repeat("A", 3000)
	longAction := strings.Repeat("B", 2000)

	msg := interfaces.AlertMessage{
		IncidentID:        "inc_long",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskHigh,
		Summary:           longSummary,
		RecommendedAction: longAction,
	}

	_, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bodyStr := string(receivedBody)

	// Verify truncation happened (should contain ellipsis)
	if !strings.Contains(bodyStr, "…") {
		t.Error("expected truncation ellipsis in payload")
	}

	// Payload shouldn't be excessively large
	if len(bodyStr) > 10000 {
		t.Errorf("payload too large after truncation: %d bytes", len(bodyStr))
	}
}

func TestWebhook_NilAbuseIPDBScore(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	msg := interfaces.AlertMessage{
		IncidentID:        "inc_nil_score",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskMedium,
		Summary:           "Test incident",
		AbuseIPDBScore:    nil, // Not checked
		RecommendedAction: "Investigate",
	}

	_, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bodyStr := string(receivedBody)
	// Should show "not checked" when score is nil
	if !strings.Contains(bodyStr, "not checked") {
		t.Errorf("expected 'not checked' for nil AbuseIPDB score, got: %s", bodyStr)
	}
}

func TestWebhook_AllRiskLevels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	risks := []enums.RiskLevel{
		enums.RiskLow,
		enums.RiskMedium,
		enums.RiskHigh,
		enums.RiskCritical,
	}

	webhook := NewDiscord(srv.URL, nil)

	for _, risk := range risks {
		t.Run(string(risk), func(t *testing.T) {
			msg := interfaces.AlertMessage{
				IncidentID: "inc_" + string(risk),
				Timestamp:  time.Now(),
				RiskScore:  risk,
				Summary:    "Test for " + string(risk),
			}

			_, err := webhook.Send(context.Background(), msg)
			if err != nil {
				t.Errorf("unexpected error for risk %s: %v", risk, err)
			}
		})
	}
}

func TestWebhook_Channel(t *testing.T) {
	slackWebhook := NewSlack("http://test", nil)
	if ch := slackWebhook.Channel(); ch != "slack" {
		t.Errorf("expected channel 'slack', got %q", ch)
	}

	discordWebhook := NewDiscord("http://test", nil)
	if ch := discordWebhook.Channel(); ch != "discord" {
		t.Errorf("expected channel 'discord', got %q", ch)
	}
}

func TestWebhook_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	msg := interfaces.AlertMessage{
		IncidentID: "inc_ctx",
		Timestamp:  time.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Test",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := webhook.Send(ctx, msg)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestWebhook_EmptyFieldsHandled(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	webhook := NewSlack(srv.URL, nil)
	msg := interfaces.AlertMessage{
		IncidentID:        "inc_empty",
		Timestamp:         time.Now(),
		RiskScore:         enums.RiskMedium,
		Summary:           "",
		RecommendedAction: "",
		TopIP:             "",
		Link:              "",
	}

	_, err := webhook.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify valid JSON was sent even with empty fields
	var payload map[string]any
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
}

func TestDiscordWebhook_ColorMapping(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tests := []struct {
		risk          enums.RiskLevel
		expectedColor int
	}{
		{enums.RiskLow, 0x22c55e},
		{enums.RiskMedium, 0xeab308},
		{enums.RiskHigh, 0xef4444},
		{enums.RiskCritical, 0x991b1b},
	}

	webhook := NewDiscord(srv.URL, nil)

	for _, tt := range tests {
		t.Run(string(tt.risk), func(t *testing.T) {
			receivedBody = nil
			msg := interfaces.AlertMessage{
				IncidentID: "inc_color",
				Timestamp:  time.Now(),
				RiskScore:  tt.risk,
				Summary:    "Test color",
			}

			_, err := webhook.Send(context.Background(), msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var payload map[string]any
			if err := json.Unmarshal(receivedBody, &payload); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			// Check embeds array exists and has color
			embeds, ok := payload["embeds"].([]any)
			if !ok || len(embeds) == 0 {
				t.Fatal("expected embeds array in Discord payload")
			}

			embed, ok := embeds[0].(map[string]any)
			if !ok {
				t.Fatal("expected embed to be an object")
			}

			color, ok := embed["color"].(float64)
			if !ok {
				t.Fatal("expected color field in embed")
			}

			if int(color) != tt.expectedColor {
				t.Errorf("expected color 0x%x, got 0x%x", tt.expectedColor, int(color))
			}
		})
	}
}
