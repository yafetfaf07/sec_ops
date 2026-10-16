package router

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/infrastructure/http/handlers"
	"sec_ops/internal/infrastructure/http/middleware"
	"sec_ops/internal/infrastructure/logging"
)

type fakePinger struct{ err error }

func (f fakePinger) PingContext(context.Context) error { return f.err }

func newTestRouter(t *testing.T, pingErr error) (*gin.Engine, *bytes.Buffer) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	r := SetupRouter(Deps{
		Logger:         logging.NewWithWriter(&logs, "debug"),
		AllowedOrigins: []string{"https://app.example.com"},
		Health:         handlers.NewHealthHandler(fakePinger{err: pingErr}),
	})
	return r, &logs
}

func do(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHealthEndpoints(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		pingErr error
		want    int
	}{
		{"liveness ok", "/healthz", nil, http.StatusOK},
		{"liveness ignores db", "/healthz", errors.New("down"), http.StatusOK},
		{"readiness ok", "/readyz", nil, http.StatusOK},
		{"readiness db down", "/readyz", errors.New("dial tcp 10.0.0.5: refused"), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestRouter(t, tc.pingErr)
			w := do(r, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
			if strings.Contains(w.Body.String(), "10.0.0.5") {
				t.Fatal("readiness leaked internal error detail")
			}
		})
	}
}

func TestNotFoundIsJSON(t *testing.T) {
	r, _ := newTestRouter(t, nil)
	w := do(r, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

func TestCORS(t *testing.T) {
	r, _ := newTestRouter(t, nil)

	t.Run("allowed preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := do(r, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d", w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
			w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Fatalf("missing CORS headers: %v", w.Header())
		}
	})

	t.Run("disallowed preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := do(r, req)
		if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("disallowed origin got %d %v", w.Code, w.Header())
		}
	})

	t.Run("disallowed simple request gets no CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		w := do(r, req)
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("must not reflect a disallowed origin")
		}
	})
}

func TestRequestID(t *testing.T) {
	r, _ := newTestRouter(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(middleware.RequestIDHeader, "abc-123")
	if got := do(r, req).Header().Get(middleware.RequestIDHeader); got != "abc-123" {
		t.Errorf("valid id not propagated, got %q", got)
	}

	// Header injection / oversized ids are replaced, not echoed.
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(middleware.RequestIDHeader, "bad id\twith<script>")
	got := do(r, req).Header().Get(middleware.RequestIDHeader)
	if got == "" || strings.ContainsAny(got, " \t<>") {
		t.Errorf("unsafe id not replaced, got %q", got)
	}
}

func TestRecoveryReturnsGeneric500(t *testing.T) {
	r, logs := newTestRouter(t, nil)
	r.GET("/boom", func(*gin.Context) { panic("secret internal detail") })

	w := do(r, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret internal detail") {
		t.Fatal("panic value leaked to client")
	}
	if !strings.Contains(logs.String(), "panic recovered") {
		t.Fatal("panic was not logged")
	}
}

func TestAccessLogUsesCloudLoggingFields(t *testing.T) {
	r, logs := newTestRouter(t, nil)
	do(r, httptest.NewRequest(http.MethodGet, "/healthz?token=supersecret", nil))
	out := logs.String()
	if !strings.Contains(out, `"severity":"INFO"`) || !strings.Contains(out, `"message":"http request"`) {
		t.Fatalf("log line not in Cloud Logging format: %s", out)
	}
	if strings.Contains(out, "supersecret") {
		t.Fatal("query string leaked into access log")
	}
}
