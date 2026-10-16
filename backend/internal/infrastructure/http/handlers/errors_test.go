package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/logging"
)

func TestFail_SentinelErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string // substring to check
	}{
		{
			name:       "ErrValidation",
			err:        interfaces.ErrValidation,
			wantStatus: http.StatusBadRequest,
			wantBody:   "validation",
		},
		{
			name:       "ErrValidation wrapped with detail",
			err:        fmt.Errorf("%w: email is required", interfaces.ErrValidation),
			wantStatus: http.StatusBadRequest,
			wantBody:   "email is required",
		},
		{
			name:       "ErrUnauthorized",
			err:        interfaces.ErrUnauthorized,
			wantStatus: http.StatusUnauthorized,
			wantBody:   "unauthorized",
		},
		{
			name:       "ErrForbidden",
			err:        interfaces.ErrForbidden,
			wantStatus: http.StatusForbidden,
			wantBody:   "permission",
		},
		{
			name:       "ErrNotFound",
			err:        interfaces.ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantBody:   "not found",
		},
		{
			name:       "ErrInvalidTransition",
			err:        interfaces.ErrInvalidTransition,
			wantStatus: http.StatusConflict,
			wantBody:   "invalid",
		},
		{
			name:       "ErrInvalidTransition wrapped",
			err:        fmt.Errorf("%w: cannot go from Open to Resolved", interfaces.ErrInvalidTransition),
			wantStatus: http.StatusConflict,
			wantBody:   "Open to Resolved",
		},
		{
			name:       "ErrConflict",
			err:        interfaces.ErrConflict,
			wantStatus: http.StatusConflict,
			wantBody:   "conflict",
		},
		{
			name:       "ErrConflict wrapped",
			err:        fmt.Errorf("%w: email already exists", interfaces.ErrConflict),
			wantStatus: http.StatusConflict,
			wantBody:   "already exists",
		},
		{
			name:       "ErrImmutable",
			err:        interfaces.ErrImmutable,
			wantStatus: http.StatusConflict,
			wantBody:   "cannot be modified",
		},
		{
			name:       "ErrQuotaExceeded",
			err:        interfaces.ErrQuotaExceeded,
			wantStatus: http.StatusTooManyRequests,
			wantBody:   "quota",
		},
		{
			name:       "ErrQuotaExceeded wrapped",
			err:        fmt.Errorf("%w: daily limit reached", interfaces.ErrQuotaExceeded),
			wantStatus: http.StatusTooManyRequests,
			wantBody:   "daily limit",
		},
		{
			name:       "ErrUpstreamUnavailable",
			err:        interfaces.ErrUpstreamUnavailable,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			log := logging.NewWithWriter(w, "error")
			Fail(c, log, tc.err)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}

			body := w.Body.String()
			if !strings.Contains(strings.ToLower(body), strings.ToLower(tc.wantBody)) {
				t.Errorf("body %q does not contain %q", body, tc.wantBody)
			}

			// All error responses must be JSON with "error" key
			if !strings.Contains(body, `"error"`) {
				t.Errorf("body is not JSON with error key: %s", body)
			}
		})
	}
}

func TestFail_UnmappedErrorReturns500WithGenericMessage(t *testing.T) {
	// Security check: unhandled errors must not leak internals
	secretError := errors.New("database password is wrong: pg://user:supersecret@host/db")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Set up request context properly
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request = req
	r.GET("/test", func(c *gin.Context) {})

	// Use separate buffer for logs
	var logBuf bytes.Buffer
	log := logging.NewWithWriter(&logBuf, "error")
	Fail(c, log, secretError)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Fatal("empty response body")
	}

	// Security property: body must NOT contain the secret error text
	if strings.Contains(body, "supersecret") {
		t.Fatalf("body leaked secret error details: %s", body)
	}
	if strings.Contains(body, "database password") {
		t.Fatalf("body leaked internal error details: %s", body)
	}

	// Must be a generic message
	if !strings.Contains(strings.ToLower(body), "internal server error") {
		t.Errorf("body should contain generic error message, got: %s", body)
	}
}

func TestFail_UnmappedErrorIsLogged(t *testing.T) {
	// Even though we don't send the error to the client, we must log it
	internalErr := errors.New("repository query failed: connection timeout")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Set up request context so the logger has a request to log
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request = req
	r.GET("/test", func(c *gin.Context) {})

	var logBuf strings.Builder
	log := logging.NewWithWriter(&logBuf, "error")
	Fail(c, log, internalErr)

	// Check that the error was logged (not sent to client)
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "unhandled error") || !strings.Contains(logOutput, "connection timeout") {
		t.Errorf("error was not logged properly, log output: %s", logOutput)
	}
}

func TestFail_NestedSentinelsAreRecognized(t *testing.T) {
	// Deeply wrapped errors should still be recognized
	deeplyWrapped := fmt.Errorf("use case failed: %w", fmt.Errorf("repository error: %w", interfaces.ErrNotFound))

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	log := logging.NewWithWriter(w, "error")
	Fail(c, log, deeplyWrapped)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestPublicMessage_ExtractsWrappedDetail(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		sentinel error
		want     string
	}{
		{
			name:     "wrapped with detail",
			err:      fmt.Errorf("%w: user_id is required", interfaces.ErrValidation),
			sentinel: interfaces.ErrValidation,
			want:     "user_id is required",
		},
		{
			name:     "bare sentinel",
			err:      interfaces.ErrValidation,
			sentinel: interfaces.ErrValidation,
			want:     "validation failed",
		},
		{
			name:     "double wrapped",
			err:      fmt.Errorf("outer: %w", fmt.Errorf("%w: inner detail", interfaces.ErrConflict)),
			sentinel: interfaces.ErrConflict,
			want:     "inner detail",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := publicMessage(tc.err, tc.sentinel)
			if !strings.Contains(got, tc.want) {
				t.Errorf("publicMessage() = %q, want substring %q", got, tc.want)
			}
		})
	}
}
