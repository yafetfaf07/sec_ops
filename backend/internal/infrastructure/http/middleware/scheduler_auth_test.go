package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

type fakeSchedulerVerifier struct {
	configured bool
	err        error
}

func (f *fakeSchedulerVerifier) Configured() bool { return f.configured }

func (f *fakeSchedulerVerifier) Verify(ctx context.Context, token string) error {
	return f.err
}

func setupSchedulerTest(auth Authenticator, oidc SchedulerVerifier) (*gin.Engine, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireAdminOrScheduler(auth, oidc))
	r.POST("/scan/daily", func(c *gin.Context) {
		p := GetPrincipal(c)
		uid := c.GetString(UserIDKey)
		c.JSON(http.StatusOK, gin.H{"principal_user_id": p.UserID, "context_user_id": uid})
	})
	return r, httptest.NewRecorder()
}

func TestRequireAdminOrScheduler_ValidOIDCSucceeds(t *testing.T) {
	auth := &fakeAuthenticator{err: interfaces.ErrUnauthorized} // JWT would fail
	oidc := &fakeSchedulerVerifier{configured: true, err: nil}  // OIDC succeeds

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer oidc-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Check that system principal is set
	body := w.Body.String()
	if body == "" {
		t.Fatal("empty response")
	}
	// The handler should see entities.SystemPrincipal
	t.Logf("response: %s", body)
}

func TestRequireAdminOrScheduler_OIDCNotConfigured_AdminJWTSucceeds(t *testing.T) {
	adminPrincipal := &entities.Principal{
		UserID: "admin-123",
		Role:   enums.RoleAdmin,
	}
	auth := &fakeAuthenticator{principal: adminPrincipal}
	oidc := &fakeSchedulerVerifier{configured: false} // OIDC not configured, skip it

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer admin-jwt")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestRequireAdminOrScheduler_OIDCNotConfigured_NonAdminJWTRejected(t *testing.T) {
	analystPrincipal := &entities.Principal{
		UserID: "analyst-123",
		Role:   enums.RoleAnalyst,
	}
	auth := &fakeAuthenticator{principal: analystPrincipal}
	oidc := &fakeSchedulerVerifier{configured: false}

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer analyst-jwt")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrScheduler_BothOIDCAndJWTInvalid(t *testing.T) {
	auth := &fakeAuthenticator{err: interfaces.ErrUnauthorized}
	oidc := &fakeSchedulerVerifier{configured: true, err: interfaces.ErrUnauthorized}

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrScheduler_MissingAuthorizationHeader(t *testing.T) {
	auth := &fakeAuthenticator{}
	oidc := &fakeSchedulerVerifier{configured: true}

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrScheduler_MalformedBearerToken(t *testing.T) {
	auth := &fakeAuthenticator{}
	oidc := &fakeSchedulerVerifier{configured: true}

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Basic sometoken")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrScheduler_OIDCConfiguredButVerifyFailsANDJWTFails(t *testing.T) {
	// This tests the fallthrough: OIDC configured but fails, then JWT also fails
	// Must not panic when both fail
	auth := &fakeAuthenticator{err: interfaces.ErrUnauthorized}
	oidc := &fakeSchedulerVerifier{configured: true, err: interfaces.ErrUnauthorized}

	r, w := setupSchedulerTest(auth, oidc)
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer invalid-everything")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrScheduler_SystemPrincipalSetOnOIDCSuccess(t *testing.T) {
	auth := &fakeAuthenticator{err: interfaces.ErrUnauthorized}
	oidc := &fakeSchedulerVerifier{configured: true, err: nil}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireAdminOrScheduler(auth, oidc))
	r.POST("/scan/daily", func(c *gin.Context) {
		p := GetPrincipal(c)
		if p == nil {
			t.Error("principal is nil")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no principal"})
			return
		}
		if p.UserID != entities.SystemPrincipal.UserID {
			t.Errorf("principal.UserID = %q, want %q", p.UserID, entities.SystemPrincipal.UserID)
		}
		uid := c.GetString(UserIDKey)
		if uid != entities.SystemPrincipal.UserID {
			t.Errorf("UserIDKey = %q, want %q", uid, entities.SystemPrincipal.UserID)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/daily", nil)
	req.Header.Set("Authorization", "Bearer oidc-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"valid", "Bearer abc123", "abc123"},
		{"empty", "", ""},
		{"no space", "Bearerabc", ""},
		{"wrong prefix", "Basic abc123", ""},
		{"only bearer", "Bearer", ""},
		{"bearer with space", "Bearer ", ""},
		{"lowercase", "bearer token", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractBearer(tc.header)
			if got != tc.want {
				t.Errorf("extractBearer(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
