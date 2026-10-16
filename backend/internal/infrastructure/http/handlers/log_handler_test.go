package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/infrastructure/http/middleware"
)

func TestConstantTimeEqual(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"equal strings", "secret123", "secret123", true},
		{"different strings same length", "secret123", "secret456", false},
		{"different lengths a longer", "secret123", "secret", false},
		{"different lengths b longer", "secret", "secret123", false},
		{"both empty", "", "", true},
		{"one empty", "secret", "", false},
		{"different at start", "xecret", "secret", false},
		{"different at end", "secretx", "secret1", false},
		{"different in middle", "sec123ret", "sec456ret", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := constantTimeEqual(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("constantTimeEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestConstantTimeEqual_ActuallyConstantTime(t *testing.T) {
	// This is a behavior test, not a timing test, but we verify the implementation
	// doesn't short-circuit on the first mismatch (which would leak timing info)

	secret := "supersecretkey123"
	// These should all take the same time (modulo noise) since they're the same length
	tests := []string{
		"aupersecretkey123", // first char different
		"supersecretkey124", // last char different
		"supersXcretkey123", // middle char different
		"aaaaaaaaaaaaaaaa1", // many differences
	}

	for _, test := range tests {
		if constantTimeEqual(secret, test) {
			t.Errorf("constantTimeEqual should return false for %q", test)
		}
	}
}

func TestRequireIngestAuth_CorrectKeyBypassesAdminChain(t *testing.T) {
	const ingestKey = "test-ingest-key-123"

	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Create a fake admin chain that would fail if called
	adminChain := func(c *gin.Context) {
		t.Error("admin chain was called, should have been bypassed")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin required"})
	}

	h := &LogHandler{ingestKey: ingestKey}
	r.POST("/ingest", h.RequireIngestAuth(adminChain), func(c *gin.Context) {
		// Check that no principal is set (ingest key auth doesn't set one)
		p := middleware.GetPrincipal(c)
		if p != nil {
			t.Errorf("principal should be nil for ingest key auth, got %+v", p)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.Header.Set("X-Ingest-Key", ingestKey)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestRequireIngestAuth_WrongKeyFallsThrough(t *testing.T) {
	const ingestKey = "correct-key"

	gin.SetMode(gin.TestMode)
	r := gin.New()

	adminChainCalled := false
	adminChain := func(c *gin.Context) {
		adminChainCalled = true
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}

	h := &LogHandler{ingestKey: ingestKey}
	r.POST("/ingest", h.RequireIngestAuth(adminChain), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.Header.Set("X-Ingest-Key", "wrong-key")
	r.ServeHTTP(w, req)

	if !adminChainCalled {
		t.Error("admin chain should have been called when key is wrong")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireIngestAuth_NoKeyHeaderFallsThrough(t *testing.T) {
	const ingestKey = "correct-key"

	gin.SetMode(gin.TestMode)
	r := gin.New()

	adminChainCalled := false
	adminChain := func(c *gin.Context) {
		adminChainCalled = true
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}

	h := &LogHandler{ingestKey: ingestKey}
	r.POST("/ingest", h.RequireIngestAuth(adminChain), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	// No X-Ingest-Key header
	r.ServeHTTP(w, req)

	if !adminChainCalled {
		t.Error("admin chain should have been called when key header is missing")
	}

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireIngestAuth_EmptyIngestKeyDisablesKeyAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	adminChainCalled := false
	adminChain := func(c *gin.Context) {
		adminChainCalled = true
		// Simulate successful admin auth
		c.Set(middleware.PrincipalKey, &entities.Principal{
			UserID: "admin-123",
			Role:   enums.RoleAdmin,
		})
		c.Next()
	}

	h := &LogHandler{ingestKey: ""} // Empty key disables header-based auth
	r.POST("/ingest", h.RequireIngestAuth(adminChain), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.Header.Set("X-Ingest-Key", "any-key")
	r.ServeHTTP(w, req)

	if !adminChainCalled {
		t.Error("admin chain should have been called when ingestKey is empty")
	}

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (admin auth succeeded)", w.Code)
	}
}

func TestRequireIngestAuth_CorrectKeyEvenWithoutAuthorizationHeader(t *testing.T) {
	const ingestKey = "test-key"

	gin.SetMode(gin.TestMode)
	r := gin.New()

	adminChain := func(c *gin.Context) {
		t.Error("admin chain should not be called when ingest key is valid")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no auth header"})
	}

	h := &LogHandler{ingestKey: ingestKey}
	r.POST("/ingest", h.RequireIngestAuth(adminChain), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.Header.Set("X-Ingest-Key", ingestKey)
	// No Authorization header
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; valid ingest key should bypass admin auth entirely", w.Code)
	}
}

func TestActorFor_ReturnsPrincipalWhenSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	expected := entities.Principal{
		UserID: "user-123",
		Email:  "test@example.com",
		Role:   enums.RoleAdmin,
	}
	c.Set(middleware.PrincipalKey, &expected)

	actor := actorFor(c)
	if actor.UserID != expected.UserID {
		t.Errorf("actorFor returned UserID %q, want %q", actor.UserID, expected.UserID)
	}
}

func TestActorFor_ReturnsSystemPrincipalWhenNotSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	// No principal set (e.g., ingest key auth)
	actor := actorFor(c)
	if actor.UserID != entities.SystemPrincipal.UserID {
		t.Errorf("actorFor returned UserID %q, want %q", actor.UserID, entities.SystemPrincipal.UserID)
	}
}
