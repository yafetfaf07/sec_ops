package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/http/middleware"
)

// Fakes for RBAC testing

type rbacTestAuth struct {
	principal *entities.Principal
	err       error
}

func (f *rbacTestAuth) Authenticate(ctx context.Context, token string) (*entities.Principal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.principal, nil
}

type rbacTestOIDC struct {
	configured bool
	err        error
}

func (f *rbacTestOIDC) Configured() bool { return f.configured }

func (f *rbacTestOIDC) Verify(ctx context.Context, token string) error {
	return f.err
}

// Helper to build a minimal router just for RBAC testing
func newMinimalRBACRouter(auth middleware.Authenticator, oidc middleware.SchedulerVerifier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)

	authMW := middleware.RequireAuth(auth)
	adminMW := middleware.RequireAdmin()
	triageMW := middleware.RequireTriage()
	schedulerOrAdmin := middleware.RequireAdminOrScheduler(auth, oidc)

	// Health endpoints (no auth)
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	r.GET("/readyz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	api := r.Group("/api/v1")
	{
		// Auth endpoints (no auth required for login, auth required for me)
		auth := api.Group("/auth")
		auth.POST("/login", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		auth.GET("/me", authMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Users (admin only)
		users := api.Group("/users", authMW, adminMW)
		users.GET("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		users.POST("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		users.PATCH("/:id/role", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Settings (admin only)
		settings := api.Group("/settings", authMW, adminMW)
		settings.GET("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		settings.PUT("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Logs (auth required for reading, admin for ingesting)
		logs := api.Group("/logs")
		logs.GET("", authMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		logs.POST("/ingest", authMW, adminMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		logs.POST("/mock", authMW, adminMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Incidents (auth for read, triage for actions)
		inc := api.Group("/incidents", authMW)
		inc.GET("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		inc.GET("/:id", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		inc.POST("/:id/acknowledge", triageMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		inc.POST("/:id/resolve", triageMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Dashboard (auth required, all roles)
		api.GET("/dashboard/summary", authMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Scan (scheduler or admin for daily, admin for manual)
		api.POST("/scan/daily", schedulerOrAdmin, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		api.POST("/scan/run", authMW, adminMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		api.GET("/scan/runs", authMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// NL Query (triage only)
		api.POST("/query", authMW, triageMW, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Audit (triage for list, admin for verify)
		audit := api.Group("/audit", authMW, triageMW)
		audit.GET("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
		audit.GET("/verify", middleware.RequireAdmin(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	}

	return r
}

func doReq(r http.Handler, method, path, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestRouterRBAC_HealthEndpointsRequireNoAuth(t *testing.T) {
	auth := &rbacTestAuth{err: interfaces.ErrUnauthorized}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	tests := []string{"/healthz", "/readyz"}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			w := doReq(r, http.MethodGet, path, "")
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for unauthenticated health check", w.Code)
			}
		})
	}
}

func TestRouterRBAC_ScanDailyWithoutTokenReturns401(t *testing.T) {
	auth := &rbacTestAuth{err: interfaces.ErrUnauthorized}
	oidc := &rbacTestOIDC{configured: false, err: interfaces.ErrUnauthorized}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/scan/daily", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for scan/daily without token", w.Code)
	}
}

func TestRouterRBAC_ScanDailyWithValidOIDCSucceeds(t *testing.T) {
	auth := &rbacTestAuth{err: interfaces.ErrUnauthorized}
	oidc := &rbacTestOIDC{configured: true, err: nil}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/scan/daily", "Bearer oidc-token")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for scan/daily with valid OIDC token", w.Code)
	}
}

func TestRouterRBAC_ScanDailyWithAdminJWTSucceeds(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "admin", Role: enums.RoleAdmin},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/scan/daily", "Bearer admin-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for scan/daily with admin JWT", w.Code)
	}
}

func TestRouterRBAC_UsersListViewerBlocked(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "viewer", Role: enums.RoleViewer},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/users", "Bearer viewer-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for viewer accessing /users", w.Code)
	}
}

func TestRouterRBAC_UsersListAdminAllowed(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "admin", Role: enums.RoleAdmin},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/users", "Bearer admin-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for admin accessing /users", w.Code)
	}
}

func TestRouterRBAC_SettingsViewerBlocked(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "viewer", Role: enums.RoleViewer},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/settings", "Bearer viewer-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for viewer accessing /settings", w.Code)
	}
}

func TestRouterRBAC_IncidentAcknowledgeAnalystAllowed(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "analyst", Role: enums.RoleAnalyst},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/incidents/123/acknowledge", "Bearer analyst-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for analyst acknowledging incident", w.Code)
	}
}

func TestRouterRBAC_IncidentAcknowledgeViewerBlocked(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "viewer", Role: enums.RoleViewer},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/incidents/123/acknowledge", "Bearer viewer-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for viewer acknowledging incident", w.Code)
	}
}

func TestRouterRBAC_AuditListAnalystAllowed(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "analyst", Role: enums.RoleAnalyst},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/audit", "Bearer analyst-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for analyst accessing /audit", w.Code)
	}
}

func TestRouterRBAC_AuditVerifyAnalystBlocked(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "analyst", Role: enums.RoleAnalyst},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/audit/verify", "Bearer analyst-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for analyst accessing /audit/verify (admin only)", w.Code)
	}
}

func TestRouterRBAC_AuditVerifyAdminAllowed(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "admin", Role: enums.RoleAdmin},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodGet, "/api/v1/audit/verify", "Bearer admin-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for admin accessing /audit/verify", w.Code)
	}
}

func TestRouterRBAC_NLQueryAnalystAllowed(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "analyst", Role: enums.RoleAnalyst},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/query", "Bearer analyst-jwt")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for analyst running NL query", w.Code)
	}
}

func TestRouterRBAC_NLQueryViewerBlocked(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "viewer", Role: enums.RoleViewer},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/query", "Bearer viewer-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for viewer running NL query", w.Code)
	}
}

func TestRouterRBAC_LogsIngestAdminOnly(t *testing.T) {
	auth := &rbacTestAuth{
		principal: &entities.Principal{UserID: "analyst", Role: enums.RoleAnalyst},
	}
	oidc := &rbacTestOIDC{configured: false}
	r := newMinimalRBACRouter(auth, oidc)

	w := doReq(r, http.MethodPost, "/api/v1/logs/ingest", "Bearer analyst-jwt")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for analyst ingesting logs", w.Code)
	}
}

func TestRouterRBAC_DashboardAllRolesAllowed(t *testing.T) {
	roles := []struct {
		name string
		role enums.Role
	}{
		{"admin", enums.RoleAdmin},
		{"analyst", enums.RoleAnalyst},
		{"viewer", enums.RoleViewer},
	}

	for _, tt := range roles {
		t.Run(tt.name, func(t *testing.T) {
			auth := &rbacTestAuth{
				principal: &entities.Principal{UserID: tt.name, Role: tt.role},
			}
			oidc := &rbacTestOIDC{configured: false}
			r := newMinimalRBACRouter(auth, oidc)

			w := doReq(r, http.MethodGet, "/api/v1/dashboard/summary", "Bearer token")
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for %s accessing dashboard", w.Code, tt.name)
			}
		})
	}
}
