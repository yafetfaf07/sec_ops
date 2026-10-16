package router

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/infrastructure/http/handlers"
	"sec_ops/internal/infrastructure/http/middleware"
)

// Deps groups every handler and cross-cutting dependency the router wires.
// All fields except Logger/AllowedOrigins/Health/Auth/Authn are required for
// a fully wired server.
type Deps struct {
	Logger         *slog.Logger
	AllowedOrigins []string

	Health    *handlers.HealthHandler
	AuthUC    middleware.Authenticator // used to build RequireAuth
	Scheduler middleware.SchedulerVerifier

	AuthH      *handlers.AuthHandler
	UserH      *handlers.UserHandler
	LogH       *handlers.LogHandler
	IncidentH  *handlers.IncidentHandler
	AuditH     *handlers.AuditHandler
	DashboardH *handlers.DashboardHandler
	ScanH      *handlers.ScanHandler
	ScanRunsH  *handlers.ScanRunsHandler
	NLQueryH   *handlers.NLQueryHandler
	SettingsH  *handlers.SettingsHandler
}

func SetupRouter(d Deps) *gin.Engine {
	r := gin.New()
	// Cloud Run sits behind Google's front end; do not trust client-supplied
	// X-Forwarded-For for ClientIP().
	_ = r.SetTrustedProxies(nil)
	r.HandleMethodNotAllowed = true

	r.Use(
		middleware.RequestID(),
		middleware.Recovery(d.Logger),
		middleware.AccessLog(d.Logger),
		middleware.CORS(d.AllowedOrigins),
	)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
	})
	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
	})

	r.GET("/healthz", d.Health.Liveness())
	r.GET("/readyz", d.Health.Readiness())

	auth := middleware.RequireAuth(d.AuthUC)
	admin := middleware.RequireAdmin()
	triage := middleware.RequireTriage()
	schedulerOrAdmin := middleware.RequireAdminOrScheduler(d.AuthUC, d.Scheduler)

	api := r.Group("/api/v1")
	{
		// -------------------------------------------------------- auth
		authGrp := api.Group("/auth")
		authGrp.POST("/login", d.AuthH.Login())
		authGrp.POST("/refresh", d.AuthH.Refresh())
		authGrp.POST("/logout", d.AuthH.Logout())
		authGrp.GET("/me", auth, d.AuthH.Me())

		// -------------------------------------------------------- users (admin)
		users := api.Group("/users", auth, admin)
		users.GET("", d.UserH.List())
		users.POST("", d.UserH.Create())
		users.PATCH("/:id/role", d.UserH.UpdateRole())

		// -------------------------------------------------------- logs
		logs := api.Group("/logs")
		logs.GET("", auth, d.LogH.List())
		logs.GET("/countries", auth, d.LogH.Countries())
		// Ingest accepts either an admin JWT or X-Ingest-Key; RequireIngestAuth
		// decides which path a given request takes before either runs.
		logs.POST("/ingest", d.LogH.RequireIngestAuth(ginChain(auth, admin)), d.LogH.Ingest())
		logs.POST("/mock", auth, admin, d.LogH.GenerateMock())

		// -------------------------------------------------------- incidents
		inc := api.Group("/incidents", auth)
		inc.GET("", d.IncidentH.List())
		inc.GET("/:id", d.IncidentH.Get())
		inc.POST("/:id/acknowledge", triage, d.IncidentH.Acknowledge())
		inc.POST("/:id/resolve", triage, d.IncidentH.Resolve())

		// -------------------------------------------------------- dashboard
		api.GET("/dashboard/summary", auth, d.DashboardH.Summary())

		// -------------------------------------------------------- scan
		api.POST("/scan/daily", schedulerOrAdmin, d.ScanH.Daily())
		api.POST("/scan/run", auth, admin, d.ScanH.Manual())
		api.GET("/scan/runs", auth, d.ScanRunsH.List())

		// -------------------------------------------------------- NL query
		api.POST("/query", auth, triage, d.NLQueryH.Run())

		// -------------------------------------------------------- audit (admin, analyst)
		audit := api.Group("/audit", auth, triage)
		audit.GET("", d.AuditH.List())
		audit.GET("/verify", middleware.RequireAdmin(), d.AuditH.Verify())

		// -------------------------------------------------------- settings (admin)
		settings := api.Group("/settings", auth, admin)
		settings.GET("", d.SettingsH.Get())
		settings.PUT("", d.SettingsH.Update())
	}

	return r
}

// ginChain combines middlewares into the single gin.HandlerFunc that
// RequireIngestAuth expects to run when the ingest key check fails.
func ginChain(mw ...gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, m := range mw {
			m(c)
			if c.IsAborted() {
				return
			}
		}
	}
}
