// Command api is the SecOps Coordinator HTTP service. It is the composition
// root: all dependencies are constructed and wired here by hand.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/usecases/alerting"
	"sec_ops/internal/application/usecases/analysis"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/auth"
	"sec_ops/internal/application/usecases/dashboard"
	"sec_ops/internal/application/usecases/enrichment"
	"sec_ops/internal/application/usecases/incident"
	"sec_ops/internal/application/usecases/ingest"
	"sec_ops/internal/application/usecases/nlquery"
	"sec_ops/internal/application/usecases/scan"
	"sec_ops/internal/application/usecases/settings"
	"sec_ops/internal/application/usecases/user"
	"sec_ops/internal/config"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/ai/gemini"
	"sec_ops/internal/infrastructure/database"
	"sec_ops/internal/infrastructure/http/handlers"
	"sec_ops/internal/infrastructure/http/router"
	"sec_ops/internal/infrastructure/httpx"
	"sec_ops/internal/infrastructure/logging"
	"sec_ops/internal/infrastructure/mocklogs"
	"sec_ops/internal/infrastructure/notify"
	"sec_ops/internal/infrastructure/repository"
	"sec_ops/internal/infrastructure/scheduler"
	"sec_ops/internal/infrastructure/security"
	"sec_ops/internal/infrastructure/threatintel/abuseipdb"
)

func main() {
	if err := run(); err != nil {
		// Config may have failed, so build a logger with fixed settings.
		logging.NewWithWriter(os.Stderr, "error").Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := logging.New(cfg.LogLevel)
	slog.SetDefault(log)
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// Cloud Run sends SIGTERM and allows ~10s before SIGKILL.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gdb, sqlDB, err := database.Connect(ctx, cfg.DatabaseURL, database.Options{
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxLifetime: cfg.DBConnMaxLifetime,
	})
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	migrateCtx, cancelMigrate := context.WithTimeout(ctx, 60*time.Second)
	err = database.Migrate(migrateCtx, sqlDB, log)
	cancelMigrate()
	if err != nil {
		return err
	}

	clock := systemClock{}

	// ---------------------------------------------------------- security
	jwtSecret := cfg.JWTSecret
	if jwtSecret == "" {
		// Only reachable outside production (config.go enforces a real
		// secret there). An ephemeral secret means sessions do not survive a
		// restart, which is acceptable for local development.
		jwtSecret, err = randomHex(32)
		if err != nil {
			return err
		}
		log.Warn("JWT_SECRET not set; using an ephemeral development secret (sessions will not survive a restart)")
	}
	jwtSvc, err := security.NewJWTService(jwtSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, time.Now)
	if err != nil {
		return err
	}
	hasher := security.NewBcryptHasher(0)
	oidcVerifier := security.NewOIDCVerifier(cfg.SchedulerAudience, cfg.SchedulerSAEmail, security.GoogleCertsURL, httpx.NewClient(10*time.Second), time.Now)

	// ---------------------------------------------------------- repositories
	tx := repository.NewTxManager(gdb)
	userRepo := repository.NewUserRepository(gdb)
	logRepo := repository.NewLogRepository(gdb)
	batchRepo := repository.NewBatchRepository(gdb)
	incidentRepo := repository.NewIncidentRepository(gdb)
	auditRepo := repository.NewAuditRepository(gdb, tx)
	tiCache := repository.NewThreatIntelCache(gdb)
	deliveryRepo := repository.NewAlertDeliveryRepository(gdb)
	scanRunRepo := repository.NewScanRunRepository(gdb)
	usageRepo := repository.NewUsageRepository(gdb)
	settingsRepo := repository.NewSettingsRepository(gdb)

	// ---------------------------------------------------------- external adapters
	geminiClient := gemini.New(gemini.Config{
		APIKey: cfg.GeminiAPIKey, BaseURL: cfg.GeminiBaseURL, DefaultModel: cfg.GeminiModel,
		RPM: cfg.GeminiRPM, HTTPClient: httpx.NewClient(90 * time.Second),
	})
	abuseClient := abuseipdb.New(cfg.AbuseIPDBAPIKey, cfg.AbuseIPDBBaseURL, httpx.NewClient(10*time.Second))
	var notifiers []interfaces.AlertNotifier
	if cfg.SlackWebhookURL != "" {
		notifiers = append(notifiers, notify.NewSlack(cfg.SlackWebhookURL, httpx.NewClient(10*time.Second)))
	}
	if cfg.DiscordWebhookURL != "" {
		notifiers = append(notifiers, notify.NewDiscord(cfg.DiscordWebhookURL, httpx.NewClient(10*time.Second)))
	}
	schedulerCtl := scheduler.New(cfg.SchedulerJobName, "", "", httpx.NewClient(15*time.Second))
	mockGen := mocklogs.New(uint64(time.Now().UnixNano()), time.Now)

	// ---------------------------------------------------------- use cases
	auditSvc := audit.NewService(auditRepo, clock)
	authSvc := auth.NewService(userRepo, hasher, hasher, jwtSvc, auditSvc, tx)
	userSvc := user.NewService(userRepo, hasher, auditSvc, tx)
	ingestSvc := ingest.NewService(logRepo, mockGen, mocklogs.ValidScenario, auditSvc, tx, clock)
	analysisSvc := analysis.NewService(geminiClient, usageRepo, clock, cfg.GeminiModel, cfg.GeminiDailyBudget)
	enrichSvc := enrichment.NewService(abuseClient, tiCache, usageRepo, clock, cfg.AbuseIPDBDailyBudget, cfg.AbuseEscalateThreshold)
	alertSvc := alerting.NewService(notifiers, deliveryRepo, auditSvc)
	incidentSvc := incident.NewService(incidentRepo, auditSvc, tx, clock)
	dashboardSvc := dashboard.NewService(logRepo, incidentRepo, scanRunRepo, clock)
	scanSvc := scan.NewService(logRepo, batchRepo, incidentRepo, scanRunRepo, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, log, scan.Config{
		MaxBatches: cfg.GeminiMaxBatches, MaxLogsPerBatch: cfg.GeminiMaxLogsPerBatch, DashboardURL: cfg.DashboardURL,
	})
	scanRunsSvc := scan.NewRunsService(scanRunRepo, 50)
	nlQuerySvc := nlquery.NewService(geminiClient, logRepo, incidentRepo, auditSvc, clock, cfg.GeminiModel)
	settingsSvc := settings.NewService(settingsRepo, schedulerCtl, auditSvc, tx,
		cfg.SlackWebhookURL != "", cfg.DiscordWebhookURL != "", geminiClient.Configured(), abuseClient.Configured(), config.ValidGeminiModel)

	// Bootstrap the first admin, if configured and none exists yet.
	bootstrapCtx, cancelBootstrap := context.WithTimeout(ctx, 10*time.Second)
	created, err := authSvc.EnsureBootstrapAdmin(bootstrapCtx, cfg.BootstrapAdminName, cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword)
	cancelBootstrap()
	if err != nil {
		return err
	}
	if created {
		log.Info("bootstrap admin created", "email", cfg.BootstrapAdminEmail)
	}

	// ---------------------------------------------------------- HTTP
	engine := router.SetupRouter(router.Deps{
		Logger:         log,
		AllowedOrigins: cfg.CORSAllowedOrigins,
		Health:         handlers.NewHealthHandler(sqlDB),
		AuthUC:         authSvc,
		Scheduler:      oidcVerifier,
		AuthH:          handlers.NewAuthHandler(authSvc, log, cfg.CookieSecure, cfg.CookieSameSiteNone),
		UserH:          handlers.NewUserHandler(userSvc, log),
		LogH:           handlers.NewLogHandler(ingestSvc, log, cfg.IngestAPIKey),
		IncidentH:      handlers.NewIncidentHandler(incidentSvc, log),
		AuditH:         handlers.NewAuditHandler(auditSvc, log),
		DashboardH:     handlers.NewDashboardHandler(dashboardSvc, log),
		ScanH:          handlers.NewScanHandler(scanSvc, log, cfg.ScanTimeout),
		ScanRunsH:      handlers.NewScanRunsHandler(scanRunsSvc, log),
		NLQueryH:       handlers.NewNLQueryHandler(nlQuerySvc, log),
		SettingsH:      handlers.NewSettingsHandler(settingsSvc, log),
	})

	srv := &http.Server{
		Addr:              net.JoinHostPort("", cfg.Port),
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// The scheduled scan runs synchronously inside its request (up to the
		// 900s Cloud Run timeout), so the write timeout must exceed it.
		WriteTimeout:   16 * time.Minute,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("server listening", "port", cfg.Port, "env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	log.Info("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	log.Info("server stopped")
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
