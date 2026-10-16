// Package config loads and validates process configuration from the
// environment. Validation is fail-fast: a misconfigured service must refuse to
// start instead of running with, say, an empty JWT secret (a weakness of
// personal_prod_golang, which validated nothing).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
	EnvTest        = "test"

	minJWTSecretLen = 32
)

type Config struct {
	AppEnv   string
	Port     string
	LogLevel string

	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration

	// CORSAllowedOrigins is an exact-match allowlist. Wildcards are not
	// supported because the frontend sends credentials (refresh cookie).
	CORSAllowedOrigins []string

	// JWTSecret signs access/refresh tokens. Required (>= 32 chars) in
	// production; in development an ephemeral random secret is generated when
	// it is empty (sessions then do not survive a restart).
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// CookieSecure / CookieSameSiteNone control the refresh cookie. In
	// production the frontend and API are different sites (*.run.app is a
	// public suffix), so SameSite=None; Secure is required.
	CookieSecure       bool
	CookieSameSiteNone bool

	BootstrapAdminEmail    string
	BootstrapAdminPassword string
	BootstrapAdminName     string

	// IngestAPIKey optionally lets an automated log shipper call
	// POST /logs/ingest with X-Ingest-Key instead of an admin JWT.
	IngestAPIKey string

	GeminiAPIKey           string
	GeminiModel            string
	GeminiBaseURL          string
	GeminiRPM              int
	GeminiDailyBudget      int
	GeminiMaxBatches       int
	GeminiMaxLogsPerBatch  int
	AbuseIPDBAPIKey        string
	AbuseIPDBBaseURL       string
	AbuseIPDBDailyBudget   int
	AbuseEscalateThreshold int

	SlackWebhookURL   string
	DiscordWebhookURL string
	DashboardURL      string

	// SchedulerAudience / SchedulerSAEmail enable Google OIDC auth on
	// POST /scan/daily for Cloud Scheduler. Both or neither.
	SchedulerAudience string
	SchedulerSAEmail  string
	// SchedulerJobName (projects/P/locations/L/jobs/J) lets admins pause,
	// resume and reschedule the job from Settings. Optional.
	SchedulerJobName string

	ScanTimeout     time.Duration
	ShutdownTimeout time.Duration
}

func (c *Config) IsProduction() bool { return c.AppEnv == EnvProduction }

// Load reads a local .env file (development only) and then the process
// environment. On Cloud Run, configuration comes from env vars and Secret
// Manager mounts, never from a file.
func Load() (*Config, error) {
	if env := os.Getenv("APP_ENV"); env == "" || env == EnvDevelopment {
		// Absence of .env is fine; real env vars always win over the file.
		_ = godotenv.Load()
	}
	return FromEnv(os.Getenv)
}

// FromEnv builds a Config from an arbitrary lookup so it can be tested without
// touching the real process environment.
func FromEnv(getenv func(string) string) (*Config, error) {
	var errs []error

	cfg := &Config{
		AppEnv:   strings.ToLower(withDefault(getenv("APP_ENV"), EnvDevelopment)),
		Port:     withDefault(getenv("PORT"), "8080"),
		LogLevel: strings.ToLower(withDefault(getenv("LOG_LEVEL"), "info")),

		DatabaseURL: strings.TrimSpace(getenv("DATABASE_URL")),
		JWTSecret:   getenv("JWT_SECRET"),
	}

	switch cfg.AppEnv {
	case EnvDevelopment, EnvProduction, EnvTest:
	default:
		errs = append(errs, fmt.Errorf("APP_ENV must be one of development|production|test, got %q", cfg.AppEnv))
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("LOG_LEVEL must be one of debug|info|warn|error, got %q", cfg.LogLevel))
	}

	if p, err := strconv.Atoi(cfg.Port); err != nil || p < 1 || p > 65535 {
		errs = append(errs, fmt.Errorf("PORT must be a number between 1 and 65535, got %q", cfg.Port))
	}

	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	} else if u, err := url.Parse(cfg.DatabaseURL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		// Never echo the URL: it contains the database password.
		errs = append(errs, errors.New("DATABASE_URL must be a postgres:// or postgresql:// URL"))
	}

	var err error
	if cfg.DBMaxOpenConns, err = intFromEnv(getenv, "DB_MAX_OPEN_CONNS", 5, 1, 100); err != nil {
		errs = append(errs, err)
	}
	if cfg.DBMaxIdleConns, err = intFromEnv(getenv, "DB_MAX_IDLE_CONNS", 2, 0, 100); err != nil {
		errs = append(errs, err)
	}
	if cfg.DBConnMaxLifetime, err = durationFromEnv(getenv, "DB_CONN_MAX_LIFETIME", 30*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.ShutdownTimeout, err = durationFromEnv(getenv, "SHUTDOWN_TIMEOUT", 8*time.Second); err != nil {
		errs = append(errs, err)
	}
	if cfg.ScanTimeout, err = durationFromEnv(getenv, "SCAN_TIMEOUT", 14*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.AccessTokenTTL, err = durationFromEnv(getenv, "ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		errs = append(errs, err)
	}
	if cfg.RefreshTokenTTL, err = durationFromEnv(getenv, "REFRESH_TOKEN_TTL", 7*24*time.Hour); err != nil {
		errs = append(errs, err)
	}

	cfg.CookieSecure = cfg.IsProduction()
	if v := strings.TrimSpace(getenv("COOKIE_SECURE")); v != "" {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			errs = append(errs, fmt.Errorf("COOKIE_SECURE must be true or false, got %q", v))
		}
		cfg.CookieSecure = b
	}
	cfg.CookieSameSiteNone = cfg.CookieSecure
	if cfg.IsProduction() && !cfg.CookieSecure {
		errs = append(errs, errors.New("COOKIE_SECURE cannot be false in production"))
	}

	cfg.BootstrapAdminEmail = strings.ToLower(strings.TrimSpace(getenv("BOOTSTRAP_ADMIN_EMAIL")))
	cfg.BootstrapAdminPassword = getenv("BOOTSTRAP_ADMIN_PASSWORD")
	cfg.BootstrapAdminName = withDefault(getenv("BOOTSTRAP_ADMIN_NAME"), "Administrator")
	if (cfg.BootstrapAdminEmail == "") != (cfg.BootstrapAdminPassword == "") {
		errs = append(errs, errors.New("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together"))
	}
	if cfg.BootstrapAdminPassword != "" && (len(cfg.BootstrapAdminPassword) < 12 || len(cfg.BootstrapAdminPassword) > 72) {
		errs = append(errs, errors.New("BOOTSTRAP_ADMIN_PASSWORD must be 12-72 characters"))
	}

	cfg.IngestAPIKey = getenv("INGEST_API_KEY")
	if cfg.IngestAPIKey != "" && len(cfg.IngestAPIKey) < 32 {
		errs = append(errs, errors.New("INGEST_API_KEY must be at least 32 characters when set"))
	}

	cfg.GeminiAPIKey = strings.TrimSpace(getenv("GEMINI_API_KEY"))
	cfg.GeminiModel = withDefault(getenv("GEMINI_MODEL"), "gemini-2.5-flash-lite")
	if !ValidGeminiModel(cfg.GeminiModel) {
		errs = append(errs, fmt.Errorf("GEMINI_MODEL %q is not a valid model id", cfg.GeminiModel))
	}
	cfg.GeminiBaseURL = withDefault(getenv("GEMINI_BASE_URL"), "https://generativelanguage.googleapis.com")
	cfg.AbuseIPDBAPIKey = strings.TrimSpace(getenv("ABUSEIPDB_API_KEY"))
	cfg.AbuseIPDBBaseURL = withDefault(getenv("ABUSEIPDB_BASE_URL"), "https://api.abuseipdb.com")
	for key, v := range map[string]string{"GEMINI_BASE_URL": cfg.GeminiBaseURL, "ABUSEIPDB_BASE_URL": cfg.AbuseIPDBBaseURL} {
		if u, perr := url.Parse(v); perr != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && !cfg.IsProduction())) {
			errs = append(errs, fmt.Errorf("%s must be an https URL", key))
		}
	}

	ints := []struct {
		dst           *int
		key           string
		def, min, max int
	}{
		{&cfg.GeminiRPM, "GEMINI_RPM", 8, 1, 1000},
		{&cfg.GeminiDailyBudget, "GEMINI_DAILY_BUDGET", 200, 1, 100000},
		{&cfg.GeminiMaxBatches, "GEMINI_MAX_BATCHES_PER_SCAN", 3, 1, 50},
		{&cfg.GeminiMaxLogsPerBatch, "GEMINI_MAX_LOGS_PER_BATCH", 500, 10, 5000},
		// AbuseIPDB free tier: 1,000 checks/day. Keep a margin.
		{&cfg.AbuseIPDBDailyBudget, "ABUSEIPDB_DAILY_BUDGET", 900, 1, 1000},
		{&cfg.AbuseEscalateThreshold, "ABUSE_ESCALATE_THRESHOLD", 50, 0, 100},
	}
	for _, it := range ints {
		if *it.dst, err = intFromEnv(getenv, it.key, it.def, it.min, it.max); err != nil {
			errs = append(errs, err)
		}
	}

	cfg.SlackWebhookURL = strings.TrimSpace(getenv("SLACK_WEBHOOK_URL"))
	if cfg.SlackWebhookURL != "" && !webhookHostAllowed(cfg.SlackWebhookURL, "hooks.slack.com") {
		errs = append(errs, errors.New("SLACK_WEBHOOK_URL must be an https://hooks.slack.com/ URL"))
	}
	cfg.DiscordWebhookURL = strings.TrimSpace(getenv("DISCORD_WEBHOOK_URL"))
	if cfg.DiscordWebhookURL != "" && !webhookHostAllowed(cfg.DiscordWebhookURL, "discord.com", "discordapp.com") {
		errs = append(errs, errors.New("DISCORD_WEBHOOK_URL must be an https://discord.com/api/webhooks/ URL"))
	}
	cfg.DashboardURL = strings.TrimRight(strings.TrimSpace(getenv("DASHBOARD_URL")), "/")

	cfg.SchedulerAudience = strings.TrimSpace(getenv("SCHEDULER_AUDIENCE"))
	cfg.SchedulerSAEmail = strings.ToLower(strings.TrimSpace(getenv("SCHEDULER_SA_EMAIL")))
	if (cfg.SchedulerAudience == "") != (cfg.SchedulerSAEmail == "") {
		errs = append(errs, errors.New("SCHEDULER_AUDIENCE and SCHEDULER_SA_EMAIL must be set together"))
	}
	cfg.SchedulerJobName = strings.TrimSpace(getenv("SCHEDULER_JOB_NAME"))
	if cfg.SchedulerJobName != "" && !schedulerJobName.MatchString(cfg.SchedulerJobName) {
		errs = append(errs, errors.New("SCHEDULER_JOB_NAME must look like projects/P/locations/L/jobs/J"))
	}

	cfg.CORSAllowedOrigins = splitList(getenv("CORS_ALLOWED_ORIGINS"))
	if len(cfg.CORSAllowedOrigins) == 0 && cfg.AppEnv != EnvProduction {
		// React Router dev server and `react-router-serve` defaults.
		cfg.CORSAllowedOrigins = []string{"http://localhost:5173", "http://localhost:3000"}
	}
	for _, o := range cfg.CORSAllowedOrigins {
		if o == "*" {
			errs = append(errs, errors.New("CORS_ALLOWED_ORIGINS must not contain '*' (credentials are used)"))
			continue
		}
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			errs = append(errs, fmt.Errorf("CORS_ALLOWED_ORIGINS entry %q must be an origin like https://app.example.com", o))
		}
	}

	if cfg.IsProduction() {
		if len(cfg.CORSAllowedOrigins) == 0 {
			errs = append(errs, errors.New("CORS_ALLOWED_ORIGINS is required in production"))
		}
		if len(cfg.JWTSecret) < minJWTSecretLen {
			errs = append(errs, fmt.Errorf("JWT_SECRET must be at least %d characters in production", minJWTSecretLen))
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	// Normalise trailing slashes so comparisons against the Origin header match.
	for i, o := range cfg.CORSAllowedOrigins {
		cfg.CORSAllowedOrigins[i] = strings.TrimRight(o, "/")
	}
	return cfg, nil
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intFromEnv(getenv func(string) string, key string, def, min, max int) (int, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d, got %q", key, min, max, raw)
	}
	return n, nil
}

func durationFromEnv(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration like 30s or 5m, got %q", key, raw)
	}
	return d, nil
}
