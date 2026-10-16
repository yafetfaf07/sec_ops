package config

import (
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const validDB = "postgres://u:p@localhost:5432/secops?sslmode=disable"

func TestFromEnvDefaults(t *testing.T) {
	cfg, err := FromEnv(envMap(map[string]string{"DATABASE_URL": validDB}))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.AppEnv != EnvDevelopment || cfg.Port != "8080" || cfg.LogLevel != "info" {
		t.Errorf("unexpected defaults: env=%q port=%q level=%q", cfg.AppEnv, cfg.Port, cfg.LogLevel)
	}
	if cfg.DBMaxOpenConns != 5 || cfg.DBMaxIdleConns != 2 || cfg.DBConnMaxLifetime != 30*time.Minute {
		t.Errorf("unexpected pool defaults: %+v", cfg)
	}
	if len(cfg.CORSAllowedOrigins) != 2 {
		t.Errorf("expected localhost dev origins, got %v", cfg.CORSAllowedOrigins)
	}
}

func TestFromEnvRejectsInvalid(t *testing.T) {
	strongSecret := strings.Repeat("x", 32)
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"missing database url", map[string]string{}, "DATABASE_URL is required"},
		{"non-postgres url", map[string]string{"DATABASE_URL": "mysql://x"}, "postgres://"},
		{"bad port", map[string]string{"DATABASE_URL": validDB, "PORT": "99999"}, "PORT"},
		{"bad env", map[string]string{"DATABASE_URL": validDB, "APP_ENV": "staging"}, "APP_ENV"},
		{"bad log level", map[string]string{"DATABASE_URL": validDB, "LOG_LEVEL": "trace"}, "LOG_LEVEL"},
		{"bad pool size", map[string]string{"DATABASE_URL": validDB, "DB_MAX_OPEN_CONNS": "0"}, "DB_MAX_OPEN_CONNS"},
		{"bad duration", map[string]string{"DATABASE_URL": validDB, "SHUTDOWN_TIMEOUT": "soon"}, "SHUTDOWN_TIMEOUT"},
		{"wildcard cors", map[string]string{"DATABASE_URL": validDB, "CORS_ALLOWED_ORIGINS": "*"}, "must not contain '*'"},
		{"cors with path", map[string]string{"DATABASE_URL": validDB, "CORS_ALLOWED_ORIGINS": "https://a.com/app"}, "must be an origin"},
		{"production weak secret", map[string]string{
			"DATABASE_URL": validDB, "APP_ENV": "production", "CORS_ALLOWED_ORIGINS": "https://a.com", "JWT_SECRET": "short",
		}, "JWT_SECRET"},
		{"production missing cors", map[string]string{
			"DATABASE_URL": validDB, "APP_ENV": "production", "JWT_SECRET": strongSecret,
		}, "CORS_ALLOWED_ORIGINS is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromEnv(envMap(tc.env))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestFromEnvNeverEchoesDatabaseURL(t *testing.T) {
	// The URL carries the database password; it must not appear in errors
	// that end up in Cloud Logging.
	secretURL := "mysql://admin:SuperSecret123@db"
	_, err := FromEnv(envMap(map[string]string{"DATABASE_URL": secretURL}))
	if err == nil || strings.Contains(err.Error(), "SuperSecret123") {
		t.Fatalf("error leaked or missing: %v", err)
	}
}

func TestFromEnvValidProduction(t *testing.T) {
	cfg, err := FromEnv(envMap(map[string]string{
		"DATABASE_URL":         validDB,
		"APP_ENV":              "production",
		"JWT_SECRET":           strings.Repeat("s", 40),
		"CORS_ALLOWED_ORIGINS": "https://app.example.com/, https://admin.example.com",
	}))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !cfg.IsProduction() {
		t.Error("expected production")
	}
	want := []string{"https://app.example.com", "https://admin.example.com"}
	for i, o := range want {
		if cfg.CORSAllowedOrigins[i] != o {
			t.Errorf("origin %d = %q, want %q", i, cfg.CORSAllowedOrigins[i], o)
		}
	}
}
