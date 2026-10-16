package interfaces

import (
	"context"
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
)

// TxManager runs fn in a database transaction. Repositories called with the
// ctx passed to fn join that transaction. Nested calls reuse the outer one.
type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// LogQuery filters raw logs. Every field is optional; zero means "no filter".
type LogQuery struct {
	Actions     []enums.LogAction
	Countries   []string
	Cities      []string
	UserIDs     []string
	IPs         []string
	Since       *time.Time
	Until       *time.Time
	Search      string // substring of user_id, ip_address or log_id
	FlaggedOnly bool
	Limit       int
	Offset      int
}

type IncidentQuery struct {
	Statuses  []enums.IncidentStatus
	Risks     []enums.RiskLevel
	Countries []string
	IPs       []string
	Since     *time.Time
	// SortBy is "detected_at" or "risk_score".
	SortBy string
	Desc   bool
	Limit  int
}

type AuditQuery struct {
	ActionType string
	UserID     string
	Since      *time.Time
	Until      *time.Time
	Limit      int
}

type UserRepository interface {
	Create(ctx context.Context, u *entities.User) error
	FindByID(ctx context.Context, id string) (*entities.User, error)
	FindByEmail(ctx context.Context, email string) (*entities.User, error)
	List(ctx context.Context) ([]entities.User, error)
	// UpdateRole and SetDisabled also bump token_version, revoking sessions.
	UpdateRole(ctx context.Context, id string, role enums.Role) error
	SetDisabled(ctx context.Context, id string, disabled bool) error
	BumpTokenVersion(ctx context.Context, id string) error
	CountActiveAdmins(ctx context.Context) (int, error)
}

type LogRepository interface {
	// InsertMany stores logs, skipping duplicates by log_id. Returns inserted count.
	InsertMany(ctx context.Context, logs []entities.RawLog) (int, error)
	List(ctx context.Context, q LogQuery) ([]entities.RawLog, int, error)
	Countries(ctx context.Context) ([]string, error)
	// UnanalyzedFlagged returns flagged logs since t not yet linked to a batch.
	UnanalyzedFlagged(ctx context.Context, since time.Time, limit int) ([]entities.RawLog, error)
	CountUnanalyzedFlagged(ctx context.Context, since time.Time) (int, error)
	// SuccessfulLoginsForUsers is context for impossible-travel analysis.
	SuccessfulLoginsForUsers(ctx context.Context, userIDs []string, from, to time.Time, limit int) ([]entities.RawLog, error)
	ByBatch(ctx context.Context, batchID string) ([]entities.RawLog, error)
	CountIngestedSince(ctx context.Context, t time.Time) (int, error)
	CountFlaggedSince(ctx context.Context, t time.Time) (int, error)
	// CountAnalyzedSince counts logs in batches whose analysis finished since t.
	CountAnalyzedSince(ctx context.Context, t time.Time) (int, error)
}

type BatchRepository interface {
	// Create stores the batch and links logIDs to it (immutably).
	Create(ctx context.Context, b *entities.AnalysisBatch, logIDs []string) error
	Update(ctx context.Context, b *entities.AnalysisBatch) error
	// Retryable returns deferred/failed batches with attempts < maxAttempts.
	Retryable(ctx context.Context, maxAttempts, limit int) ([]entities.AnalysisBatch, error)
}

type IncidentRepository interface {
	// Create returns ErrConflict if an unresolved incident has the same fingerprint.
	Create(ctx context.Context, inc *entities.Incident) error
	Get(ctx context.Context, id string) (*entities.Incident, error)
	// GetForUpdate locks the row; must be called inside WithinTx.
	GetForUpdate(ctx context.Context, id string) (*entities.Incident, error)
	List(ctx context.Context, q IncidentQuery) ([]entities.Incident, error)
	FindOpenByFingerprint(ctx context.Context, fp string) (*entities.Incident, error)
	LastResolvedByFingerprint(ctx context.Context, fp string) (*entities.Incident, error)
	UpdateStatus(ctx context.Context, inc *entities.Incident) error
	UpdateEnrichment(ctx context.Context, id string, risk enums.RiskLevel, confidence int) error
	AddComment(ctx context.Context, c *entities.IncidentComment) error
	CountActiveByRisk(ctx context.Context) (map[enums.RiskLevel]int, error)
}

type AuditRepository interface {
	// Append computes the hash chain link and inserts the entry atomically.
	Append(ctx context.Context, e *entities.AuditEntry) error
	List(ctx context.Context, q AuditQuery) ([]entities.AuditEntry, error)
	// Ascending pages through the chain in insertion order for verification.
	Ascending(ctx context.Context, afterID int64, limit int) ([]entities.AuditEntry, error)
}

type ThreatIntelCache interface {
	Get(ctx context.Context, ip string, now time.Time) (*entities.ThreatIntel, error) // ErrNotFound when absent/expired
	Put(ctx context.Context, ti *entities.ThreatIntel) error
}

type AlertDeliveryRepository interface {
	Insert(ctx context.Context, d *entities.AlertDelivery) error
}

type ScanRunRepository interface {
	// Start returns ErrConflict when another scan is running.
	Start(ctx context.Context, r *entities.ScanRun) error
	Finish(ctx context.Context, r *entities.ScanRun) error
	FailStale(ctx context.Context, startedBefore time.Time) (int, error)
	LastFinished(ctx context.Context) (*entities.ScanRun, error) // ErrNotFound if none
	List(ctx context.Context, limit int) ([]entities.ScanRun, error)
}

// UsageRepository tracks the daily free-tier budget per provider.
type UsageRepository interface {
	// Consume atomically increments today's counter if it is below limit.
	Consume(ctx context.Context, provider string, day time.Time, limit int) (bool, error)
}

type SettingsRepository interface {
	Get(ctx context.Context) (*entities.Settings, error) // ErrNotFound if never saved
	Save(ctx context.Context, s *entities.Settings) error
}

// ---------------------------------------------------------------------------
// External service ports
// ---------------------------------------------------------------------------

// JSONGenerationRequest asks an LLM for a JSON document matching Schema.
type JSONGenerationRequest struct {
	Model             string
	SystemInstruction string
	Prompt            string
	// Schema is a Gemini responseSchema (OpenAPI subset, upper-case types).
	Schema      map[string]any
	MaxAttempts int // retries on 429/5xx inside the adapter; 0 = adapter default
}

// LLM is implemented by the Gemini adapter. It returns ErrQuotaExceeded on
// rate limiting and ErrUpstreamUnavailable on other upstream failures.
type LLM interface {
	GenerateJSON(ctx context.Context, req JSONGenerationRequest) ([]byte, error)
	Configured() bool
}

type ThreatIntelClient interface {
	Check(ctx context.Context, ip string) (*entities.ThreatIntel, error)
	Configured() bool
}

type AlertMessage struct {
	IncidentID        string
	Timestamp         time.Time
	RiskScore         enums.RiskLevel
	Summary           string
	AbuseIPDBScore    *int // nil when not checked
	RecommendedAction string
	TopIP             string
	Country           string
	Link              string
}

type AlertNotifier interface {
	Channel() string // "slack" | "discord"
	// Send returns the HTTP status (0 if no response) and an error on failure.
	Send(ctx context.Context, m AlertMessage) (int, error)
}

// SchedulerControl manages the Cloud Scheduler job that calls /scan/daily.
type SchedulerControl interface {
	Configured() bool
	Apply(ctx context.Context, enabled bool, cronHour int, timezone string) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

type TokenClaims struct {
	UserID       string
	Role         enums.Role
	TokenVersion int
	ExpiresAt    time.Time
}

type TokenService interface {
	IssueAccess(u *entities.User) (string, time.Time, error)
	IssueRefresh(u *entities.User) (string, time.Time, error)
	ParseAccess(token string) (*TokenClaims, error)
	ParseRefresh(token string) (*TokenClaims, error)
}

type Clock interface {
	Now() time.Time
}

// MockLogGenerator produces synthetic logs for a named scenario (FR-SEC-001).
type MockLogGenerator interface {
	Generate(scenario string, count int, attackerIPs []string) []entities.RawLog
}
