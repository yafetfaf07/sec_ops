// Package entities holds plain domain structs. No JSON, GORM or HTTP tags:
// DTOs (application/dtos) and DB models (infrastructure/database/dbmodels)
// are mapped explicitly at layer boundaries.
package entities

import (
	"time"

	"sec_ops/internal/domain/enums"
)

type User struct {
	ID           string
	Name         string
	Email        string
	PasswordHash string
	Role         enums.Role
	TokenVersion int
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Principal is the authenticated caller, resolved by the auth middleware and
// passed to use cases. It is never built from request input.
type Principal struct {
	UserID string
	Email  string
	Name   string
	Role   enums.Role
}

// SystemPrincipal is used for automated work (Cloud Scheduler, ingest key).
var SystemPrincipal = Principal{UserID: enums.SystemActor, Email: enums.SystemActor, Name: enums.SystemActor}

func (p Principal) IsSystem() bool { return p.UserID == enums.SystemActor }

// Actor is the label recorded in audit/comments: email for users, SYSTEM otherwise.
func (p Principal) Actor() string {
	if p.IsSystem() || p.Email == "" {
		return enums.SystemActor
	}
	return p.Email
}

type RawLog struct {
	ID         string
	LogID      string
	Timestamp  time.Time
	UserID     string
	IPAddress  string
	Country    string
	City       string
	Action     enums.LogAction
	UserAgent  string
	Flagged    bool
	IngestedAt time.Time
}

type BatchStatus string

const (
	BatchPending  BatchStatus = "pending"
	BatchRunning  BatchStatus = "running"
	BatchDone     BatchStatus = "done"
	BatchFailed   BatchStatus = "failed"
	BatchDeferred BatchStatus = "deferred"
)

type AnalysisBatch struct {
	ID                string
	ScanRunID         string
	WindowStart       time.Time
	WindowEnd         time.Time
	Status            BatchStatus
	Attempts          int
	Model             string
	RiskScore         enums.RiskLevel
	Summary           string
	RecommendedAction string
	SuspiciousIPs     []string
	Patterns          []string
	AffectedUsers     []string
	TopIP             string
	RawResponse       []byte
	Error             string
	CreatedAt         time.Time
	AnalyzedAt        *time.Time
}

type Incident struct {
	ID                  string
	BatchID             string
	Fingerprint         string
	AIRiskScore         enums.RiskLevel
	RiskScore           enums.RiskLevel
	Status              enums.IncidentStatus
	AISummary           string
	RecommendedAction   string
	SuspiciousIPs       []string
	Patterns            []string
	AffectedUsers       []string
	TopIP               string
	Country             string
	AbuseIPDBConfidence int
	DetectedAt          time.Time
	AcknowledgedAt      *time.Time
	AcknowledgedBy      string
	ResolvedAt          *time.Time
	ResolvedBy          string
	UpdatedAt           time.Time
	Comments            []IncidentComment
}

type IncidentComment struct {
	ID         string
	IncidentID string
	Author     string
	Role       string // enums.Role value or "SYSTEM"
	Body       string
	CreatedAt  time.Time
}

type AuditEntry struct {
	ID         int64
	Timestamp  time.Time
	UserID     string
	ActionType enums.AuditAction
	EntityType string
	EntityID   string
	Details    string
	Metadata   map[string]string
	PrevHash   string
	Hash       string
}

type ThreatIntel struct {
	IP              string
	AbuseConfidence int
	TotalReports    int
	Country         string
	FetchedAt       time.Time
	ExpiresAt       time.Time
	Cached          bool
}

type AlertDelivery struct {
	ID          string
	IncidentID  string
	Channel     string
	Success     bool
	HTTPStatus  int
	Error       string
	AttemptedAt time.Time
}

type ScanTrigger string

const (
	TriggerScheduler ScanTrigger = "scheduler"
	TriggerManual    ScanTrigger = "manual"
)

type ScanStatus string

const (
	ScanRunning   ScanStatus = "running"
	ScanSucceeded ScanStatus = "succeeded"
	ScanFailed    ScanStatus = "failed"
)

type ScanRun struct {
	ID          string
	Trigger     ScanTrigger
	Actor       string
	Status      ScanStatus
	StartedAt   time.Time
	FinishedAt  *time.Time
	LogsFetched int
	Analyzed    int
	NewAlerts   int
	Error       string
}

// Settings are the non-secret, admin-editable runtime settings.
type Settings struct {
	SchedulerEnabled bool
	CronHourUTC      int
	Timezone         string
	GeminiModel      string
	AbuseIPDBEnabled bool
	SuppressionDays  int
	UpdatedBy        string
	UpdatedAt        time.Time
}
