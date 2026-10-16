// Package dtos defines the JSON shapes of the HTTP API. Field names and enum
// strings mirror the frontend's app/lib/types.ts exactly.
package dtos

import (
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
)

// ----------------------------------------------------------------- auth/users

type LoginRequest struct {
	Email    string `json:"email" binding:"required,max=320"`
	Password string `json:"password" binding:"required,max=72"`
}

type UserResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	Role      enums.Role `json:"role"`
	Disabled  bool       `json:"disabled"`
	CreatedAt time.Time  `json:"created_at"`
}

// LoginResponse is the body for /auth/login and /auth/refresh. The refresh
// token is never in the body; it is set as an httpOnly cookie by the handler.
type LoginResponse struct {
	AccessToken string       `json:"access_token"`
	TokenType   string       `json:"token_type"`
	ExpiresAt   time.Time    `json:"expires_at"`
	User        UserResponse `json:"user"`
}

// TokenPair is returned by the auth use case to the handler only.
type TokenPair struct {
	Response         LoginResponse
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type CreateUserRequest struct {
	Name     string `json:"name" binding:"required,max=200"`
	Email    string `json:"email" binding:"required,max=320"`
	Password string `json:"password" binding:"required,min=12,max=72"`
	Role     string `json:"role" binding:"required"`
}

type UpdateUserRequest struct {
	Role     *string `json:"role"`
	Disabled *bool   `json:"disabled"`
}

func ToUserResponse(u *entities.User) UserResponse {
	return UserResponse{ID: u.ID, Name: u.Name, Email: u.Email, Role: u.Role, Disabled: u.Disabled, CreatedAt: u.CreatedAt}
}

// ----------------------------------------------------------------- logs

type LogEntry struct {
	LogID     string          `json:"log_id"`
	Timestamp time.Time       `json:"timestamp"`
	UserID    string          `json:"user_id"`
	IPAddress string          `json:"ip_address"`
	Country   string          `json:"country"`
	City      string          `json:"city"`
	Action    enums.LogAction `json:"action"`
	UserAgent string          `json:"user_agent"`
	Flagged   bool            `json:"flagged"`
}

func ToLogEntry(l entities.RawLog) LogEntry {
	return LogEntry{
		LogID: l.LogID, Timestamp: l.Timestamp, UserID: l.UserID, IPAddress: l.IPAddress, Country: l.Country,
		City: l.City, Action: l.Action, UserAgent: l.UserAgent, Flagged: l.Flagged,
	}
}

// LogPage matches the frontend's mock LogPage.
type LogPage struct {
	Rows     []LogEntry `json:"rows"`
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"pageSize"`
}

// LogListQuery matches the frontend's LogQuery query params.
type LogListQuery struct {
	Action   string `form:"action"`
	Country  string `form:"country"`
	Search   string `form:"search"`
	Page     int    `form:"page"`
	PageSize int    `form:"pageSize"`
}

// IngestLog is one inbound log. "flagged" is intentionally absent: the server
// derives it from the action.
type IngestLog struct {
	LogID     string `json:"log_id"`
	Timestamp string `json:"timestamp"`
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	Country   string `json:"country"`
	City      string `json:"city"`
	Action    string `json:"action"`
	UserAgent string `json:"user_agent"`
}

type IngestRequest struct {
	Logs []IngestLog `json:"logs" binding:"required"`
}

type MockLogsRequest struct {
	Scenario string `json:"scenario"`
	Count    int    `json:"count"`
	// AttackerIPs optionally overrides generated attacker addresses (public
	// IPs make AbuseIPDB enrichment demonstrable). Max 10.
	AttackerIPs []string `json:"attacker_ips"`
}

type IngestError struct {
	Index  int    `json:"index"`
	LogID  string `json:"log_id,omitempty"`
	Reason string `json:"reason"`
}

type IngestResult struct {
	Received   int           `json:"received"`
	Inserted   int           `json:"inserted"`
	Duplicates int           `json:"duplicates"`
	Flagged    int           `json:"flagged"`
	Rejected   []IngestError `json:"rejected"`
}

// ----------------------------------------------------------------- incidents

type IncidentComment struct {
	Author    string    `json:"author"`
	Role      string    `json:"role"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type Incident struct {
	ID                  string               `json:"id"`
	RiskScore           enums.RiskLevel      `json:"risk_score"`
	AIRiskScore         enums.RiskLevel      `json:"ai_risk_score"`
	Status              enums.IncidentStatus `json:"status"`
	AISummary           string               `json:"ai_summary"`
	RecommendedAction   string               `json:"recommended_action"`
	AbuseIPDBConfidence int                  `json:"abuseipdb_confidence"`
	TopIP               string               `json:"top_ip"`
	SuspiciousIPs       []string             `json:"suspicious_ips"`
	Patterns            []string             `json:"patterns"`
	AffectedUsers       []string             `json:"affected_users"`
	Country             string               `json:"country"`
	DetectedAt          time.Time            `json:"detected_at"`
	AcknowledgedAt      *time.Time           `json:"acknowledged_at,omitempty"`
	ResolvedAt          *time.Time           `json:"resolved_at,omitempty"`
	BatchRef            string               `json:"batch_ref"`
	Comments            []IncidentComment    `json:"comments"`
}

func ToIncident(i entities.Incident) Incident {
	comments := make([]IncidentComment, 0, len(i.Comments))
	for _, c := range i.Comments {
		comments = append(comments, IncidentComment{Author: c.Author, Role: c.Role, Body: c.Body, CreatedAt: c.CreatedAt})
	}
	return Incident{
		ID: i.ID, RiskScore: i.RiskScore, AIRiskScore: i.AIRiskScore, Status: i.Status, AISummary: i.AISummary,
		RecommendedAction: i.RecommendedAction, AbuseIPDBConfidence: i.AbuseIPDBConfidence, TopIP: i.TopIP,
		SuspiciousIPs: nonNil(i.SuspiciousIPs), Patterns: nonNil(i.Patterns), AffectedUsers: nonNil(i.AffectedUsers),
		Country: i.Country, DetectedAt: i.DetectedAt, AcknowledgedAt: i.AcknowledgedAt, ResolvedAt: i.ResolvedAt,
		BatchRef: i.BatchID, Comments: comments,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// IncidentListQuery matches the frontend's IncidentQuery.
type IncidentListQuery struct {
	Status string `form:"status"`
	Risk   string `form:"risk"`
	Sort   string `form:"sort"`
	Dir    string `form:"dir"`
}

type ResolveRequest struct {
	Comment string `json:"comment"`
}

// ----------------------------------------------------------------- audit

type AuditEntry struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	UserID     string            `json:"user_id"`
	ActionType string            `json:"action_type"`
	Details    string            `json:"details"`
	EntityType string            `json:"entity_type,omitempty"`
	EntityID   string            `json:"entity_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type AuditListQuery struct {
	ActionType string `form:"action_type"`
	UserID     string `form:"user_id"`
	From       string `form:"from"`
	To         string `form:"to"`
	Limit      int    `form:"limit"`
}

type AuditVerifyResult struct {
	Valid      bool   `json:"valid"`
	Checked    int    `json:"checked"`
	FirstBadID int64  `json:"first_bad_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	LatestHash string `json:"latest_hash,omitempty"`
}

// ----------------------------------------------------------------- dashboard/scan

type DashboardSummary struct {
	LogsAnalyzedToday int                     `json:"logs_analyzed_today"`
	ActiveThreats     map[enums.RiskLevel]int `json:"active_threats"`
	LastScanTime      *time.Time              `json:"last_scan_time"`
	CriticalIncidents int                     `json:"critical_incidents"`
	FlaggedLogs       int                     `json:"flagged_logs"`
	LogsIngestedToday int                     `json:"logs_ingested_today"`
	PendingAnalysis   int                     `json:"pending_analysis"`
}

type ScanResult struct {
	ScanID      string    `json:"scan_id"`
	LogsFetched int       `json:"logs_fetched"`
	Analyzed    int       `json:"analyzed"`
	NewAlerts   int       `json:"new_alerts"`
	Incidents   int       `json:"incidents"`
	Deferred    int       `json:"deferred"`
	Suppressed  int       `json:"suppressed"`
	ExecutedAt  time.Time `json:"executed_at"`
	Status      string    `json:"status"`
}

type ScanRun struct {
	ID          string     `json:"id"`
	Trigger     string     `json:"trigger"`
	Actor       string     `json:"actor"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	LogsFetched int        `json:"logs_fetched"`
	Analyzed    int        `json:"analyzed"`
	NewAlerts   int        `json:"new_alerts"`
	Error       string     `json:"error,omitempty"`
}

func ToScanRun(r entities.ScanRun) ScanRun {
	return ScanRun{
		ID: r.ID, Trigger: string(r.Trigger), Actor: r.Actor, Status: string(r.Status), StartedAt: r.StartedAt,
		FinishedAt: r.FinishedAt, LogsFetched: r.LogsFetched, Analyzed: r.Analyzed, NewAlerts: r.NewAlerts, Error: r.Error,
	}
}

// ----------------------------------------------------------------- NL query

type NLQueryRequest struct {
	Query string `json:"query"`
}

type NLQueryResult struct {
	Query              string            `json:"query"`
	Interpretation     string            `json:"interpretation"`
	FiltersApplied     map[string]string `json:"filters_applied"`
	MatchedIncidentIDs []string          `json:"matched_incident_ids"`
	MatchedLogIDs      []string          `json:"matched_log_ids"`
	Logs               []LogEntry        `json:"logs"`
	Incidents          []Incident        `json:"incidents"`
}

// ----------------------------------------------------------------- settings

// SchedulerSettings matches the frontend type. The *_webhook_set fields are
// read-only: webhooks are secrets configured via Secret Manager.
type SchedulerSettings struct {
	Enabled           bool   `json:"enabled"`
	CronHourUTC       int    `json:"cron_hour_utc"`
	Timezone          string `json:"timezone"`
	SlackWebhookSet   bool   `json:"slack_webhook_set"`
	DiscordWebhookSet bool   `json:"discord_webhook_set"`
	GeminiModel       string `json:"gemini_model"`
	AbuseIPDBEnabled  bool   `json:"abuseipdb_enabled"`
	// Extra, backward-compatible fields.
	SuppressionDays     int        `json:"suppression_days"`
	GeminiConfigured    bool       `json:"gemini_configured"`
	AbuseIPDBConfigured bool       `json:"abuseipdb_configured"`
	SchedulerManaged    bool       `json:"scheduler_managed"`
	UpdatedBy           string     `json:"updated_by,omitempty"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
}

// SettingsPatch accepts the frontend's Partial<SchedulerSettings>. Read-only
// fields are accepted and ignored so the frontend can send its whole form.
type SettingsPatch struct {
	Enabled          *bool   `json:"enabled"`
	CronHourUTC      *int    `json:"cron_hour_utc"`
	Timezone         *string `json:"timezone"`
	GeminiModel      *string `json:"gemini_model"`
	AbuseIPDBEnabled *bool   `json:"abuseipdb_enabled"`
	SuppressionDays  *int    `json:"suppression_days"`
}

type UpdateSettingsRequest struct {
	Patch SettingsPatch `json:"patch"`
}
