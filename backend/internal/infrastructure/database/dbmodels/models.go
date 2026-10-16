// Package dbmodels holds the row structs used by the GORM repositories.
// Every model declares TableName() and explicit column tags so GORM's naming
// strategy never decides a table or column name (the todo_task_dbs bug in
// personal_prod_golang).
package dbmodels

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// JSONList maps a Go string slice to a jsonb array column.
//
// Value returns a string, not []byte: with the pgx simple protocol (required
// behind poolers) []byte is sent as a bytea literal, which Postgres refuses
// to cast to jsonb.
type JSONList []string

func (l JSONList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(l))
	return string(b), err
}

func (l *JSONList) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case nil:
		*l = JSONList{}
		return nil
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("JSONList: unsupported scan type %T", src)
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	*l = out
	return nil
}

// JSONMap maps map[string]string to a jsonb object column.
type JSONMap map[string]string

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(map[string]string(m))
	return string(b), err
}

func (m *JSONMap) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case nil:
		*m = JSONMap{}
		return nil
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("JSONMap: unsupported scan type %T", src)
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	*m = out
	return nil
}

// JSONRaw stores an arbitrary JSON document (nullable jsonb).
type JSONRaw []byte

func (r JSONRaw) Value() (driver.Value, error) {
	if len(r) == 0 {
		return nil, nil
	}
	if !json.Valid(r) {
		return nil, fmt.Errorf("JSONRaw: invalid JSON")
	}
	return string(r), nil
}

func (r *JSONRaw) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*r = nil
	case []byte:
		*r = append((*r)[:0], v...)
	case string:
		*r = JSONRaw(v)
	default:
		return fmt.Errorf("JSONRaw: unsupported scan type %T", src)
	}
	return nil
}

type User struct {
	ID           string    `gorm:"column:id;primaryKey"`
	Name         string    `gorm:"column:name"`
	Email        string    `gorm:"column:email"`
	PasswordHash string    `gorm:"column:password_hash"`
	Role         string    `gorm:"column:role"`
	TokenVersion int       `gorm:"column:token_version"`
	Disabled     bool      `gorm:"column:disabled"`
	CreatedAt    time.Time `gorm:"column:created_at"`
	UpdatedAt    time.Time `gorm:"column:updated_at"`
}

func (User) TableName() string { return "users" }

type RawLog struct {
	ID         string    `gorm:"column:id;primaryKey"`
	LogID      string    `gorm:"column:log_id"`
	Ts         time.Time `gorm:"column:ts"`
	UserID     string    `gorm:"column:user_id"`
	IPAddress  string    `gorm:"column:ip_address"`
	Country    string    `gorm:"column:country"`
	City       string    `gorm:"column:city"`
	Action     string    `gorm:"column:action"`
	UserAgent  string    `gorm:"column:user_agent"`
	Flagged    bool      `gorm:"column:flagged"`
	IngestedAt time.Time `gorm:"column:ingested_at"`
}

func (RawLog) TableName() string { return "raw_logs" }

type AnalysisBatch struct {
	ID                string     `gorm:"column:id;primaryKey"`
	ScanRunID         *string    `gorm:"column:scan_run_id"`
	WindowStart       time.Time  `gorm:"column:window_start"`
	WindowEnd         time.Time  `gorm:"column:window_end"`
	Status            string     `gorm:"column:status"`
	Attempts          int        `gorm:"column:attempts"`
	Model             string     `gorm:"column:model"`
	RiskScore         *string    `gorm:"column:risk_score"`
	Summary           string     `gorm:"column:summary"`
	RecommendedAction string     `gorm:"column:recommended_action"`
	SuspiciousIPs     JSONList   `gorm:"column:suspicious_ips"`
	Patterns          JSONList   `gorm:"column:patterns"`
	AffectedUsers     JSONList   `gorm:"column:affected_users"`
	TopIP             string     `gorm:"column:top_ip"`
	RawResponse       JSONRaw    `gorm:"column:raw_response"`
	Error             *string    `gorm:"column:error"`
	CreatedAt         time.Time  `gorm:"column:created_at"`
	AnalyzedAt        *time.Time `gorm:"column:analyzed_at"`
}

func (AnalysisBatch) TableName() string { return "analysis_batches" }

type BatchLog struct {
	LogID   string `gorm:"column:log_id;primaryKey"`
	BatchID string `gorm:"column:batch_id"`
}

func (BatchLog) TableName() string { return "batch_logs" }

type Incident struct {
	ID                  string     `gorm:"column:id;primaryKey"`
	BatchID             string     `gorm:"column:batch_id"`
	Fingerprint         string     `gorm:"column:fingerprint"`
	AIRiskScore         string     `gorm:"column:ai_risk_score"`
	RiskScore           string     `gorm:"column:risk_score"`
	Status              string     `gorm:"column:status"`
	AISummary           string     `gorm:"column:ai_summary"`
	RecommendedAction   string     `gorm:"column:recommended_action"`
	SuspiciousIPs       JSONList   `gorm:"column:suspicious_ips"`
	Patterns            JSONList   `gorm:"column:patterns"`
	AffectedUsers       JSONList   `gorm:"column:affected_users"`
	TopIP               string     `gorm:"column:top_ip"`
	Country             string     `gorm:"column:country"`
	AbuseIPDBConfidence int        `gorm:"column:abuseipdb_confidence"`
	DetectedAt          time.Time  `gorm:"column:detected_at"`
	AcknowledgedAt      *time.Time `gorm:"column:acknowledged_at"`
	AcknowledgedBy      *string    `gorm:"column:acknowledged_by"`
	ResolvedAt          *time.Time `gorm:"column:resolved_at"`
	ResolvedBy          *string    `gorm:"column:resolved_by"`
	UpdatedAt           time.Time  `gorm:"column:updated_at"`
}

func (Incident) TableName() string { return "incidents" }

type IncidentComment struct {
	ID         string    `gorm:"column:id;primaryKey"`
	IncidentID string    `gorm:"column:incident_id"`
	Author     string    `gorm:"column:author"`
	Role       string    `gorm:"column:role"`
	Body       string    `gorm:"column:body"`
	CreatedAt  time.Time `gorm:"column:created_at"`
}

func (IncidentComment) TableName() string { return "incident_comments" }

type AuditLog struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Ts         time.Time `gorm:"column:ts"`
	UserID     string    `gorm:"column:user_id"`
	ActionType string    `gorm:"column:action_type"`
	EntityType string    `gorm:"column:entity_type"`
	EntityID   string    `gorm:"column:entity_id"`
	Details    string    `gorm:"column:details"`
	Metadata   JSONMap   `gorm:"column:metadata"`
	PrevHash   string    `gorm:"column:prev_hash"`
	Hash       string    `gorm:"column:hash"`
}

func (AuditLog) TableName() string { return "audit_logs" }

type ThreatIntel struct {
	IP              string    `gorm:"column:ip;primaryKey"`
	AbuseConfidence int       `gorm:"column:abuse_confidence"`
	TotalReports    int       `gorm:"column:total_reports"`
	Country         string    `gorm:"column:country"`
	Raw             JSONRaw   `gorm:"column:raw"`
	FetchedAt       time.Time `gorm:"column:fetched_at"`
	ExpiresAt       time.Time `gorm:"column:expires_at"`
}

func (ThreatIntel) TableName() string { return "threat_intel_cache" }

type AlertDelivery struct {
	ID          string    `gorm:"column:id;primaryKey"`
	IncidentID  string    `gorm:"column:incident_id"`
	Channel     string    `gorm:"column:channel"`
	Status      string    `gorm:"column:status"`
	HTTPStatus  *int      `gorm:"column:http_status"`
	Error       *string   `gorm:"column:error"`
	AttemptedAt time.Time `gorm:"column:attempted_at"`
}

func (AlertDelivery) TableName() string { return "alert_deliveries" }

type ScanRun struct {
	ID          string     `gorm:"column:id;primaryKey"`
	Trigger     string     `gorm:"column:trigger"`
	Actor       string     `gorm:"column:actor"`
	Status      string     `gorm:"column:status"`
	StartedAt   time.Time  `gorm:"column:started_at"`
	FinishedAt  *time.Time `gorm:"column:finished_at"`
	LogsFetched int        `gorm:"column:logs_fetched"`
	Analyzed    int        `gorm:"column:analyzed"`
	NewAlerts   int        `gorm:"column:new_alerts"`
	Error       *string    `gorm:"column:error"`
}

func (ScanRun) TableName() string { return "scan_runs" }

type Setting struct {
	Key       string    `gorm:"column:key;primaryKey"`
	Value     JSONRaw   `gorm:"column:value"`
	UpdatedBy string    `gorm:"column:updated_by"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (Setting) TableName() string { return "settings" }

// StrPtr returns nil for "" so optional text/uuid columns are stored as NULL.
func StrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func StrVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
