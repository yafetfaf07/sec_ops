// Package enums holds the domain enumerations. Their string values are the
// exact strings used by the React frontend (app/lib/types.ts) and stored in
// the database CHECK constraints, so no translation layer is needed. Changing
// a value is a breaking change for the frontend AND requires a migration.
package enums

import "fmt"

// RiskLevel is ordered: Low < Medium < High < Critical.
type RiskLevel string

const (
	RiskLow      RiskLevel = "Low"
	RiskMedium   RiskLevel = "Medium"
	RiskHigh     RiskLevel = "High"
	RiskCritical RiskLevel = "Critical"
)

var riskRank = map[RiskLevel]int{RiskLow: 0, RiskMedium: 1, RiskHigh: 2, RiskCritical: 3}

// AllRiskLevels is ordered from lowest to highest.
func AllRiskLevels() []RiskLevel { return []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical} }

func (r RiskLevel) Valid() bool { _, ok := riskRank[r]; return ok }

// Rank returns the ordinal for sorting/comparison, or -1 for an invalid level.
func (r RiskLevel) Rank() int {
	if n, ok := riskRank[r]; ok {
		return n
	}
	return -1
}

func (r RiskLevel) AtLeast(other RiskLevel) bool { return r.Valid() && r.Rank() >= other.Rank() }

// RequiresAlert reports whether an incident at this level is dispatched to
// Slack/Discord (FR-SEC-003, FR-SEC-005: Medium and above).
func (r RiskLevel) RequiresAlert() bool { return r.AtLeast(RiskMedium) }

// MaxRisk returns the higher of two levels; invalid inputs lose.
func MaxRisk(a, b RiskLevel) RiskLevel {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

func ParseRiskLevel(s string) (RiskLevel, error) {
	r := RiskLevel(s)
	if !r.Valid() {
		return "", fmt.Errorf("invalid risk level %q", s)
	}
	return r, nil
}

// IncidentStatus follows Open -> Acknowledged -> Resolved, with Open ->
// Resolved allowed. Resolved is terminal (FR-SEC-012: no re-alerting).
type IncidentStatus string

const (
	StatusOpen         IncidentStatus = "Open"
	StatusAcknowledged IncidentStatus = "Acknowledged"
	StatusResolved     IncidentStatus = "Resolved"
)

func (s IncidentStatus) Valid() bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusResolved:
		return true
	}
	return false
}

func (s IncidentStatus) CanTransitionTo(next IncidentStatus) bool {
	switch s {
	case StatusOpen:
		return next == StatusAcknowledged || next == StatusResolved
	case StatusAcknowledged:
		return next == StatusResolved
	}
	return false
}

func ParseIncidentStatus(s string) (IncidentStatus, error) {
	st := IncidentStatus(s)
	if !st.Valid() {
		return "", fmt.Errorf("invalid incident status %q", s)
	}
	return st, nil
}

type LogAction string

const (
	ActionLoginSuccess        LogAction = "Login Success"
	ActionLoginFailed         LogAction = "Login Failed"
	ActionPrivilegeEscalation LogAction = "Privilege Escalation"
)

func AllLogActions() []LogAction {
	return []LogAction{ActionLoginSuccess, ActionLoginFailed, ActionPrivilegeEscalation}
}

func (a LogAction) Valid() bool {
	switch a {
	case ActionLoginSuccess, ActionLoginFailed, ActionPrivilegeEscalation:
		return true
	}
	return false
}

// RequiresReview reports whether a log is flagged for AI review (FR-SEC-001).
// The server always computes the flag; a client-supplied value is ignored.
func (a LogAction) RequiresReview() bool {
	return a == ActionLoginFailed || a == ActionPrivilegeEscalation
}

func ParseLogAction(s string) (LogAction, error) {
	a := LogAction(s)
	if !a.Valid() {
		return "", fmt.Errorf("invalid log action %q", s)
	}
	return a, nil
}

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	}
	return false
}

// CanTriage: acknowledge/resolve incidents, run NL queries, read audit.
func (r Role) CanTriage() bool { return r == RoleAdmin || r == RoleAnalyst }

// CanAdminister: settings, scheduler, users, ingestion, manual scans.
func (r Role) CanAdminister() bool { return r == RoleAdmin }

func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("invalid role %q", s)
	}
	return r, nil
}

// AuditAction values are the `action_type` strings shown in the audit view.
// SCHEDULED_SCAN, INCIDENT_ACKNOWLEDGED, INCIDENT_RESOLVED and
// SETTINGS_UPDATED match what the frontend mock already uses.
type AuditAction string

const (
	AuditLogsIngested         AuditAction = "LOGS_INGESTED"
	AuditScheduledScan        AuditAction = "SCHEDULED_SCAN"
	AuditScanFailed           AuditAction = "SCAN_FAILED"
	AuditAIAnalysis           AuditAction = "AI_ANALYSIS"
	AuditAIAnalysisDeferred   AuditAction = "AI_ANALYSIS_DEFERRED"
	AuditThreatIntelLookup    AuditAction = "THREAT_INTEL_LOOKUP"
	AuditIncidentCreated      AuditAction = "INCIDENT_CREATED"
	AuditIncidentEscalated    AuditAction = "INCIDENT_ESCALATED"
	AuditAlertSent            AuditAction = "ALERT_SENT"
	AuditAlertFailed          AuditAction = "ALERT_FAILED"
	AuditAlertSuppressed      AuditAction = "ALERT_SUPPRESSED"
	AuditIncidentAcknowledged AuditAction = "INCIDENT_ACKNOWLEDGED"
	AuditIncidentResolved     AuditAction = "INCIDENT_RESOLVED"
	AuditNLQuery              AuditAction = "NL_QUERY"
	AuditSettingsUpdated      AuditAction = "SETTINGS_UPDATED"
	AuditUserLogin            AuditAction = "USER_LOGIN"
	AuditUserLoginFailed      AuditAction = "USER_LOGIN_FAILED"
	AuditUserCreated          AuditAction = "USER_CREATED"
	AuditUserRoleChanged      AuditAction = "USER_ROLE_CHANGED"
)

// SystemActor is recorded as user_id for automated actions (FR-SEC-031).
const SystemActor = "SYSTEM"
