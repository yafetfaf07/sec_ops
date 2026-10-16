package enums

import "testing"

func TestRiskLevelOrdering(t *testing.T) {
	levels := AllRiskLevels()
	for i := 1; i < len(levels); i++ {
		if levels[i].Rank() <= levels[i-1].Rank() {
			t.Fatalf("%s must rank above %s", levels[i], levels[i-1])
		}
	}
	if RiskLevel("Severe").Rank() != -1 || RiskLevel("Severe").Valid() {
		t.Error("unknown level must be invalid with rank -1")
	}
	if got := MaxRisk(RiskHigh, RiskCritical); got != RiskCritical {
		t.Errorf("MaxRisk(High, Critical) = %s", got)
	}
	if got := MaxRisk(RiskMedium, RiskLevel("bogus")); got != RiskMedium {
		t.Errorf("invalid level must lose MaxRisk, got %s", got)
	}
}

func TestRiskRequiresAlert(t *testing.T) {
	cases := map[RiskLevel]bool{RiskLow: false, RiskMedium: true, RiskHigh: true, RiskCritical: true, "": false}
	for lvl, want := range cases {
		if got := lvl.RequiresAlert(); got != want {
			t.Errorf("%q.RequiresAlert() = %v, want %v", lvl, got, want)
		}
	}
}

func TestIncidentTransitions(t *testing.T) {
	cases := []struct {
		from, to IncidentStatus
		ok       bool
	}{
		{StatusOpen, StatusAcknowledged, true},
		{StatusOpen, StatusResolved, true},
		{StatusAcknowledged, StatusResolved, true},
		{StatusAcknowledged, StatusOpen, false},
		{StatusAcknowledged, StatusAcknowledged, false},
		{StatusOpen, StatusOpen, false},
		// Resolved is terminal: this is what stops re-alerting (FR-SEC-012).
		{StatusResolved, StatusOpen, false},
		{StatusResolved, StatusAcknowledged, false},
		{StatusResolved, StatusResolved, false},
	}
	for _, tc := range cases {
		if got := tc.from.CanTransitionTo(tc.to); got != tc.ok {
			t.Errorf("%s -> %s = %v, want %v", tc.from, tc.to, got, tc.ok)
		}
	}
}

func TestLogActionFlagging(t *testing.T) {
	cases := map[LogAction]bool{
		ActionLoginSuccess:        false,
		ActionLoginFailed:         true,
		ActionPrivilegeEscalation: true,
	}
	for a, want := range cases {
		if got := a.RequiresReview(); got != want {
			t.Errorf("%q.RequiresReview() = %v, want %v", a, got, want)
		}
	}
	if _, err := ParseLogAction("login failed"); err == nil {
		t.Error("parsing must be exact-case to match the frontend and DB CHECK")
	}
}

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role               Role
		triage, administer bool
	}{
		{RoleAdmin, true, true},
		{RoleAnalyst, true, false},
		{RoleViewer, false, false},
		{Role("root"), false, false},
	}
	for _, tc := range cases {
		if tc.role.CanTriage() != tc.triage || tc.role.CanAdminister() != tc.administer {
			t.Errorf("%q: triage=%v admin=%v", tc.role, tc.role.CanTriage(), tc.role.CanAdminister())
		}
	}
}

// Guards the frontend contract: these literals are duplicated in
// frontend app/lib/types.ts and in the 0001_init.sql CHECK constraints.
func TestEnumStringsMatchFrontendContract(t *testing.T) {
	pairs := map[string]string{
		string(RiskLow): "Low", string(RiskMedium): "Medium", string(RiskHigh): "High", string(RiskCritical): "Critical",
		string(StatusOpen): "Open", string(StatusAcknowledged): "Acknowledged", string(StatusResolved): "Resolved",
		string(ActionLoginSuccess): "Login Success", string(ActionLoginFailed): "Login Failed",
		string(ActionPrivilegeEscalation): "Privilege Escalation",
		string(RoleAdmin):                 "admin", string(RoleAnalyst): "analyst", string(RoleViewer): "viewer",
		string(AuditScheduledScan): "SCHEDULED_SCAN", string(AuditIncidentResolved): "INCIDENT_RESOLVED",
		SystemActor: "SYSTEM",
	}
	for got, want := range pairs {
		if got != want {
			t.Errorf("enum value %q, want %q", got, want)
		}
	}
}
