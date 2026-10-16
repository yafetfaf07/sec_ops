package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
)

// -------------------------------------------------------------------- BuildAggregate tests

func TestBuildAggregate_GroupsFailuresByIP(t *testing.T) {
	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: time.Now()},
		{UserID: "user2", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: time.Now()},
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: time.Now()},
		{UserID: "user3", IPAddress: "5.6.7.8", Action: enums.ActionLoginFailed, Timestamp: time.Now()},
	}

	agg := BuildAggregate(flagged, nil)

	if agg.TotalLogs != 4 {
		t.Errorf("TotalLogs = %d, want 4", agg.TotalLogs)
	}
	if agg.FailedLogins != 4 {
		t.Errorf("FailedLogins = %d, want 4", agg.FailedLogins)
	}
	if agg.UniqueIPs != 2 {
		t.Errorf("UniqueIPs = %d, want 2", agg.UniqueIPs)
	}
	if agg.UniqueUsers != 3 {
		t.Errorf("UniqueUsers = %d, want 3", agg.UniqueUsers)
	}

	// Check that 1.2.3.4 is first (3 failures) and has 2 distinct users
	if len(agg.FailuresByIP) < 1 {
		t.Fatal("FailuresByIP is empty")
	}
	top := agg.FailuresByIP[0]
	if top.IP != "1.2.3.4" {
		t.Errorf("top IP = %s, want 1.2.3.4", top.IP)
	}
	if top.Count != 3 {
		t.Errorf("top IP count = %d, want 3", top.Count)
	}
	if len(top.Users) != 2 {
		t.Errorf("top IP users = %d, want 2", len(top.Users))
	}
}

func TestBuildAggregate_GroupsEscalationsByIP(t *testing.T) {
	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionPrivilegeEscalation, Timestamp: time.Now()},
		{UserID: "user2", IPAddress: "1.2.3.4", Action: enums.ActionPrivilegeEscalation, Timestamp: time.Now()},
		{UserID: "user3", IPAddress: "5.6.7.8", Action: enums.ActionPrivilegeEscalation, Timestamp: time.Now()},
	}

	agg := BuildAggregate(flagged, nil)

	if agg.Escalations != 3 {
		t.Errorf("Escalations = %d, want 3", agg.Escalations)
	}
	if len(agg.EscalationsByIP) != 2 {
		t.Errorf("len(EscalationsByIP) = %d, want 2", len(agg.EscalationsByIP))
	}

	// Top escalation IP should be 1.2.3.4 with 2 events
	if agg.EscalationsByIP[0].IP != "1.2.3.4" || agg.EscalationsByIP[0].Count != 2 {
		t.Errorf("top escalation IP = %s with count %d, want 1.2.3.4 with 2",
			agg.EscalationsByIP[0].IP, agg.EscalationsByIP[0].Count)
	}
}

func TestBuildAggregate_DetectsImpossibleTravel(t *testing.T) {
	// Two logins from different countries within 60 minutes should be flagged
	base := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	logins := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginSuccess, Timestamp: base},
		{UserID: "user1", IPAddress: "5.6.7.8", Country: "CN", Action: enums.ActionLoginSuccess, Timestamp: base.Add(30 * time.Minute)},
	}

	agg := BuildAggregate(nil, logins)

	if len(agg.ImpossibleTravel) != 1 {
		t.Fatalf("len(ImpossibleTravel) = %d, want 1", len(agg.ImpossibleTravel))
	}

	travel := agg.ImpossibleTravel[0]
	if travel.UserID != "user1" {
		t.Errorf("travel.UserID = %s, want user1", travel.UserID)
	}
	if travel.FromCountry != "US" {
		t.Errorf("travel.FromCountry = %s, want US", travel.FromCountry)
	}
	if travel.ToCountry != "CN" {
		t.Errorf("travel.ToCountry = %s, want CN", travel.ToCountry)
	}
	if travel.MinutesApart != 30 {
		t.Errorf("travel.MinutesApart = %f, want 30", travel.MinutesApart)
	}
	if travel.ToIP != "5.6.7.8" {
		t.Errorf("travel.ToIP = %s, want 5.6.7.8", travel.ToIP)
	}
}

func TestBuildAggregate_NoImpossibleTravelSameCountry(t *testing.T) {
	// Same country should not trigger impossible travel
	base := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	logins := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginSuccess, Timestamp: base},
		{UserID: "user1", IPAddress: "5.6.7.8", Country: "US", Action: enums.ActionLoginSuccess, Timestamp: base.Add(30 * time.Minute)},
	}

	agg := BuildAggregate(nil, logins)

	if len(agg.ImpossibleTravel) != 0 {
		t.Errorf("len(ImpossibleTravel) = %d, want 0 (same country)", len(agg.ImpossibleTravel))
	}
}

func TestBuildAggregate_NoImpossibleTravelOverThreshold(t *testing.T) {
	// Travel with > 60 minutes gap should not be flagged
	base := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	logins := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginSuccess, Timestamp: base},
		{UserID: "user1", IPAddress: "5.6.7.8", Country: "CN", Action: enums.ActionLoginSuccess, Timestamp: base.Add(61 * time.Minute)},
	}

	agg := BuildAggregate(nil, logins)

	if len(agg.ImpossibleTravel) != 0 {
		t.Errorf("len(ImpossibleTravel) = %d, want 0 (over threshold)", len(agg.ImpossibleTravel))
	}
}

func TestBuildAggregate_CapsListSizes(t *testing.T) {
	// Create 25 different IPs (should cap at 20)
	flagged := make([]entities.RawLog, 25)
	for i := 0; i < 25; i++ {
		flagged[i] = entities.RawLog{
			UserID:    "user1",
			IPAddress: testIP(i),
			Action:    enums.ActionLoginFailed,
			Timestamp: time.Now(),
		}
	}

	agg := BuildAggregate(flagged, nil)

	if len(agg.FailuresByIP) != 20 {
		t.Errorf("len(FailuresByIP) = %d, want 20 (capped)", len(agg.FailuresByIP))
	}
}

func TestBuildAggregate_CapsSampleLogs(t *testing.T) {
	// Create 50 logs (should cap at maxPromptLogs = 40)
	flagged := make([]entities.RawLog, 50)
	for i := 0; i < 50; i++ {
		flagged[i] = entities.RawLog{
			UserID:    "user1",
			IPAddress: "1.2.3.4",
			Action:    enums.ActionLoginFailed,
			Timestamp: time.Now(),
		}
	}

	agg := BuildAggregate(flagged, nil)

	if len(agg.SampleLogs) != 40 {
		t.Errorf("len(SampleLogs) = %d, want 40 (capped)", len(agg.SampleLogs))
	}
}

// -------------------------------------------------------------------- Service.Analyze tests

func TestAnalyze_ConsumesExactlyOneUsageUnit(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse("Medium", "Test summary", "Test action", []string{"1.2.3.4"}, []string{"pattern1"}, []string{"user1"}),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	count := usage.GetCount("gemini", clock.Now())
	if count != 1 {
		t.Errorf("usage count = %d, want 1", count)
	}

	if llm.CallCount != 1 {
		t.Errorf("LLM call count = %d, want 1", llm.CallCount)
	}
}

func TestAnalyze_ReturnsQuotaExceededWithoutCallingLLM(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse("Medium", "Test summary", "Test action", []string{"1.2.3.4"}, []string{"pattern1"}, []string{"user1"}),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 1)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	// First call should succeed
	_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err != nil {
		t.Fatalf("First Analyze call failed: %v", err)
	}

	// Reset call count to verify second call doesn't reach LLM
	llm.CallCount = 0

	// Second call should return quota exceeded without calling LLM
	_, _, err = svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err == nil {
		t.Fatal("Expected quota exceeded error, got nil")
	}
	if !containsString(err.Error(), "quota exceeded") && !containsString(err.Error(), "budget exhausted") {
		t.Errorf("Expected quota error, got: %v", err)
	}

	if llm.CallCount != 0 {
		t.Errorf("LLM called %d times after quota exhausted, want 0", llm.CallCount)
	}
}

func TestAnalyze_DropsInventedSuspiciousIPs(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()

	// LLM response includes IPs that are NOT in the aggregate
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse(
			"High",
			"Test summary",
			"Test action",
			[]string{"1.2.3.4", "9.9.9.9", "8.8.8.8"}, // 9.9.9.9 and 8.8.8.8 are not in logs
			[]string{"pattern1"},
			[]string{"user1"},
		),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	outcome, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Only 1.2.3.4 should be kept
	if len(outcome.SuspiciousIPs) != 1 {
		t.Errorf("len(SuspiciousIPs) = %d, want 1", len(outcome.SuspiciousIPs))
	}
	if len(outcome.SuspiciousIPs) > 0 && outcome.SuspiciousIPs[0] != "1.2.3.4" {
		t.Errorf("SuspiciousIPs[0] = %s, want 1.2.3.4", outcome.SuspiciousIPs[0])
	}
}

func TestAnalyze_DropsInventedAffectedUsers(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()

	// LLM response includes users NOT in the aggregate
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse(
			"High",
			"Test summary",
			"Test action",
			[]string{"1.2.3.4"},
			[]string{"pattern1"},
			[]string{"user1", "user2", "invented_user"}, // invented_user not in logs
		),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
		{UserID: "user2", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	outcome, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Only user1 and user2 should be kept
	if len(outcome.AffectedUsers) != 2 {
		t.Errorf("len(AffectedUsers) = %d, want 2", len(outcome.AffectedUsers))
	}

	// Check that invented_user is not in the list
	for _, u := range outcome.AffectedUsers {
		if u == "invented_user" {
			t.Error("invented_user should have been filtered out")
		}
	}
}

func TestAnalyze_RejectsInvalidRiskScore(t *testing.T) {
	tests := []struct {
		name      string
		riskScore string
	}{
		{"empty", ""},
		{"invalid", "InvalidRisk"},
		{"lowercase", "medium"},
		{"typo", "Hight"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			usage := testfakes.NewFakeUsageRepository()
			llm := &testfakes.FakeLLM{
				ConfigOK: true,
				Response: testfakes.BuildLLMResponse(
					tt.riskScore,
					"Test summary",
					"Test action",
					[]string{"1.2.3.4"},
					[]string{"pattern1"},
					[]string{"user1"},
				),
			}

			svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

			flagged := []entities.RawLog{
				{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
			}

			_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
			if err == nil {
				t.Fatal("Expected error for invalid risk score, got nil")
			}
			if !containsString(err.Error(), "invalid risk_score") {
				t.Errorf("Expected 'invalid risk_score' error, got: %v", err)
			}
		})
	}
}

func TestAnalyze_AcceptsValidRiskScores(t *testing.T) {
	tests := []struct {
		riskScore string
		expected  enums.RiskLevel
	}{
		{"Low", enums.RiskLow},
		{"Medium", enums.RiskMedium},
		{"High", enums.RiskHigh},
		{"Critical", enums.RiskCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.riskScore), func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			usage := testfakes.NewFakeUsageRepository()
			llm := &testfakes.FakeLLM{
				ConfigOK: true,
				Response: testfakes.BuildLLMResponse(
					tt.riskScore,
					"Test summary",
					"Test action",
					[]string{"1.2.3.4"},
					[]string{"pattern1"},
					[]string{"user1"},
				),
			}

			svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

			flagged := []entities.RawLog{
				{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
			}

			outcome, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			if outcome.RiskScore != tt.expected {
				t.Errorf("RiskScore = %v, want %v", outcome.RiskScore, tt.expected)
			}
		})
	}
}

func TestAnalyze_RejectsMalformedJSON(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: []byte(`{invalid json`),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err == nil {
		t.Fatal("Expected error for malformed JSON, got nil")
	}
	if !containsString(err.Error(), "malformed JSON") {
		t.Errorf("Expected 'malformed JSON' error, got: %v", err)
	}
}

func TestAnalyze_RejectsEmptySummary(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse("Medium", "", "action", []string{}, []string{}, []string{}),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err == nil {
		t.Fatal("Expected error for empty summary, got nil")
	}
	if !containsString(err.Error(), "empty summary") {
		t.Errorf("Expected 'empty summary' error, got: %v", err)
	}
}

func TestAnalyze_HandlesIPsFromImpossibleTravel(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()

	// Create impossible travel event
	base := clock.Now()
	successLogins := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginSuccess, Timestamp: base},
		{UserID: "user1", IPAddress: "5.6.7.8", Country: "CN", Action: enums.ActionLoginSuccess, Timestamp: base.Add(30 * time.Minute)},
	}

	// LLM response includes the IP from impossible travel
	llm := &testfakes.FakeLLM{
		ConfigOK: true,
		Response: testfakes.BuildLLMResponse(
			"High",
			"Impossible travel detected",
			"Investigate user1",
			[]string{"5.6.7.8"}, // This IP is from the impossible travel event
			[]string{"impossible_travel"},
			[]string{"user1"},
		),
	}

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	// Empty flagged but with impossible travel detection
	outcome, _, err := svc.Analyze(context.Background(), nil, successLogins, base, base.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// 5.6.7.8 should be kept because it's in the impossible travel event
	if len(outcome.SuspiciousIPs) != 1 || outcome.SuspiciousIPs[0] != "5.6.7.8" {
		t.Errorf("SuspiciousIPs = %v, want [5.6.7.8]", outcome.SuspiciousIPs)
	}
}

func TestAnalyze_UnconfiguredLLMReturnsError(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	usage := testfakes.NewFakeUsageRepository()
	llm := &testfakes.FakeLLM{ConfigOK: false} // Not configured

	svc := NewService(llm, usage, clock, "gemini-1.5-flash", 100)

	flagged := []entities.RawLog{
		{UserID: "user1", IPAddress: "1.2.3.4", Action: enums.ActionLoginFailed, Timestamp: clock.Now()},
	}

	_, _, err := svc.Analyze(context.Background(), flagged, nil, clock.Now(), clock.Now())
	if err == nil {
		t.Fatal("Expected error for unconfigured LLM, got nil")
	}
	if !containsString(err.Error(), "not configured") {
		t.Errorf("Expected 'not configured' error, got: %v", err)
	}
}

// -------------------------------------------------------------------- Helpers

func testIP(n int) string {
	// Generate unique IPs like 192.0.2.0, 192.0.2.1, etc.
	return fmt.Sprintf("192.0.2.%d", n)
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Verify that parseAndValidate correctly builds the response structure
func TestParseAndValidate_BuildsCorrectOutcome(t *testing.T) {
	raw := testfakes.BuildLLMResponse(
		"High",
		"This is a test summary",
		"Block the attacker",
		[]string{"1.2.3.4", "5.6.7.8"},
		[]string{"brute_force", "credential_stuffing"},
		[]string{"user1", "user2"},
	)

	// Create aggregate with the known IPs and users
	agg := Aggregate{
		FailuresByIP: []IPCount{
			{IP: "1.2.3.4", Count: 5, Users: []string{"user1"}},
			{IP: "5.6.7.8", Count: 3, Users: []string{"user2"}},
		},
	}

	outcome, err := parseAndValidate(raw, agg)
	if err != nil {
		t.Fatalf("parseAndValidate failed: %v", err)
	}

	if outcome.RiskScore != enums.RiskHigh {
		t.Errorf("RiskScore = %v, want High", outcome.RiskScore)
	}
	if outcome.Summary != "This is a test summary" {
		t.Errorf("Summary = %q, want %q", outcome.Summary, "This is a test summary")
	}
	if outcome.RecommendedAction != "Block the attacker" {
		t.Errorf("RecommendedAction = %q, want %q", outcome.RecommendedAction, "Block the attacker")
	}
	if len(outcome.SuspiciousIPs) != 2 {
		t.Errorf("len(SuspiciousIPs) = %d, want 2", len(outcome.SuspiciousIPs))
	}
	if len(outcome.Patterns) != 2 {
		t.Errorf("len(Patterns) = %d, want 2", len(outcome.Patterns))
	}
	if len(outcome.AffectedUsers) != 2 {
		t.Errorf("len(AffectedUsers) = %d, want 2", len(outcome.AffectedUsers))
	}

	// Verify RawResponse is stored
	var parsed map[string]interface{}
	if err := json.Unmarshal(outcome.RawResponse, &parsed); err != nil {
		t.Errorf("RawResponse is not valid JSON: %v", err)
	}
}
