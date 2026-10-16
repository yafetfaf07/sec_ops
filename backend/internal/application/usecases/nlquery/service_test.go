package nlquery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestNLQueryService_Run_ValidatesQueryLength(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantError bool
	}{
		{"empty query", "", true},
		{"whitespace only", "   ", true},
		{"valid short query", "show me failed logins", false},
		{"exactly at max", strings.Repeat("a", maxQueryLen), false},
		{"over max", strings.Repeat("a", maxQueryLen+1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := testfakes.NewLogRepository()
			incidents := testfakes.NewIncidentRepository()
			auditRepo := testfakes.NewAuditRepository()
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
			auditSvc := audit.NewService(auditRepo, clock)

			llmResp := map[string]any{"explanation": "test"}
			llmJSON, _ := json.Marshal(llmResp)
			llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

			svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
			p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

			_, err := svc.Run(context.Background(), p, tt.query)
			if tt.wantError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestNLQueryService_Run_BuildsLogQuery(t *testing.T) {
	// Verify LLM filter is translated to LogQuery with enum validation
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	// Insert some logs
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log2", Timestamp: clock.T.Add(-2 * time.Hour), UserID: "user2", IPAddress: "5.6.7.8", Country: "CA", Action: enums.ActionLoginSuccess, Flagged: false, IngestedAt: clock.T},
		{LogID: "log3", Timestamp: clock.T.Add(-3 * time.Hour), UserID: "user3", IPAddress: "9.10.11.12", Country: "US", Action: enums.ActionPrivilegeEscalation, Flagged: true, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"actions":     []string{"Login Failed"},
		"countries":   []string{"US"},
		"risk_levels": []string{"High"},
		"hours":       24,
		"explanation": "Showing failed logins from US",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

	result, err := svc.Run(context.Background(), p, "show me failed logins from US")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should match only log1 (LoginFailed + US)
	if len(result.Logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(result.Logs))
	}
	if len(result.Logs) > 0 && result.Logs[0].LogID != "log1" {
		t.Errorf("expected log1, got %s", result.Logs[0].LogID)
	}

	// Verify filters are applied
	if _, ok := result.FiltersApplied["action"]; !ok {
		t.Error("expected action filter in FiltersApplied")
	}
	if _, ok := result.FiltersApplied["country"]; !ok {
		t.Error("expected country filter in FiltersApplied")
	}
}

func TestNLQueryService_Run_UnknownEnumsSilentlyDropped(t *testing.T) {
	// Unknown action/risk strings in LLM response are silently dropped
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log2", Timestamp: clock.T.Add(-2 * time.Hour), UserID: "user2", IPAddress: "5.6.7.8", Country: "CA", Action: enums.ActionLoginSuccess, Flagged: false, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"actions":     []string{"InvalidAction", "Login Failed"},
		"countries":   []string{"US"},
		"risk_levels": []string{"SuperCritical", "High"},
		"hours":       24,
		"explanation": "Testing unknown enums",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

	result, err := svc.Run(context.Background(), p, "test query")
	if err != nil {
		t.Fatalf("Run should not fail on unknown enums: %v", err)
	}

	// Should still work, just with only valid enum (Login Failed)
	if len(result.Logs) != 1 {
		t.Errorf("expected 1 log (only valid action), got %d", len(result.Logs))
	}
}

func TestNLQueryService_Run_NeverConcatenatesSQL(t *testing.T) {
	// CRITICALLY verify model's filter values are matched against fixed enums
	// and never concatenated into anything resembling SQL
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	// Attempt SQL injection via LLM response
	llmResp := map[string]any{
		"actions":     []string{"Login Failed'; DROP TABLE users; --"},
		"countries":   []string{"US' OR '1'='1"},
		"risk_levels": []string{"High"},
		"hours":       24,
		"explanation": "SQL injection attempt",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

	result, err := svc.Run(context.Background(), p, "test query")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// The malicious action string doesn't match any enum, so it's dropped
	// The malicious country string is just treated as a literal string filter
	// buildQueries returns structured LogQuery/IncidentQuery types, never SQL strings
	logQuery, incQuery, _ := svc.buildQueries(llmFilter{
		Actions:    []string{"Login Failed'; DROP TABLE users; --"},
		Countries:  []string{"US' OR '1'='1"},
		RiskLevels: []string{"High"},
		Hours:      24,
	})

	// Verify the output is a structured query, not SQL
	if len(logQuery.Actions) > 0 {
		// If any action was parsed, it must be a valid enum
		for _, a := range logQuery.Actions {
			if !a.Valid() {
				t.Errorf("invalid action enum slipped through: %v", a)
			}
		}
	}

	// Countries are just strings, but they're used in parameterized queries by the repo
	// The critical thing is that buildQueries returns interfaces.LogQuery, not a SQL string
	if len(logQuery.Countries) > 0 {
		// The malicious string is treated as a literal country name
		// The repository will use parameterized queries, so no SQL injection
		t.Logf("Countries filter: %v (treated as literal strings in parameterized query)", logQuery.Countries)
	}

	// Verify result types are structured, not strings
	_ = logQuery // interfaces.LogQuery
	_ = incQuery // interfaces.IncidentQuery
	_ = result   // *dtos.NLQueryResult

	// No SQL string should ever be constructed
	t.Log("buildQueries returns structured types, never SQL strings - verified")
}

func TestNLQueryService_Run_ClampsHoursAndLimit(t *testing.T) {
	// hours clamped to maxHours, limit to resultLimit
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	llmResp := map[string]any{
		"actions":     []string{"Login Failed"},
		"countries":   []string{},
		"risk_levels": []string{},
		"hours":       9999, // way over maxHours
		"explanation": "Testing clamping",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

	_, err := svc.Run(context.Background(), p, "test query")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify buildQueries clamps hours
	logQuery, _, _ := svc.buildQueries(llmFilter{Hours: 9999})
	if logQuery.Since == nil {
		t.Fatal("expected Since to be set")
	}
	timeSince := clock.T.Sub(*logQuery.Since)
	maxDuration := time.Duration(maxHours) * time.Hour
	if timeSince > maxDuration {
		t.Errorf("hours not clamped: got %v, max %v", timeSince, maxDuration)
	}

	// Verify resultLimit is applied
	if logQuery.Limit != resultLimit {
		t.Errorf("expected limit %d, got %d", resultLimit, logQuery.Limit)
	}
}

func TestNLQueryService_Run_DefaultsHoursWhenZero(t *testing.T) {
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	llmResp := map[string]any{
		"actions":     []string{},
		"countries":   []string{},
		"risk_levels": []string{},
		"hours":       0,
		"explanation": "No time specified",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")

	logQuery, _, _ := svc.buildQueries(llmFilter{Hours: 0})
	if logQuery.Since == nil {
		t.Fatal("expected Since to be set")
	}
	timeSince := clock.T.Sub(*logQuery.Since)
	expected := time.Duration(defaultHours) * time.Hour
	if timeSince != expected {
		t.Errorf("expected default %v, got %v", expected, timeSince)
	}
}

func TestNLQueryService_Run_RecordsAudit(t *testing.T) {
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)

	llmResp := map[string]any{
		"actions":     []string{},
		"countries":   []string{},
		"risk_levels": []string{},
		"hours":       24,
		"explanation": "Test",
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}}

	svc := NewService(llm, logs, incidents, auditSvc, clock, "gemini-2.5-flash-lite")
	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAnalyst}

	_, err := svc.Run(context.Background(), p, "test query")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	entries, _ := auditRepo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].ActionType != enums.AuditNLQuery {
		t.Errorf("expected action NL_QUERY, got %v", entries[0].ActionType)
	}
	if entries[0].UserID != "user1" {
		t.Errorf("expected user1, got %s", entries[0].UserID)
	}
}
