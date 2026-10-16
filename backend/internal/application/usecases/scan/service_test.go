package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/alerting"
	"sec_ops/internal/application/usecases/analysis"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/enrichment"
	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestScanService_Run_ConcurrentScanReturnsConflict(t *testing.T) {
	// When a scan is already running, Start() returns ErrConflict
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	llm := &testfakes.ScriptedLLM{Responses: [][]byte{}, Errors: []error{}}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false // disabled
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{})

	// Manually set running flag to simulate a scan in progress
	_ = scanRuns.Start(context.Background(), &entities.ScanRun{
		Trigger:   entities.TriggerManual,
		Actor:     "admin",
		StartedAt: clock.T, // Set to current time so it's not stale
	})

	// Second concurrent scan should fail
	_, err := svc.Run(context.Background(), entities.TriggerManual, "admin2")
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !isConflictError(err) {
		t.Errorf("expected conflict error, got: %v", err)
	}
}

func TestScanService_Run_HappyPath_CreatesIncidentAndAlert(t *testing.T) {
	// End-to-end: flagged logs + LLM returns High risk -> incident + alert
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	// Insert flagged logs
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log2", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log3", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user2", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"risk_score":         "High",
		"summary":            "Multiple failed logins from IP 1.2.3.4",
		"recommended_action": "Block IP 1.2.3.4",
		"suspicious_ips":     []string{"1.2.3.4"},
		"patterns":           []string{"brute_force"},
		"affected_users":     []string{"user1", "user2"},
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}, Errors: []error{nil}}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{})

	result, err := svc.Run(context.Background(), entities.TriggerManual, "admin")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.LogsFetched != 3 {
		t.Errorf("expected 3 logs fetched, got %d", result.LogsFetched)
	}
	if result.Analyzed != 3 {
		t.Errorf("expected 3 logs analyzed, got %d", result.Analyzed)
	}
	if result.Incidents != 1 {
		t.Errorf("expected 1 incident, got %d", result.Incidents)
	}
	if result.NewAlerts != 1 {
		t.Errorf("expected 1 alert, got %d", result.NewAlerts)
	}

	// Verify incident was created
	allInc, _ := incidents.List(context.Background(), interfaces.IncidentQuery{})
	if len(allInc) != 1 {
		t.Fatalf("expected 1 incident in repo, got %d", len(allInc))
	}
	inc := allInc[0]
	if inc.RiskScore != enums.RiskHigh {
		t.Errorf("expected risk High, got %v", inc.RiskScore)
	}
	if inc.Status != enums.StatusOpen {
		t.Errorf("expected status Open, got %v", inc.Status)
	}

	// Verify alert was sent
	if notifier.CallCount != 1 {
		t.Errorf("expected 1 alert sent, got %d", notifier.CallCount)
	}
}

func TestScanService_Run_FingerprintSuppression_OpenIncident(t *testing.T) {
	// Same fingerprint with Open status -> suppressed, no new incident
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	// Create an existing Open incident with a known fingerprint
	fp := entities.IncidentFingerprint([]string{"brute_force"}, []string{"1.2.3.4"}, []string{"user1", "user2"})
	_ = incidents.Create(context.Background(), &entities.Incident{
		Fingerprint:   fp,
		RiskScore:     enums.RiskHigh,
		Status:        enums.StatusOpen,
		AISummary:     "Existing incident",
		SuspiciousIPs: []string{"1.2.3.4"},
		Patterns:      []string{"brute_force"},
		AffectedUsers: []string{"user1", "user2"},
	})

	// Insert new flagged logs
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log2", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user2", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"risk_score":         "High",
		"summary":            "Multiple failed logins from IP 1.2.3.4",
		"recommended_action": "Block IP 1.2.3.4",
		"suspicious_ips":     []string{"1.2.3.4"},
		"patterns":           []string{"brute_force"},
		"affected_users":     []string{"user1", "user2"},
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}, Errors: []error{nil}}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{})

	result, err := svc.Run(context.Background(), entities.TriggerManual, "admin")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// No new incident or alert should be created
	if result.Incidents != 0 {
		t.Errorf("expected 0 new incidents (suppressed), got %d", result.Incidents)
	}
	if result.NewAlerts != 0 {
		t.Errorf("expected 0 new alerts (suppressed), got %d", result.NewAlerts)
	}

	// Still only 1 incident in repo
	allInc, _ := incidents.List(context.Background(), interfaces.IncidentQuery{})
	if len(allInc) != 1 {
		t.Errorf("expected 1 incident total, got %d", len(allInc))
	}

	// Check audit for suppression
	auditEntries, _ := auditRepo.List(context.Background(), interfaces.AuditQuery{})
	foundSuppressed := false
	for _, e := range auditEntries {
		if e.ActionType == enums.AuditAlertSuppressed {
			foundSuppressed = true
			break
		}
	}
	if !foundSuppressed {
		t.Error("expected ALERT_SUPPRESSED audit entry")
	}
}

func TestScanService_Run_FingerprintSuppression_ResolvedWithinWindow(t *testing.T) {
	// Same fingerprint resolved within suppression_days -> suppressed
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	// Create a resolved incident 3 days ago (within 7-day window)
	fp := entities.IncidentFingerprint([]string{"brute_force"}, []string{"1.2.3.4"}, []string{"user1"})
	resolvedAt := clock.T.Add(-3 * 24 * time.Hour)
	_ = incidents.Create(context.Background(), &entities.Incident{
		Fingerprint:   fp,
		RiskScore:     enums.RiskHigh,
		Status:        enums.StatusResolved,
		AISummary:     "Resolved incident",
		SuspiciousIPs: []string{"1.2.3.4"},
		Patterns:      []string{"brute_force"},
		AffectedUsers: []string{"user1"},
		ResolvedAt:    &resolvedAt,
	})

	// Insert new flagged logs with same pattern
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"risk_score":         "High",
		"summary":            "Multiple failed logins from IP 1.2.3.4",
		"recommended_action": "Block IP 1.2.3.4",
		"suspicious_ips":     []string{"1.2.3.4"},
		"patterns":           []string{"brute_force"},
		"affected_users":     []string{"user1"},
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}, Errors: []error{nil}}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{SuppressionDays: 7})

	result, err := svc.Run(context.Background(), entities.TriggerManual, "admin")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Incidents != 0 {
		t.Errorf("expected 0 new incidents (suppressed within window), got %d", result.Incidents)
	}
	if result.Suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", result.Suppressed)
	}
}

func TestScanService_Run_FingerprintSuppression_ResolvedOutsideWindow(t *testing.T) {
	// Same fingerprint resolved outside suppression_days -> new incident created
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	// Create a resolved incident 10 days ago (outside 7-day window)
	fp := entities.IncidentFingerprint([]string{"brute_force"}, []string{"1.2.3.4"}, []string{"user1"})
	resolvedAt := clock.T.Add(-10 * 24 * time.Hour)
	_ = incidents.Create(context.Background(), &entities.Incident{
		Fingerprint:   fp,
		RiskScore:     enums.RiskHigh,
		Status:        enums.StatusResolved,
		AISummary:     "Old resolved incident",
		SuspiciousIPs: []string{"1.2.3.4"},
		Patterns:      []string{"brute_force"},
		AffectedUsers: []string{"user1"},
		ResolvedAt:    &resolvedAt,
	})

	// Insert new flagged logs with same pattern
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	llmResp := map[string]any{
		"risk_score":         "High",
		"summary":            "Multiple failed logins from IP 1.2.3.4",
		"recommended_action": "Block IP 1.2.3.4",
		"suspicious_ips":     []string{"1.2.3.4"},
		"patterns":           []string{"brute_force"},
		"affected_users":     []string{"user1"},
	}
	llmJSON, _ := json.Marshal(llmResp)
	llm := &testfakes.ScriptedLLM{Responses: [][]byte{llmJSON}, Errors: []error{nil}}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{SuppressionDays: 7})

	result, err := svc.Run(context.Background(), entities.TriggerManual, "admin")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Incidents != 1 {
		t.Errorf("expected 1 new incident (outside suppression window), got %d", result.Incidents)
	}
	if result.Suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", result.Suppressed)
	}

	// Should now have 2 total incidents (old resolved + new open)
	allInc, _ := incidents.List(context.Background(), interfaces.IncidentQuery{})
	if len(allInc) != 2 {
		t.Errorf("expected 2 incidents total, got %d", len(allInc))
	}
}

func TestScanService_Run_LLMRetryableError_BatchDeferred(t *testing.T) {
	// LLM returns ErrUpstreamUnavailable -> batch stored with status deferred
	logs := testfakes.NewLogRepository()
	batches := testfakes.NewBatchRepository(logs)
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	tx := &testfakes.TxManager{}

	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
	})

	llm := &testfakes.ScriptedLLM{
		Responses: [][]byte{nil},
		Errors:    []error{fmt.Errorf("%w: service unavailable", interfaces.ErrUpstreamUnavailable)},
	}
	usage := testfakes.NewUsageRepository()
	analysisSvc := analysis.NewService(llm, usage, clock, "gemini-2.5-flash-lite", 10)
	cache := testfakes.NewThreatIntelCache()
	tiClient := testfakes.NewFakeThreatIntelClient()
	tiClient.ConfigOK = false
	enrichSvc := enrichment.NewService(tiClient, cache, usage, clock, 100, 50)
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := testfakes.NewAlertDeliveryRepository()
	notifier := &testfakes.FakeAlertNotifier{}
	alertSvc := alerting.NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	svc := NewService(logs, batches, incidents, scanRuns, analysisSvc, enrichSvc, alertSvc, auditSvc, tx, clock, nil, Config{})

	result, err := svc.Run(context.Background(), entities.TriggerManual, "admin")
	if err != nil {
		t.Fatalf("Run should not fail overall: %v", err)
	}

	// Scan succeeds but no incidents
	if result.Incidents != 0 {
		t.Errorf("expected 0 incidents, got %d", result.Incidents)
	}
	if result.Analyzed != 0 {
		t.Errorf("expected 0 analyzed (deferred), got %d", result.Analyzed)
	}

	// Check batch status
	allBatches, _ := batches.Retryable(context.Background(), 10, 10)
	if len(allBatches) != 1 {
		t.Fatalf("expected 1 deferred batch, got %d", len(allBatches))
	}
	if allBatches[0].Status != entities.BatchDeferred {
		t.Errorf("expected status deferred, got %v", allBatches[0].Status)
	}
}

func TestScanService_chunk_RespectsLimits(t *testing.T) {
	// chunk respects maxPerBatch and maxBatches
	logs := make([]entities.RawLog, 150)
	for i := range logs {
		logs[i] = entities.RawLog{LogID: fmt.Sprintf("log%d", i)}
	}

	// maxPerBatch=50, maxBatches=2 -> 2 batches of 50, rest dropped
	chunks := chunk(logs, 50, 2)
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 50 {
		t.Errorf("expected first chunk of 50, got %d", len(chunks[0]))
	}
	if len(chunks[1]) != 50 {
		t.Errorf("expected second chunk of 50, got %d", len(chunks[1]))
	}

	// Verify logs beyond cap are left out
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	if total != 100 {
		t.Errorf("expected 100 logs total in chunks, got %d", total)
	}
}

func TestScanService_chunk_HandlesExactMultiple(t *testing.T) {
	logs := make([]entities.RawLog, 100)
	for i := range logs {
		logs[i] = entities.RawLog{LogID: fmt.Sprintf("log%d", i)}
	}

	chunks := chunk(logs, 50, 3)
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks (exact fit), got %d", len(chunks))
	}
}

func TestScanService_chunk_HandlesEmpty(t *testing.T) {
	chunks := chunk(nil, 50, 3)
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty input, got %d", len(chunks))
	}
}

func isConflictError(err error) bool {
	return err != nil && (err == interfaces.ErrConflict || fmt.Sprintf("%v", err) == fmt.Sprintf("%v: a scan is already running", interfaces.ErrConflict))
}
