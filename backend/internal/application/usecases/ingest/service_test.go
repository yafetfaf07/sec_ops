package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/ingest"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// ----------------------------------------------------------------- Fakes

type fakeLogRepo struct {
	logs          []entities.RawLog
	insertedCount int
	shouldFail    error
}

func (r *fakeLogRepo) InsertMany(ctx context.Context, logs []entities.RawLog) (int, error) {
	if r.shouldFail != nil {
		return 0, r.shouldFail
	}
	inserted := 0
	for _, l := range logs {
		// Check for duplicates by log_id
		duplicate := false
		for _, existing := range r.logs {
			if existing.LogID == l.LogID {
				duplicate = true
				break
			}
		}
		if !duplicate {
			r.logs = append(r.logs, l)
			inserted++
		}
	}
	r.insertedCount = inserted
	return inserted, nil
}

func (r *fakeLogRepo) List(ctx context.Context, q interfaces.LogQuery) ([]entities.RawLog, int, error) {
	return r.logs, len(r.logs), nil
}

func (r *fakeLogRepo) Countries(ctx context.Context) ([]string, error) {
	return []string{"USA", "UK"}, nil
}

func (r *fakeLogRepo) UnanalyzedFlagged(ctx context.Context, since time.Time, limit int) ([]entities.RawLog, error) {
	return nil, nil
}

func (r *fakeLogRepo) CountUnanalyzedFlagged(ctx context.Context, since time.Time) (int, error) {
	return 0, nil
}

func (r *fakeLogRepo) SuccessfulLoginsForUsers(ctx context.Context, userIDs []string, from, to time.Time, limit int) ([]entities.RawLog, error) {
	return nil, nil
}

func (r *fakeLogRepo) ByBatch(ctx context.Context, batchID string) ([]entities.RawLog, error) {
	return nil, nil
}

func (r *fakeLogRepo) CountIngestedSince(ctx context.Context, t time.Time) (int, error) {
	return len(r.logs), nil
}

func (r *fakeLogRepo) CountFlaggedSince(ctx context.Context, t time.Time) (int, error) {
	count := 0
	for _, l := range r.logs {
		if l.Flagged {
			count++
		}
	}
	return count, nil
}

func (r *fakeLogRepo) CountAnalyzedSince(ctx context.Context, t time.Time) (int, error) {
	return 0, nil
}

type fakeMockLogGenerator struct {
	lastScenario string
	lastCount    int
	lastIPs      []string
}

func (g *fakeMockLogGenerator) Generate(scenario string, count int, attackerIPs []string) []entities.RawLog {
	g.lastScenario = scenario
	g.lastCount = count
	g.lastIPs = attackerIPs

	logs := make([]entities.RawLog, count)
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		action := enums.ActionLoginSuccess
		if scenario == "brute_force" && i%3 == 0 {
			action = enums.ActionLoginFailed
		}
		logs[i] = entities.RawLog{
			LogID:     fmt.Sprintf("mock-%s-%d", scenario, i),
			Timestamp: now.Add(-time.Duration(i) * time.Minute),
			UserID:    fmt.Sprintf("user-%d", i%10),
			IPAddress: "192.168.1.1",
			Country:   "USA",
			Action:    action,
			Flagged:   action.RequiresReview(),
		}
	}
	return logs
}

type fakeAuditRepo struct {
	entries []entities.AuditEntry
}

func (a *fakeAuditRepo) Append(ctx context.Context, e *entities.AuditEntry) error {
	e.ID = int64(len(a.entries) + 1)
	a.entries = append(a.entries, *e)
	return nil
}

func (a *fakeAuditRepo) List(ctx context.Context, q interfaces.AuditQuery) ([]entities.AuditEntry, error) {
	return a.entries, nil
}

func (a *fakeAuditRepo) Ascending(ctx context.Context, afterID int64, limit int) ([]entities.AuditEntry, error) {
	return a.entries, nil
}

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	}
	return c.now
}

type fakeTxManager struct{}

func (tx *fakeTxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func validScenarios(s string) bool {
	switch s {
	case "brute_force", "impossible_travel", "privilege_escalation", "benign", "mixed":
		return true
	}
	return false
}

// ----------------------------------------------------------------- Tests

func TestIngest_Success(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
		{
			LogID:     "log-2",
			Timestamp: "2026-10-16T10:01:00Z",
			UserID:    "user2",
			IPAddress: "10.0.0.50",
			Country:   "UK",
			Action:    "Login Failed",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if result.Received != 2 {
		t.Errorf("Expected 2 received, got %d", result.Received)
	}
	if result.Inserted != 2 {
		t.Errorf("Expected 2 inserted, got %d", result.Inserted)
	}
	if result.Flagged != 1 {
		t.Errorf("Expected 1 flagged (Login Failed), got %d", result.Flagged)
	}
	if len(result.Rejected) != 0 {
		t.Errorf("Expected 0 rejected, got %d", len(result.Rejected))
	}

	// Verify flagged is derived server-side
	if !logs.logs[1].Flagged {
		t.Error("Login Failed should be flagged")
	}
	if logs.logs[0].Flagged {
		t.Error("Login Success should not be flagged")
	}
}

func TestIngest_RejectsInvalidRowsIndividually(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
		{
			LogID:     "log-2",
			Timestamp: "invalid-timestamp",
			UserID:    "user2",
			IPAddress: "192.168.1.101",
			Country:   "UK",
			Action:    "Login Success",
		},
		{
			LogID:     "log-3",
			Timestamp: "2026-10-16T10:02:00Z",
			UserID:    "user3",
			IPAddress: "not-an-ip",
			Country:   "USA",
			Action:    "Login Success",
		},
		{
			LogID:     "log-4",
			Timestamp: "2026-10-16T10:03:00Z",
			UserID:    "user4",
			IPAddress: "192.168.1.102",
			Country:   "USA",
			Action:    "Login Success",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if result.Received != 4 {
		t.Errorf("Expected 4 received, got %d", result.Received)
	}
	if result.Inserted != 2 {
		t.Errorf("Expected 2 inserted (valid ones), got %d", result.Inserted)
	}
	if len(result.Rejected) != 2 {
		t.Fatalf("Expected 2 rejected, got %d", len(result.Rejected))
	}

	// Verify rejection details
	if result.Rejected[0].Index != 1 {
		t.Errorf("Expected first rejection at index 1, got %d", result.Rejected[0].Index)
	}
	if result.Rejected[1].Index != 2 {
		t.Errorf("Expected second rejection at index 2, got %d", result.Rejected[1].Index)
	}
}

func TestIngest_DerivesFlaggerServerSide(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Privilege Escalation",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if result.Flagged != 1 {
		t.Errorf("Expected Privilege Escalation to be flagged, got %d flagged", result.Flagged)
	}
	if !logs.logs[0].Flagged {
		t.Error("Privilege Escalation should be flagged server-side")
	}
}

func TestIngest_RejectsDuplicateLogIDInRequest(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "duplicate-id",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
		{
			LogID:     "duplicate-id",
			Timestamp: "2026-10-16T10:01:00Z",
			UserID:    "user2",
			IPAddress: "192.168.1.101",
			Country:   "UK",
			Action:    "Login Success",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if result.Inserted != 1 {
		t.Errorf("Expected 1 inserted, got %d", result.Inserted)
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("Expected 1 rejected for duplicate, got %d", len(result.Rejected))
	}
	if result.Rejected[0].Index != 1 {
		t.Errorf("Expected rejection at index 1, got %d", result.Rejected[0].Index)
	}
}

func TestIngest_RejectsBatchOverMaxSize(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	// Create 1001 logs (over MaxBatch of 1000)
	req := make([]dtos.IngestLog, 1001)
	for i := range req {
		req[i] = dtos.IngestLog{
			LogID:     fmt.Sprintf("log-%d", i),
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		}
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for batch over max size, got %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for oversized batch")
	}
}

func TestIngest_RejectsTimestampTooFarInFuture(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T13:00:00Z", // 1 hour in the future, exceeds 5 min skew
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("Expected 1 rejected for future timestamp, got %d", len(result.Rejected))
	}
	if result.Inserted != 0 {
		t.Errorf("Expected 0 inserted, got %d", result.Inserted)
	}
}

func TestIngest_RejectsTimestampTooFarInPast(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-07-01T10:00:00Z", // More than 90 days ago
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("Expected 1 rejected for old timestamp, got %d", len(result.Rejected))
	}
	if result.Inserted != 0 {
		t.Errorf("Expected 0 inserted, got %d", result.Inserted)
	}
}

func TestIngest_RejectsInvalidAction(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Invalid Action",
		},
	}

	result, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if len(result.Rejected) != 1 {
		t.Fatalf("Expected 1 rejected for invalid action, got %d", len(result.Rejected))
	}
}

func TestGenerateMock_Success(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.MockLogsRequest{
		Scenario: "brute_force",
		Count:    50,
	}

	result, err := svc.GenerateMock(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("GenerateMock failed: %v", err)
	}
	if result.Received != 50 {
		t.Errorf("Expected 50 received, got %d", result.Received)
	}
	if result.Inserted != 50 {
		t.Errorf("Expected 50 inserted, got %d", result.Inserted)
	}
	if gen.lastScenario != "brute_force" {
		t.Errorf("Expected scenario brute_force, got %s", gen.lastScenario)
	}
	if gen.lastCount != 50 {
		t.Errorf("Expected count 50, got %d", gen.lastCount)
	}
}

func TestGenerateMock_ValidatesScenario(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.MockLogsRequest{
		Scenario: "invalid_scenario",
		Count:    50,
	}

	result, err := svc.GenerateMock(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for invalid scenario, got %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for invalid scenario")
	}
}

func TestGenerateMock_ValidatesCountBounds(t *testing.T) {
	tests := []struct {
		name        string
		count       int
		shouldError bool
	}{
		{"zero count defaults to 100", 0, false},
		{"negative count defaults to 100", -1, false},
		{"valid count", 100, false},
		{"max count", 500, false},
		{"over max count", 501, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &fakeLogRepo{}
			gen := &fakeMockLogGenerator{}
			auditRepo := &fakeAuditRepo{}
			clock := &fakeClock{}
			auditSvc := audit.NewService(auditRepo, clock)
			tx := &fakeTxManager{}
			svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

			admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
			req := dtos.MockLogsRequest{
				Scenario: "benign",
				Count:    tt.count,
			}

			result, err := svc.GenerateMock(context.Background(), admin, req)

			if tt.shouldError {
				if !errors.Is(err, interfaces.ErrValidation) {
					t.Errorf("Expected ErrValidation, got %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected success, got %v", err)
				}
				expectedCount := tt.count
				if expectedCount <= 0 {
					expectedCount = 100
				}
				if result.Received != expectedCount {
					t.Errorf("Expected %d logs, got %d", expectedCount, result.Received)
				}
			}
		})
	}
}

func TestGenerateMock_ValidatesAttackerIPs(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}

	t.Run("valid IPs", func(t *testing.T) {
		req := dtos.MockLogsRequest{
			Scenario:    "brute_force",
			Count:       10,
			AttackerIPs: []string{"192.168.1.100", "10.0.0.50"},
		}

		result, err := svc.GenerateMock(context.Background(), admin, req)

		if err != nil {
			t.Fatalf("Expected success with valid IPs, got %v", err)
		}
		if len(gen.lastIPs) != 2 {
			t.Errorf("Expected 2 IPs passed to generator, got %d", len(gen.lastIPs))
		}
		if result == nil {
			t.Fatal("Expected result")
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		req := dtos.MockLogsRequest{
			Scenario:    "brute_force",
			Count:       10,
			AttackerIPs: []string{"not-an-ip"},
		}

		result, err := svc.GenerateMock(context.Background(), admin, req)

		if !errors.Is(err, interfaces.ErrValidation) {
			t.Errorf("Expected ErrValidation for invalid IP, got %v", err)
		}
		if result != nil {
			t.Error("Expected nil result for invalid IP")
		}
	})

	t.Run("too many IPs", func(t *testing.T) {
		req := dtos.MockLogsRequest{
			Scenario: "brute_force",
			Count:    10,
			AttackerIPs: []string{
				"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5",
				"6.6.6.6", "7.7.7.7", "8.8.8.8", "9.9.9.9", "10.10.10.10",
				"11.11.11.11", // 11th IP
			},
		}

		result, err := svc.GenerateMock(context.Background(), admin, req)

		if !errors.Is(err, interfaces.ErrValidation) {
			t.Errorf("Expected ErrValidation for too many IPs, got %v", err)
		}
		if result != nil {
			t.Error("Expected nil result for too many IPs")
		}
	})
}

func TestIngest_EmptyBatch(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{}

	result, err := svc.Ingest(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for empty batch, got %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for empty batch")
	}
}

func TestIngest_AuditEntryCreated(t *testing.T) {
	logs := &fakeLogRepo{}
	gen := &fakeMockLogGenerator{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := ingest.NewService(logs, gen, validScenarios, auditSvc, tx, clock)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := []dtos.IngestLog{
		{
			LogID:     "log-1",
			Timestamp: "2026-10-16T10:00:00Z",
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Country:   "USA",
			Action:    "Login Success",
		},
	}

	_, err := svc.Ingest(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// Verify audit entry
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditLogsIngested {
		t.Errorf("Expected action type LOGS_INGESTED, got %v", entry.ActionType)
	}
	if entry.UserID != admin.UserID {
		t.Errorf("Expected user ID %s, got %s", admin.UserID, entry.UserID)
	}
}
