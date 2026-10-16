package audit

import (
	"context"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestAuditService_RecordAndVerify_ValidChain(t *testing.T) {
	// Build a chain of 5 entries, verify reports Valid=true
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAdmin}

	events := []Event{
		{Actor: p, Action: enums.AuditUserLogin, EntityType: "user", EntityID: "user1", Details: "User logged in"},
		{Actor: p, Action: enums.AuditLogsIngested, EntityType: "logs", EntityID: "", Details: "Ingested 10 logs"},
		{Actor: p, Action: enums.AuditIncidentCreated, EntityType: "incident", EntityID: "inc1", Details: "Incident created"},
		{Actor: p, Action: enums.AuditIncidentAcknowledged, EntityType: "incident", EntityID: "inc1", Details: "Incident acknowledged"},
		{Actor: p, Action: enums.AuditIncidentResolved, EntityType: "incident", EntityID: "inc1", Details: "Incident resolved"},
	}

	for _, e := range events {
		if err := svc.Record(context.Background(), e); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
		clock.T = clock.T.Add(1 * time.Minute) // advance time for each entry
	}

	// Verify chain
	result, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected Valid=true, got false (reason: %s, bad ID: %d)", result.Reason, result.FirstBadID)
	}
	if result.Checked != 5 {
		t.Errorf("expected 5 entries checked, got %d", result.Checked)
	}
	if result.LatestHash == "" {
		t.Error("expected LatestHash to be set")
	}
}

func TestAuditService_RecordAndVerify_CorruptedHash_DetectedWithFirstBadID(t *testing.T) {
	// Build a chain, corrupt one entry's hash, verify reports Valid=false with FirstBadID
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAdmin}

	events := []Event{
		{Actor: p, Action: enums.AuditUserLogin, EntityType: "user", EntityID: "user1", Details: "Entry 1"},
		{Actor: p, Action: enums.AuditLogsIngested, EntityType: "logs", EntityID: "", Details: "Entry 2"},
		{Actor: p, Action: enums.AuditIncidentCreated, EntityType: "incident", EntityID: "inc1", Details: "Entry 3"},
		{Actor: p, Action: enums.AuditIncidentAcknowledged, EntityType: "incident", EntityID: "inc1", Details: "Entry 4"},
	}

	for _, e := range events {
		if err := svc.Record(context.Background(), e); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
		clock.T = clock.T.Add(1 * time.Minute)
	}

	// Corrupt entry ID 3
	if err := repo.CorruptHash(3); err != nil {
		t.Fatalf("CorruptHash failed: %v", err)
	}

	// Verify chain
	result, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.Valid {
		t.Error("expected Valid=false after corruption")
	}
	if result.FirstBadID != 3 {
		t.Errorf("expected FirstBadID=3, got %d", result.FirstBadID)
	}
	if result.Reason == "" {
		t.Error("expected Reason to be set")
	}
	t.Logf("Corruption detected: %s at ID %d", result.Reason, result.FirstBadID)
}

func TestAuditService_Record_SystemActor(t *testing.T) {
	// SYSTEM actor is recorded correctly
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	err := svc.Record(context.Background(), Event{
		Actor:      entities.SystemPrincipal,
		Action:     enums.AuditScheduledScan,
		EntityType: "scan_run",
		EntityID:   "run1",
		Details:    "Scheduled scan completed",
	})
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	entries, _ := repo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].UserID != enums.SystemActor {
		t.Errorf("expected user_id=%s, got %s", enums.SystemActor, entries[0].UserID)
	}
}

func TestAuditService_Record_MetadataIncludesActorInfo(t *testing.T) {
	// Non-system actor's email and role are added to metadata
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAdmin}

	err := svc.Record(context.Background(), Event{
		Actor:      p,
		Action:     enums.AuditUserLogin,
		EntityType: "user",
		EntityID:   "user1",
		Details:    "Login",
		Metadata:   map[string]string{"custom": "value"},
	})
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	entries, _ := repo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	meta := entries[0].Metadata
	if meta["actor_email"] != "user@test.com" {
		t.Errorf("expected actor_email=user@test.com, got %s", meta["actor_email"])
	}
	if meta["actor_role"] != "admin" {
		t.Errorf("expected actor_role=admin, got %s", meta["actor_role"])
	}
	if meta["custom"] != "value" {
		t.Errorf("expected custom=value, got %s", meta["custom"])
	}
}

func TestAuditService_Record_TruncatesLongDetails(t *testing.T) {
	// Details longer than maxDetails are truncated
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: enums.RoleAdmin}

	longDetails := make([]rune, maxDetails+100)
	for i := range longDetails {
		longDetails[i] = 'a'
	}

	err := svc.Record(context.Background(), Event{
		Actor:      p,
		Action:     enums.AuditUserLogin,
		EntityType: "user",
		EntityID:   "user1",
		Details:    string(longDetails),
	})
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	entries, _ := repo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	detailsLen := len([]rune(entries[0].Details))
	if detailsLen != maxDetails {
		t.Errorf("expected details length=%d, got %d", maxDetails, detailsLen)
	}
}

func TestAuditService_List_Filters(t *testing.T) {
	// List applies filters correctly
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	p1 := entities.Principal{UserID: "user1", Email: "user1@test.com", Role: enums.RoleAdmin}
	p2 := entities.Principal{UserID: "user2", Email: "user2@test.com", Role: enums.RoleAnalyst}

	_ = svc.Record(context.Background(), Event{Actor: p1, Action: enums.AuditUserLogin, EntityType: "user", EntityID: "user1", Details: "Login 1"})
	clock.T = clock.T.Add(1 * time.Minute)
	_ = svc.Record(context.Background(), Event{Actor: p2, Action: enums.AuditUserLogin, EntityType: "user", EntityID: "user2", Details: "Login 2"})
	clock.T = clock.T.Add(1 * time.Minute)
	_ = svc.Record(context.Background(), Event{Actor: p1, Action: enums.AuditLogsIngested, EntityType: "logs", EntityID: "", Details: "Ingest"})

	// Filter by user
	entries, err := svc.List(context.Background(), interfaces.AuditQuery{UserID: "user1"})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for user1, got %d", len(entries))
	}

	// Filter by action
	entries, err = svc.List(context.Background(), interfaces.AuditQuery{ActionType: string(enums.AuditUserLogin)})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for USER_LOGIN, got %d", len(entries))
	}

	// Filter by limit
	entries, err = svc.List(context.Background(), interfaces.AuditQuery{Limit: 1})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry with limit=1, got %d", len(entries))
	}
}

func TestAuditService_Verify_EmptyChain(t *testing.T) {
	// Verify on empty chain returns Valid=true
	repo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	svc := NewService(repo, clock)

	result, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Error("expected Valid=true for empty chain")
	}
	if result.Checked != 0 {
		t.Errorf("expected 0 checked, got %d", result.Checked)
	}
}
