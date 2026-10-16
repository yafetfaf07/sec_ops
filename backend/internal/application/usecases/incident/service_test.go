package incident

import (
	"context"
	"strings"
	"testing"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// -------------------------------------------------------------------- State machine tests

func TestAcknowledge_OpenToAcknowledged(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	// Create an open incident
	inc := &entities.Incident{
		ID:     "inc-1",
		Status: enums.StatusOpen,
	}
	repo.SetIncident("inc-1", inc)

	principal := entities.Principal{
		UserID: "user-123",
		Email:  "analyst@example.com",
		Name:   "Test Analyst",
		Role:   enums.RoleAnalyst,
	}

	result, err := svc.Acknowledge(context.Background(), principal, "inc-1")
	if err != nil {
		t.Fatalf("Acknowledge failed: %v", err)
	}

	if result.Status != enums.StatusAcknowledged {
		t.Errorf("result.Status = %s, want Acknowledged", result.Status)
	}

	// Verify the incident was updated
	updated, _ := repo.Get(context.Background(), "inc-1")
	if updated.Status != enums.StatusAcknowledged {
		t.Errorf("updated.Status = %s, want Acknowledged", updated.Status)
	}
	if updated.AcknowledgedAt == nil {
		t.Error("AcknowledgedAt is nil, want timestamp")
	}
	if updated.AcknowledgedBy != "user-123" {
		t.Errorf("AcknowledgedBy = %s, want user-123", updated.AcknowledgedBy)
	}

	// Verify audit entry
	entry := auditRepo.FindAction(enums.AuditIncidentAcknowledged)
	if entry == nil {
		t.Fatal("INCIDENT_ACKNOWLEDGED audit entry not found")
	}
	if entry.EntityID != "inc-1" {
		t.Errorf("audit EntityID = %s, want inc-1", entry.EntityID)
	}
}

func TestResolve_OpenToResolved(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	// Create an open incident
	inc := &entities.Incident{
		ID:     "inc-2",
		Status: enums.StatusOpen,
	}
	repo.SetIncident("inc-2", inc)

	principal := entities.Principal{
		UserID: "user-456",
		Email:  "admin@example.com",
		Name:   "Test Admin",
		Role:   enums.RoleAdmin,
	}

	req := dtos.ResolveRequest{Comment: "False positive, verified benign."}

	result, err := svc.Resolve(context.Background(), principal, "inc-2", req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if result.Status != enums.StatusResolved {
		t.Errorf("result.Status = %s, want Resolved", result.Status)
	}

	// Verify the incident was updated
	updated, _ := repo.Get(context.Background(), "inc-2")
	if updated.Status != enums.StatusResolved {
		t.Errorf("updated.Status = %s, want Resolved", updated.Status)
	}
	if updated.ResolvedAt == nil {
		t.Error("ResolvedAt is nil, want timestamp")
	}
	if updated.ResolvedBy != "user-456" {
		t.Errorf("ResolvedBy = %s, want user-456", updated.ResolvedBy)
	}

	// Verify comment was added
	if len(updated.Comments) != 1 {
		t.Fatalf("len(comments) = %d, want 1", len(updated.Comments))
	}
	comment := updated.Comments[0]
	if comment.Body != "False positive, verified benign." {
		t.Errorf("comment.Body = %q, want %q", comment.Body, "False positive, verified benign.")
	}
	if comment.Author != "admin@example.com" {
		t.Errorf("comment.Author = %s, want admin@example.com", comment.Author)
	}
	if comment.Role != string(enums.RoleAdmin) {
		t.Errorf("comment.Role = %s, want admin", comment.Role)
	}

	// Verify audit entry
	entry := auditRepo.FindAction(enums.AuditIncidentResolved)
	if entry == nil {
		t.Fatal("INCIDENT_RESOLVED audit entry not found")
	}
}

func TestResolve_AcknowledgedToResolved(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	// Create an acknowledged incident
	ackTime := clock.Now().Add(-1 * time.Hour)
	inc := &entities.Incident{
		ID:             "inc-3",
		Status:         enums.StatusAcknowledged,
		AcknowledgedAt: &ackTime,
		AcknowledgedBy: "user-previous",
	}
	repo.SetIncident("inc-3", inc)

	principal := entities.Principal{
		UserID: "user-789",
		Email:  "analyst@example.com",
		Role:   enums.RoleAnalyst,
	}

	req := dtos.ResolveRequest{Comment: "Issue resolved after investigation."}

	result, err := svc.Resolve(context.Background(), principal, "inc-3", req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if result.Status != enums.StatusResolved {
		t.Errorf("result.Status = %s, want Resolved", result.Status)
	}

	// Verify the incident was updated
	updated, _ := repo.Get(context.Background(), "inc-3")
	if updated.Status != enums.StatusResolved {
		t.Errorf("updated.Status = %s, want Resolved", updated.Status)
	}

	// AcknowledgedAt/By should remain
	if updated.AcknowledgedAt == nil || !updated.AcknowledgedAt.Equal(ackTime) {
		t.Error("AcknowledgedAt was modified, want original timestamp")
	}
	if updated.AcknowledgedBy != "user-previous" {
		t.Error("AcknowledgedBy was modified")
	}

	// ResolvedAt/By should be set
	if updated.ResolvedAt == nil {
		t.Error("ResolvedAt is nil, want timestamp")
	}
	if updated.ResolvedBy != "user-789" {
		t.Errorf("ResolvedBy = %s, want user-789", updated.ResolvedBy)
	}
}

func TestAcknowledge_AcknowledgedToOpenRejected(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	// Create an acknowledged incident
	ackTime := clock.Now().Add(-1 * time.Hour)
	inc := &entities.Incident{
		ID:             "inc-4",
		Status:         enums.StatusAcknowledged,
		AcknowledgedAt: &ackTime,
		AcknowledgedBy: "user-first",
	}
	repo.SetIncident("inc-4", inc)

	principal := entities.Principal{
		UserID: "user-second",
		Email:  "analyst@example.com",
		Role:   enums.RoleAnalyst,
	}

	// Trying to acknowledge again should fail (no Acknowledged->Acknowledged or Acknowledged->Open)
	_, err := svc.Acknowledge(context.Background(), principal, "inc-4")
	if err == nil {
		t.Fatal("Expected error for Acknowledged->Acknowledged, got nil")
	}

	if !containsErr(err, interfaces.ErrInvalidTransition) {
		t.Errorf("Expected ErrInvalidTransition, got: %v", err)
	}

	// Verify incident was NOT modified
	unchanged, _ := repo.Get(context.Background(), "inc-4")
	if unchanged.Status != enums.StatusAcknowledged {
		t.Errorf("Status changed to %s, should remain Acknowledged", unchanged.Status)
	}
	if unchanged.AcknowledgedBy != "user-first" {
		t.Error("AcknowledgedBy was modified")
	}
}

func TestResolve_ResolvedToAnythingRejected(t *testing.T) {
	tests := []struct {
		name       string
		transition func(svc *Service, ctx context.Context, p entities.Principal, id string) error
	}{
		{
			name: "Resolved->Acknowledged",
			transition: func(svc *Service, ctx context.Context, p entities.Principal, id string) error {
				_, err := svc.Acknowledge(ctx, p, id)
				return err
			},
		},
		{
			name: "Resolved->Resolved",
			transition: func(svc *Service, ctx context.Context, p entities.Principal, id string) error {
				_, err := svc.Resolve(ctx, p, id, dtos.ResolveRequest{Comment: "Trying again"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			repo := testfakes.NewIncidentRepository()
			auditRepo := testfakes.NewAuditRepository()
			auditSvc := audit.NewService(auditRepo, clock)
			tx := &testfakes.TxManager{}

			svc := NewService(repo, auditSvc, tx, clock)

			// Create a resolved incident
			resolvedTime := clock.Now().Add(-2 * time.Hour)
			inc := &entities.Incident{
				ID:         "inc-resolved",
				Status:     enums.StatusResolved,
				ResolvedAt: &resolvedTime,
				ResolvedBy: "user-original",
			}
			repo.SetIncident("inc-resolved", inc)

			principal := entities.Principal{
				UserID: "user-new",
				Email:  "analyst@example.com",
				Role:   enums.RoleAnalyst,
			}

			err := tt.transition(svc, context.Background(), principal, "inc-resolved")
			if err == nil {
				t.Fatalf("Expected error for %s, got nil", tt.name)
			}

			if !containsErr(err, interfaces.ErrInvalidTransition) {
				t.Errorf("Expected ErrInvalidTransition, got: %v", err)
			}

			// Verify incident remains resolved
			unchanged, _ := repo.Get(context.Background(), "inc-resolved")
			if unchanged.Status != enums.StatusResolved {
				t.Errorf("Status changed to %s, should remain Resolved", unchanged.Status)
			}
		})
	}
}

// -------------------------------------------------------------------- Resolve validation tests

func TestResolve_RequiresNonEmptyComment(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-5", Status: enums.StatusOpen}
	repo.SetIncident("inc-5", inc)

	principal := entities.Principal{
		UserID: "user-123",
		Email:  "analyst@example.com",
		Role:   enums.RoleAnalyst,
	}

	tests := []struct {
		name    string
		comment string
	}{
		{"empty", ""},
		{"whitespace_only", "   "},
		{"newlines_only", "\n\n\n"},
		{"tabs_only", "\t\t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := dtos.ResolveRequest{Comment: tt.comment}

			_, err := svc.Resolve(context.Background(), principal, "inc-5", req)
			if err == nil {
				t.Fatal("Expected error for empty comment, got nil")
			}

			if !containsErr(err, interfaces.ErrValidation) {
				t.Errorf("Expected ErrValidation, got: %v", err)
			}

			if !containsString(err.Error(), "comment is required") {
				t.Errorf("Error message should mention comment is required, got: %v", err)
			}
		})
	}
}

func TestResolve_CommentMaxLength2000Chars(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-6", Status: enums.StatusOpen}
	repo.SetIncident("inc-6", inc)

	principal := entities.Principal{
		UserID: "user-123",
		Email:  "analyst@example.com",
		Role:   enums.RoleAnalyst,
	}

	// Exactly 2000 chars should work
	comment2000 := strings.Repeat("a", 2000)
	req := dtos.ResolveRequest{Comment: comment2000}
	_, err := svc.Resolve(context.Background(), principal, "inc-6", req)
	if err != nil {
		t.Fatalf("Resolve with 2000 char comment failed: %v", err)
	}

	// Reset incident to Open for next test
	inc.Status = enums.StatusOpen
	repo.SetIncident("inc-6", inc)

	// 2001 chars should fail
	comment2001 := strings.Repeat("b", 2001)
	req = dtos.ResolveRequest{Comment: comment2001}
	_, err = svc.Resolve(context.Background(), principal, "inc-6", req)
	if err == nil {
		t.Fatal("Expected error for 2001 char comment, got nil")
	}

	if !containsErr(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation, got: %v", err)
	}

	if !containsString(err.Error(), "at most 2000 characters") {
		t.Errorf("Error should mention 2000 character limit, got: %v", err)
	}
}

// -------------------------------------------------------------------- Role-based authorization tests

func TestAcknowledge_ViewerRoleForbidden(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-7", Status: enums.StatusOpen}
	repo.SetIncident("inc-7", inc)

	viewer := entities.Principal{
		UserID: "viewer-123",
		Email:  "viewer@example.com",
		Role:   enums.RoleViewer,
	}

	_, err := svc.Acknowledge(context.Background(), viewer, "inc-7")
	if err == nil {
		t.Fatal("Expected error for viewer acknowledging, got nil")
	}

	if !containsErr(err, interfaces.ErrForbidden) {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}

	// Verify incident was NOT modified
	unchanged, _ := repo.Get(context.Background(), "inc-7")
	if unchanged.Status != enums.StatusOpen {
		t.Errorf("Status changed to %s, should remain Open", unchanged.Status)
	}
	if unchanged.AcknowledgedAt != nil {
		t.Error("AcknowledgedAt should be nil")
	}
}

func TestResolve_ViewerRoleForbidden(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-8", Status: enums.StatusOpen}
	repo.SetIncident("inc-8", inc)

	viewer := entities.Principal{
		UserID: "viewer-456",
		Email:  "viewer@example.com",
		Role:   enums.RoleViewer,
	}

	req := dtos.ResolveRequest{Comment: "Trying to resolve"}

	_, err := svc.Resolve(context.Background(), viewer, "inc-8", req)
	if err == nil {
		t.Fatal("Expected error for viewer resolving, got nil")
	}

	if !containsErr(err, interfaces.ErrForbidden) {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}

	// Verify incident was NOT modified
	unchanged, _ := repo.Get(context.Background(), "inc-8")
	if unchanged.Status != enums.StatusOpen {
		t.Errorf("Status changed to %s, should remain Open", unchanged.Status)
	}
	if unchanged.ResolvedAt != nil {
		t.Error("ResolvedAt should be nil")
	}
}

func TestAcknowledge_AnalystRoleAllowed(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-9", Status: enums.StatusOpen}
	repo.SetIncident("inc-9", inc)

	analyst := entities.Principal{
		UserID: "analyst-123",
		Email:  "analyst@example.com",
		Role:   enums.RoleAnalyst,
	}

	_, err := svc.Acknowledge(context.Background(), analyst, "inc-9")
	if err != nil {
		t.Fatalf("Acknowledge by analyst failed: %v", err)
	}

	updated, _ := repo.Get(context.Background(), "inc-9")
	if updated.Status != enums.StatusAcknowledged {
		t.Errorf("Status = %s, want Acknowledged", updated.Status)
	}
}

func TestResolve_AdminRoleAllowed(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	repo := testfakes.NewIncidentRepository()
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	svc := NewService(repo, auditSvc, tx, clock)

	inc := &entities.Incident{ID: "inc-10", Status: enums.StatusOpen}
	repo.SetIncident("inc-10", inc)

	admin := entities.Principal{
		UserID: "admin-789",
		Email:  "admin@example.com",
		Role:   enums.RoleAdmin,
	}

	req := dtos.ResolveRequest{Comment: "Admin resolving incident"}

	_, err := svc.Resolve(context.Background(), admin, "inc-10", req)
	if err != nil {
		t.Fatalf("Resolve by admin failed: %v", err)
	}

	updated, _ := repo.Get(context.Background(), "inc-10")
	if updated.Status != enums.StatusResolved {
		t.Errorf("Status = %s, want Resolved", updated.Status)
	}
}

// -------------------------------------------------------------------- Helpers

func containsErr(err error, target error) bool {
	if err == nil {
		return false
	}
	// Simple string contains check since we can't use errors.Is in this isolated test
	return containsString(err.Error(), target.Error())
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
