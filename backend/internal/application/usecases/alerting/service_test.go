package alerting

import (
	"context"
	"net/http"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestDispatch_ZeroNotifiersRecordsAlertSuppressed(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	// Service with zero notifiers
	svc := NewService([]interfaces.AlertNotifier{}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-123",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Test incident",
	}

	sent, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if sent != 0 {
		t.Errorf("sent = %d, want 0 (no notifiers)", sent)
	}

	// Check that ALERT_SUPPRESSED was recorded in audit
	entry := auditRepo.FindAction(enums.AuditAlertSuppressed)
	if entry == nil {
		t.Fatal("ALERT_SUPPRESSED audit entry not found")
	}

	if entry.EntityType != "incident" {
		t.Errorf("audit EntityType = %s, want incident", entry.EntityType)
	}
	if entry.EntityID != "inc-123" {
		t.Errorf("audit EntityID = %s, want inc-123", entry.EntityID)
	}
	if entry.UserID != enums.SystemActor {
		t.Errorf("audit UserID = %s, want SYSTEM", entry.UserID)
	}

	// No deliveries should be recorded
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 0 {
		t.Errorf("len(deliveries) = %d, want 0", len(allDeliveries))
	}
}

func TestDispatch_OneSuccessNotifier(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	notifier := testfakes.NewSuccessNotifier("slack")
	svc := NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID:        "inc-456",
		Timestamp:         clock.Now(),
		RiskScore:         enums.RiskCritical,
		Summary:           "Critical incident",
		RecommendedAction: "Block IP",
		TopIP:             "1.2.3.4",
		Country:           "CN",
		Link:              "https://app.example.com/incidents/inc-456",
	}

	sent, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}

	// Verify notifier was called with correct message
	if len(notifier.Calls) != 1 {
		t.Fatalf("notifier call count = %d, want 1", len(notifier.Calls))
	}
	if notifier.Calls[0].IncidentID != "inc-456" {
		t.Errorf("notifier received IncidentID = %s, want inc-456", notifier.Calls[0].IncidentID)
	}

	// Check delivery record
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 1 {
		t.Fatalf("len(deliveries) = %d, want 1", len(allDeliveries))
	}

	delivery := allDeliveries[0]
	if delivery.IncidentID != "inc-456" {
		t.Errorf("delivery.IncidentID = %s, want inc-456", delivery.IncidentID)
	}
	if delivery.Channel != "slack" {
		t.Errorf("delivery.Channel = %s, want slack", delivery.Channel)
	}
	if !delivery.Success {
		t.Error("delivery.Success = false, want true")
	}
	if delivery.HTTPStatus != http.StatusOK {
		t.Errorf("delivery.HTTPStatus = %d, want 200", delivery.HTTPStatus)
	}
	if delivery.Error != "" {
		t.Errorf("delivery.Error = %q, want empty", delivery.Error)
	}

	// Check audit record
	entry := auditRepo.FindAction(enums.AuditAlertSent)
	if entry == nil {
		t.Fatal("ALERT_SENT audit entry not found")
	}
	if entry.EntityID != "inc-456" {
		t.Errorf("audit EntityID = %s, want inc-456", entry.EntityID)
	}
}

func TestDispatch_OneFailingNotifier(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	notifier := testfakes.NewFailingNotifier("discord", http.StatusBadGateway)
	svc := NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-789",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Test failure",
	}

	sent, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if sent != 0 {
		t.Errorf("sent = %d, want 0 (notifier failed)", sent)
	}

	// Check delivery record
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 1 {
		t.Fatalf("len(deliveries) = %d, want 1", len(allDeliveries))
	}

	delivery := allDeliveries[0]
	if delivery.Success {
		t.Error("delivery.Success = true, want false")
	}
	if delivery.HTTPStatus != http.StatusBadGateway {
		t.Errorf("delivery.HTTPStatus = %d, want 502", delivery.HTTPStatus)
	}

	// CRITICAL: Error text must be hardcoded, not from the webhook error
	// This prevents leaking webhook URLs or other sensitive details
	if delivery.Error != "delivery failed" {
		t.Errorf("delivery.Error = %q, want exactly 'delivery failed'", delivery.Error)
	}

	// Verify error does NOT contain anything identifying like URL fragments
	if containsAny(delivery.Error, []string{"http", "webhook", "discord.com", "slack.com"}) {
		t.Errorf("delivery.Error contains identifying information: %q", delivery.Error)
	}

	// Check audit record
	entry := auditRepo.FindAction(enums.AuditAlertFailed)
	if entry == nil {
		t.Fatal("ALERT_FAILED audit entry not found")
	}
	if entry.EntityID != "inc-789" {
		t.Errorf("audit EntityID = %s, want inc-789", entry.EntityID)
	}
	if entry.Metadata["channel"] != "discord" {
		t.Errorf("audit metadata channel = %s, want discord", entry.Metadata["channel"])
	}
}

func TestDispatch_OneFailingOneSucceedingNotifier(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	failing := testfakes.NewFailingNotifier("slack", http.StatusServiceUnavailable)
	succeeding := testfakes.NewSuccessNotifier("discord")

	svc := NewService([]interfaces.AlertNotifier{failing, succeeding}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-mixed",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Mixed result test",
	}

	sent, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	// One succeeded
	if sent != 1 {
		t.Errorf("sent = %d, want 1 (one succeeded)", sent)
	}

	// Should have two delivery records
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 2 {
		t.Fatalf("len(deliveries) = %d, want 2", len(allDeliveries))
	}

	// Count successes and failures
	var successCount, failureCount int
	for _, d := range allDeliveries {
		if d.Success {
			successCount++
			if d.Channel != "discord" {
				t.Errorf("success delivery channel = %s, want discord", d.Channel)
			}
			if d.HTTPStatus != http.StatusOK {
				t.Errorf("success delivery status = %d, want 200", d.HTTPStatus)
			}
		} else {
			failureCount++
			if d.Channel != "slack" {
				t.Errorf("failed delivery channel = %s, want slack", d.Channel)
			}
			if d.HTTPStatus != http.StatusServiceUnavailable {
				t.Errorf("failed delivery status = %d, want 503", d.HTTPStatus)
			}
			if d.Error != "delivery failed" {
				t.Errorf("failed delivery error = %q, want 'delivery failed'", d.Error)
			}
		}
	}

	if successCount != 1 {
		t.Errorf("success count = %d, want 1", successCount)
	}
	if failureCount != 1 {
		t.Errorf("failure count = %d, want 1", failureCount)
	}

	// Check audit records
	allAudit := auditRepo.GetAll()
	var sentCount, failedCount int
	for _, e := range allAudit {
		if e.ActionType == enums.AuditAlertSent {
			sentCount++
		}
		if e.ActionType == enums.AuditAlertFailed {
			failedCount++
		}
	}

	if sentCount != 1 {
		t.Errorf("ALERT_SENT audit count = %d, want 1", sentCount)
	}
	if failedCount != 1 {
		t.Errorf("ALERT_FAILED audit count = %d, want 1", failedCount)
	}
}

func TestDispatch_MultipleSuccessNotifiers(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	slack := testfakes.NewSuccessNotifier("slack")
	discord := testfakes.NewSuccessNotifier("discord")

	svc := NewService([]interfaces.AlertNotifier{slack, discord}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-both",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskCritical,
		Summary:    "Both channels test",
	}

	sent, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if sent != 2 {
		t.Errorf("sent = %d, want 2", sent)
	}

	// Both notifiers should have been called
	if len(slack.Calls) != 1 {
		t.Errorf("slack call count = %d, want 1", len(slack.Calls))
	}
	if len(discord.Calls) != 1 {
		t.Errorf("discord call count = %d, want 1", len(discord.Calls))
	}

	// Should have two successful delivery records
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 2 {
		t.Fatalf("len(deliveries) = %d, want 2", len(allDeliveries))
	}

	for _, d := range allDeliveries {
		if !d.Success {
			t.Errorf("delivery for %s failed, want success", d.Channel)
		}
	}

	// Should have two ALERT_SENT audit records
	allAudit := auditRepo.GetAll()
	sentCount := 0
	for _, e := range allAudit {
		if e.ActionType == enums.AuditAlertSent {
			sentCount++
		}
	}
	if sentCount != 2 {
		t.Errorf("ALERT_SENT audit count = %d, want 2", sentCount)
	}
}

func TestDispatch_ErrorDoesNotContainWebhookURL(t *testing.T) {
	// This is a critical security test: ensure that delivery.Error never
	// contains anything that could identify the webhook URL
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	// Create a failing notifier with an error message that includes URL-like content
	notifier := &testfakes.ConfigurableAlertNotifier{
		ChannelName: "slack",
		Status:      http.StatusBadRequest,
		Err:         testErr("webhook delivery failed: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX returned 400"),
	}

	svc := NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-sec",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskHigh,
		Summary:    "Security test",
	}

	_, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	// Get the delivery record
	allDeliveries := deliveries.GetAll()
	if len(allDeliveries) != 1 {
		t.Fatalf("len(deliveries) = %d, want 1", len(allDeliveries))
	}

	delivery := allDeliveries[0]

	// The error MUST be the hardcoded string, not the actual error
	if delivery.Error != "delivery failed" {
		t.Errorf("delivery.Error = %q, want exactly 'delivery failed'", delivery.Error)
	}

	// Double-check: ensure NO URL fragments in the error field
	forbiddenStrings := []string{
		"http", "https", "://", "slack.com", "discord.com",
		"hooks", "webhook", "services", "T00000000", "B00000000",
	}

	for _, forbidden := range forbiddenStrings {
		if contains(delivery.Error, forbidden) {
			t.Errorf("delivery.Error contains forbidden string %q: %s", forbidden, delivery.Error)
		}
	}
}

func TestDispatch_CorrectAuditDetails(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	auditRepo := testfakes.NewAuditRepository()
	auditSvc := audit.NewService(auditRepo, clock)
	deliveries := &testfakes.FakeAlertDeliveryRepository{}

	notifier := testfakes.NewSuccessNotifier("slack")
	svc := NewService([]interfaces.AlertNotifier{notifier}, deliveries, auditSvc)

	msg := interfaces.AlertMessage{
		IncidentID: "inc-audit",
		Timestamp:  clock.Now(),
		RiskScore:  enums.RiskMedium,
		Summary:    "Audit test",
	}

	_, err := svc.Dispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	entry := auditRepo.FindAction(enums.AuditAlertSent)
	if entry == nil {
		t.Fatal("ALERT_SENT audit entry not found")
	}

	// Check details format
	expectedDetails := "slack alert sent for incident inc-audit."
	if entry.Details != expectedDetails {
		t.Errorf("audit Details = %q, want %q", entry.Details, expectedDetails)
	}

	// Check metadata
	if entry.Metadata["channel"] != "slack" {
		t.Errorf("audit metadata channel = %s, want slack", entry.Metadata["channel"])
	}

	// Check actor is SYSTEM
	if entry.UserID != enums.SystemActor {
		t.Errorf("audit UserID = %s, want SYSTEM", entry.UserID)
	}
}

// -------------------------------------------------------------------- Helpers

type testErr string

func (e testErr) Error() string { return string(e) }

func contains(s, substr string) bool {
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

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if contains(s, substr) {
			return true
		}
	}
	return false
}
