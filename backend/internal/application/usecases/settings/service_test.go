package settings

import (
	"context"
	"testing"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func TestSettingsService_Update_NonAdminForbidden(t *testing.T) {
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" || m == "gemini-1.5-flash" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	tests := []struct {
		name string
		role enums.Role
	}{
		{"analyst", enums.RoleAnalyst},
		{"viewer", enums.RoleViewer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := entities.Principal{UserID: "user1", Email: "user@test.com", Role: tt.role}
			enabled := true
			patch := dtos.SettingsPatch{Enabled: &enabled}

			_, err := svc.Update(context.Background(), p, patch)
			if err != interfaces.ErrForbidden {
				t.Errorf("expected ErrForbidden, got %v", err)
			}
		})
	}
}

func TestSettingsService_Update_CronHourValidation(t *testing.T) {
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	tests := []struct {
		hour      int
		wantError bool
	}{
		{-1, true},
		{0, false},
		{12, false},
		{23, false},
		{24, true},
		{100, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.hour)), func(t *testing.T) {
			patch := dtos.SettingsPatch{CronHourUTC: &tt.hour}
			_, err := svc.Update(context.Background(), p, patch)
			if tt.wantError && !isValidationError(err) {
				t.Errorf("expected validation error, got %v", err)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSettingsService_Update_InvalidGeminiModel(t *testing.T) {
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" || m == "gemini-1.5-flash" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	tests := []struct {
		model     string
		wantError bool
	}{
		{"gemini-2.5-flash-lite", false},
		{"gemini-1.5-flash", false},
		{"invalid-model", true},
		{"gpt-4", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			model := tt.model
			patch := dtos.SettingsPatch{GeminiModel: &model}
			_, err := svc.Update(context.Background(), p, patch)
			if tt.wantError && !isValidationError(err) {
				t.Errorf("expected validation error, got %v", err)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSettingsService_Update_NoOpPatch_NoAuditOrScheduler(t *testing.T) {
	// A no-op patch (all fields nil or equal to current) should not call
	// audit.Record or SchedulerControl.Apply
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	// Set initial settings
	_ = repo.Save(context.Background(), &entities.Settings{
		SchedulerEnabled: true,
		CronHourUTC:      2,
		Timezone:         "UTC",
		GeminiModel:      "gemini-2.5-flash-lite",
		AbuseIPDBEnabled: true,
		SuppressionDays:  7,
	})

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	// Patch with all nil fields
	patch := dtos.SettingsPatch{}
	_, err := svc.Update(context.Background(), p, patch)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify no audit entry
	entries, _ := auditRepo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries for no-op patch, got %d", len(entries))
	}

	// Verify no scheduler call
	if scheduler.CallCount != 0 {
		t.Errorf("expected 0 scheduler calls for no-op patch, got %d", scheduler.CallCount)
	}
}

func TestSettingsService_Update_ChangedFields_CallsAuditAndScheduler(t *testing.T) {
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" || m == "gemini-1.5-flash" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	// Set initial settings
	_ = repo.Save(context.Background(), &entities.Settings{
		SchedulerEnabled: true,
		CronHourUTC:      2,
		Timezone:         "UTC",
		GeminiModel:      "gemini-2.5-flash-lite",
		AbuseIPDBEnabled: true,
		SuppressionDays:  7,
	})

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	// Change cron hour
	newHour := 12
	patch := dtos.SettingsPatch{CronHourUTC: &newHour}
	result, err := svc.Update(context.Background(), p, patch)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if result.CronHourUTC != 12 {
		t.Errorf("expected CronHourUTC=12, got %d", result.CronHourUTC)
	}

	// Verify audit entry
	entries, _ := auditRepo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	if entries[0].ActionType != enums.AuditSettingsUpdated {
		t.Errorf("expected SETTINGS_UPDATED, got %v", entries[0].ActionType)
	}
	if entries[0].Metadata["cron_hour_utc"] != "12" {
		t.Errorf("expected metadata cron_hour_utc=12, got %v", entries[0].Metadata)
	}

	// Verify scheduler call
	if scheduler.CallCount != 1 {
		t.Errorf("expected 1 scheduler call, got %d", scheduler.CallCount)
	}
	if scheduler.LastCall.CronHour != 12 {
		t.Errorf("expected scheduler called with hour=12, got %d", scheduler.LastCall.CronHour)
	}
}

func TestSettingsService_Update_EqualValues_NoChange(t *testing.T) {
	// Patching with the same value as current should be no-op
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return m == "gemini-2.5-flash-lite" }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	// Set initial settings
	_ = repo.Save(context.Background(), &entities.Settings{
		SchedulerEnabled: true,
		CronHourUTC:      2,
		Timezone:         "UTC",
		GeminiModel:      "gemini-2.5-flash-lite",
		AbuseIPDBEnabled: true,
		SuppressionDays:  7,
	})

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	// Patch with same hour
	sameHour := 2
	patch := dtos.SettingsPatch{CronHourUTC: &sameHour}
	_, err := svc.Update(context.Background(), p, patch)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// No audit or scheduler call
	entries, _ := auditRepo.List(context.Background(), interfaces.AuditQuery{})
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries, got %d", len(entries))
	}
	if scheduler.CallCount != 0 {
		t.Errorf("expected 0 scheduler calls, got %d", scheduler.CallCount)
	}
}

func TestSettingsService_Update_SuppressionDaysValidation(t *testing.T) {
	repo := testfakes.NewSettingsRepository()
	scheduler := &testfakes.FakeSchedulerControl{}
	auditRepo := testfakes.NewAuditRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &testfakes.TxManager{}

	validModel := func(m string) bool { return true }
	svc := NewService(repo, scheduler, auditSvc, tx, true, true, true, true, validModel)

	p := entities.Principal{UserID: "admin", Email: "admin@test.com", Role: enums.RoleAdmin}

	tests := []struct {
		days      int
		wantError bool
	}{
		{-1, true},
		{0, false},
		{7, false},
		{90, false},
		{91, true},
		{100, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.days)), func(t *testing.T) {
			patch := dtos.SettingsPatch{SuppressionDays: &tt.days}
			_, err := svc.Update(context.Background(), p, patch)
			if tt.wantError && !isValidationError(err) {
				t.Errorf("expected validation error, got %v", err)
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func isValidationError(err error) bool {
	return err != nil && (err == interfaces.ErrValidation || interfaces.ErrValidation.Error() == err.Error() || containsSubstring(err.Error(), "validation"))
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findInString(s, substr))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
