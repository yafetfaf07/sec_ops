// Package settings implements the admin-editable runtime settings and the
// Cloud Scheduler control surface (FR-SEC-030, FR-SEC-003).
package settings

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// defaults seed the row on first read when none has been saved yet.
var defaults = entities.Settings{SchedulerEnabled: true, CronHourUTC: 2, Timezone: "UTC", GeminiModel: "gemini-2.5-flash-lite", AbuseIPDBEnabled: true, SuppressionDays: 7}

type Service struct {
	repo       interfaces.SettingsRepository
	scheduler  interfaces.SchedulerControl
	audit      *audit.Service
	tx         interfaces.TxManager
	slackSet   bool
	discordSet bool
	geminiSet  bool
	abuseSet   bool
	validModel func(string) bool
}

func NewService(repo interfaces.SettingsRepository, scheduler interfaces.SchedulerControl, auditSvc *audit.Service, tx interfaces.TxManager,
	slackConfigured, discordConfigured, geminiConfigured, abuseConfigured bool, validModel func(string) bool) *Service {
	return &Service{
		repo: repo, scheduler: scheduler, audit: auditSvc, tx: tx,
		slackSet: slackConfigured, discordSet: discordConfigured, geminiSet: geminiConfigured, abuseSet: abuseConfigured,
		validModel: validModel,
	}
}

func (s *Service) Get(ctx context.Context) (*dtos.SchedulerSettings, error) {
	cur, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	return s.toDTO(cur), nil
}

func (s *Service) current(ctx context.Context) (*entities.Settings, error) {
	cur, err := s.repo.Get(ctx)
	if errors.Is(err, interfaces.ErrNotFound) {
		d := defaults
		return &d, nil
	}
	return cur, err
}

func (s *Service) toDTO(cur *entities.Settings) *dtos.SchedulerSettings {
	out := &dtos.SchedulerSettings{
		Enabled: cur.SchedulerEnabled, CronHourUTC: cur.CronHourUTC, Timezone: cur.Timezone,
		SlackWebhookSet: s.slackSet, DiscordWebhookSet: s.discordSet, GeminiModel: cur.GeminiModel,
		AbuseIPDBEnabled: cur.AbuseIPDBEnabled, SuppressionDays: cur.SuppressionDays,
		GeminiConfigured: s.geminiSet, AbuseIPDBConfigured: s.abuseSet, SchedulerManaged: s.scheduler.Configured(),
		UpdatedBy: cur.UpdatedBy,
	}
	if !cur.UpdatedAt.IsZero() {
		t := cur.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// Update applies a partial patch, persists it, and-if a Cloud Scheduler job
// is configured-pushes the schedule change (FR-SEC-030: admin only, enforced
// by the caller/handler via RBAC middleware).
func (s *Service) Update(ctx context.Context, p entities.Principal, patch dtos.SettingsPatch) (*dtos.SchedulerSettings, error) {
	if !p.Role.CanAdminister() {
		return nil, interfaces.ErrForbidden
	}
	var result *entities.Settings
	err := s.tx.WithinTx(ctx, func(ctx context.Context) error {
		cur, err := s.current(ctx)
		if err != nil {
			return err
		}
		changed := map[string]string{}
		if patch.Enabled != nil && *patch.Enabled != cur.SchedulerEnabled {
			cur.SchedulerEnabled = *patch.Enabled
			changed["enabled"] = fmt.Sprint(cur.SchedulerEnabled)
		}
		if patch.CronHourUTC != nil {
			if *patch.CronHourUTC < 0 || *patch.CronHourUTC > 23 {
				return fmt.Errorf("%w: cron_hour_utc must be 0-23", interfaces.ErrValidation)
			}
			if *patch.CronHourUTC != cur.CronHourUTC {
				cur.CronHourUTC = *patch.CronHourUTC
				changed["cron_hour_utc"] = fmt.Sprint(cur.CronHourUTC)
			}
		}
		if patch.Timezone != nil {
			tz := strings.TrimSpace(*patch.Timezone)
			if tz == "" || len(tz) > 64 {
				return fmt.Errorf("%w: timezone is invalid", interfaces.ErrValidation)
			}
			if tz != cur.Timezone {
				cur.Timezone, changed["timezone"] = tz, tz
			}
		}
		if patch.GeminiModel != nil {
			m := strings.TrimSpace(*patch.GeminiModel)
			if !s.validModel(m) {
				return fmt.Errorf("%w: gemini_model is not a valid model id", interfaces.ErrValidation)
			}
			if m != cur.GeminiModel {
				cur.GeminiModel, changed["gemini_model"] = m, m
			}
		}
		if patch.AbuseIPDBEnabled != nil && *patch.AbuseIPDBEnabled != cur.AbuseIPDBEnabled {
			cur.AbuseIPDBEnabled = *patch.AbuseIPDBEnabled
			changed["abuseipdb_enabled"] = fmt.Sprint(cur.AbuseIPDBEnabled)
		}
		if patch.SuppressionDays != nil {
			if *patch.SuppressionDays < 0 || *patch.SuppressionDays > 90 {
				return fmt.Errorf("%w: suppression_days must be 0-90", interfaces.ErrValidation)
			}
			if *patch.SuppressionDays != cur.SuppressionDays {
				cur.SuppressionDays = *patch.SuppressionDays
				changed["suppression_days"] = fmt.Sprint(cur.SuppressionDays)
			}
		}
		if len(changed) == 0 {
			result = cur
			return nil
		}
		cur.UpdatedBy = p.Actor()
		if err := s.repo.Save(ctx, cur); err != nil {
			return err
		}
		if s.scheduler.Configured() {
			if err := s.scheduler.Apply(ctx, cur.SchedulerEnabled, cur.CronHourUTC, cur.Timezone); err != nil {
				return err
			}
		}
		result = cur
		return s.audit.Record(ctx, audit.Event{
			Actor: p, Action: enums.AuditSettingsUpdated, EntityType: "settings",
			Details: fmt.Sprintf("Scheduler/API configuration updated by %s.", p.Actor()), Metadata: changed,
		})
	})
	if err != nil {
		return nil, err
	}
	return s.toDTO(result), nil
}
