package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

// ---------------------------------------------------------------- threat intel

type ThreatIntelCache struct{ db *gorm.DB }

var _ interfaces.ThreatIntelCache = (*ThreatIntelCache)(nil)

func NewThreatIntelCache(db *gorm.DB) *ThreatIntelCache { return &ThreatIntelCache{db: db} }

func (r *ThreatIntelCache) Get(ctx context.Context, ip string, now time.Time) (*entities.ThreatIntel, error) {
	var m dbmodels.ThreatIntel
	if err := conn(ctx, r.db).Where("ip = ? AND expires_at > ?", ip, now.UTC()).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	return &entities.ThreatIntel{
		IP: m.IP, AbuseConfidence: m.AbuseConfidence, TotalReports: m.TotalReports, Country: m.Country,
		FetchedAt: m.FetchedAt.UTC(), ExpiresAt: m.ExpiresAt.UTC(), Cached: true,
	}, nil
}

func (r *ThreatIntelCache) Put(ctx context.Context, ti *entities.ThreatIntel) error {
	m := dbmodels.ThreatIntel{
		IP: ti.IP, AbuseConfidence: ti.AbuseConfidence, TotalReports: ti.TotalReports, Country: ti.Country,
		FetchedAt: ti.FetchedAt.UTC(), ExpiresAt: ti.ExpiresAt.UTC(),
	}
	return translate(conn(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip"}},
		DoUpdates: clause.AssignmentColumns([]string{"abuse_confidence", "total_reports", "country", "fetched_at", "expires_at"}),
	}).Create(&m).Error)
}

// ---------------------------------------------------------------- deliveries

type AlertDeliveryRepository struct{ db *gorm.DB }

var _ interfaces.AlertDeliveryRepository = (*AlertDeliveryRepository)(nil)

func NewAlertDeliveryRepository(db *gorm.DB) *AlertDeliveryRepository {
	return &AlertDeliveryRepository{db: db}
}

func (r *AlertDeliveryRepository) Insert(ctx context.Context, d *entities.AlertDelivery) error {
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	if d.AttemptedAt.IsZero() {
		d.AttemptedAt = time.Now().UTC()
	}
	status := "failed"
	if d.Success {
		status = "success"
	}
	var hs *int
	if d.HTTPStatus != 0 {
		hs = &d.HTTPStatus
	}
	m := dbmodels.AlertDelivery{
		ID: d.ID, IncidentID: d.IncidentID, Channel: d.Channel, Status: status,
		HTTPStatus: hs, Error: dbmodels.StrPtr(d.Error), AttemptedAt: d.AttemptedAt,
	}
	return translate(conn(ctx, r.db).Create(&m).Error)
}

// ---------------------------------------------------------------- scan runs

type ScanRunRepository struct{ db *gorm.DB }

var _ interfaces.ScanRunRepository = (*ScanRunRepository)(nil)

func NewScanRunRepository(db *gorm.DB) *ScanRunRepository { return &ScanRunRepository{db: db} }

func toScanRun(m dbmodels.ScanRun) entities.ScanRun {
	return entities.ScanRun{
		ID: m.ID, Trigger: entities.ScanTrigger(m.Trigger), Actor: m.Actor, Status: entities.ScanStatus(m.Status),
		StartedAt: m.StartedAt.UTC(), FinishedAt: utcPtr(m.FinishedAt), LogsFetched: m.LogsFetched,
		Analyzed: m.Analyzed, NewAlerts: m.NewAlerts, Error: dbmodels.StrVal(m.Error),
	}
}

// Start inserts a running scan. The partial unique index
// scan_runs_one_running_uq turns a concurrent second start into ErrConflict.
func (r *ScanRunRepository) Start(ctx context.Context, s *entities.ScanRun) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now().UTC()
	}
	s.Status = entities.ScanRunning
	m := dbmodels.ScanRun{ID: s.ID, Trigger: string(s.Trigger), Actor: s.Actor, Status: string(s.Status), StartedAt: s.StartedAt}
	return translate(conn(ctx, r.db).Create(&m).Error)
}

func (r *ScanRunRepository) Finish(ctx context.Context, s *entities.ScanRun) error {
	return translate(conn(ctx, r.db).Model(&dbmodels.ScanRun{}).Where("id = ?", s.ID).Updates(map[string]any{
		"status":       string(s.Status),
		"finished_at":  s.FinishedAt,
		"logs_fetched": s.LogsFetched,
		"analyzed":     s.Analyzed,
		"new_alerts":   s.NewAlerts,
		"error":        dbmodels.StrPtr(s.Error),
	}).Error)
}

// FailStale marks runs left "running" by a crashed or killed instance as
// failed, so the one-running lock cannot wedge forever.
func (r *ScanRunRepository) FailStale(ctx context.Context, startedBefore time.Time) (int, error) {
	res := conn(ctx, r.db).Model(&dbmodels.ScanRun{}).
		Where("status = ? AND started_at < ?", string(entities.ScanRunning), startedBefore.UTC()).
		Updates(map[string]any{"status": string(entities.ScanFailed), "finished_at": time.Now().UTC(), "error": "abandoned (timeout)"})
	return int(res.RowsAffected), translate(res.Error)
}

func (r *ScanRunRepository) LastFinished(ctx context.Context) (*entities.ScanRun, error) {
	var m dbmodels.ScanRun
	err := conn(ctx, r.db).Where("status = ?", string(entities.ScanSucceeded)).Order("finished_at DESC").Take(&m).Error
	if err != nil {
		return nil, translate(err)
	}
	s := toScanRun(m)
	return &s, nil
}

func (r *ScanRunRepository) List(ctx context.Context, limit int) ([]entities.ScanRun, error) {
	var ms []dbmodels.ScanRun
	if err := conn(ctx, r.db).Order("started_at DESC").Limit(clampLimit(limit, 20, 100)).Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	out := make([]entities.ScanRun, len(ms))
	for i, m := range ms {
		out[i] = toScanRun(m)
	}
	return out, nil
}

// ---------------------------------------------------------------- usage budget

type UsageRepository struct{ db *gorm.DB }

var _ interfaces.UsageRepository = (*UsageRepository)(nil)

func NewUsageRepository(db *gorm.DB) *UsageRepository { return &UsageRepository{db: db} }

// Consume increments today's counter only while it is below limit, in one
// atomic statement, so concurrent callers cannot overshoot the free tier.
func (r *UsageRepository) Consume(ctx context.Context, provider string, day time.Time, limit int) (bool, error) {
	var count int
	err := conn(ctx, r.db).Raw(`
		INSERT INTO api_usage (day, provider, count) VALUES (?, ?, 1)
		ON CONFLICT (day, provider) DO UPDATE SET count = api_usage.count + 1
		WHERE api_usage.count < ?
		RETURNING count`, day.UTC().Format("2006-01-02"), provider, limit).Scan(&count).Error
	if err != nil {
		return false, translate(err)
	}
	// No row returned (count stays 0) when the WHERE rejected the update.
	return count > 0 && count <= limit, nil
}

// ---------------------------------------------------------------- settings

const settingsKey = "runtime"

type SettingsRepository struct{ db *gorm.DB }

var _ interfaces.SettingsRepository = (*SettingsRepository)(nil)

func NewSettingsRepository(db *gorm.DB) *SettingsRepository { return &SettingsRepository{db: db} }

type settingsDoc struct {
	SchedulerEnabled bool   `json:"scheduler_enabled"`
	CronHourUTC      int    `json:"cron_hour_utc"`
	Timezone         string `json:"timezone"`
	GeminiModel      string `json:"gemini_model"`
	AbuseIPDBEnabled bool   `json:"abuseipdb_enabled"`
	SuppressionDays  int    `json:"suppression_days"`
}

func (r *SettingsRepository) Get(ctx context.Context) (*entities.Settings, error) {
	var m dbmodels.Setting
	if err := conn(ctx, r.db).Where("key = ?", settingsKey).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	var d settingsDoc
	if err := json.Unmarshal(m.Value, &d); err != nil {
		return nil, errors.Join(errors.New("corrupt settings row"), err)
	}
	return &entities.Settings{
		SchedulerEnabled: d.SchedulerEnabled, CronHourUTC: d.CronHourUTC, Timezone: d.Timezone,
		GeminiModel: d.GeminiModel, AbuseIPDBEnabled: d.AbuseIPDBEnabled, SuppressionDays: d.SuppressionDays,
		UpdatedBy: m.UpdatedBy, UpdatedAt: m.UpdatedAt.UTC(),
	}, nil
}

func (r *SettingsRepository) Save(ctx context.Context, s *entities.Settings) error {
	b, err := json.Marshal(settingsDoc{
		SchedulerEnabled: s.SchedulerEnabled, CronHourUTC: s.CronHourUTC, Timezone: s.Timezone,
		GeminiModel: s.GeminiModel, AbuseIPDBEnabled: s.AbuseIPDBEnabled, SuppressionDays: s.SuppressionDays,
	})
	if err != nil {
		return err
	}
	s.UpdatedAt = time.Now().UTC()
	m := dbmodels.Setting{Key: settingsKey, Value: b, UpdatedBy: s.UpdatedBy, UpdatedAt: s.UpdatedAt}
	return translate(conn(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_by", "updated_at"}),
	}).Create(&m).Error)
}
