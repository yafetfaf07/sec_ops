package repository

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

// LogRepository is append-only by construction: it has no update or delete
// methods, and the database triggers reject them anyway.
type LogRepository struct{ db *gorm.DB }

var _ interfaces.LogRepository = (*LogRepository)(nil)

func NewLogRepository(db *gorm.DB) *LogRepository { return &LogRepository{db: db} }

func toRawLog(m dbmodels.RawLog) entities.RawLog {
	return entities.RawLog{
		ID: m.ID, LogID: m.LogID, Timestamp: m.Ts.UTC(), UserID: m.UserID, IPAddress: m.IPAddress,
		Country: m.Country, City: m.City, Action: enums.LogAction(m.Action), UserAgent: m.UserAgent,
		Flagged: m.Flagged, IngestedAt: m.IngestedAt.UTC(),
	}
}

func (r *LogRepository) InsertMany(ctx context.Context, logs []entities.RawLog) (int, error) {
	if len(logs) == 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	rows := make([]dbmodels.RawLog, len(logs))
	for i, l := range logs {
		rows[i] = dbmodels.RawLog{
			ID: uuid.NewString(), LogID: l.LogID, Ts: l.Timestamp.UTC(), UserID: l.UserID,
			IPAddress: l.IPAddress, Country: l.Country, City: l.City, Action: string(l.Action),
			UserAgent: l.UserAgent, Flagged: l.Flagged, IngestedAt: now,
		}
	}
	res := conn(ctx, r.db).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "log_id"}},
		DoNothing: true,
	}).CreateInBatches(rows, 200)
	if res.Error != nil {
		return 0, translate(res.Error)
	}
	return int(res.RowsAffected), nil
}

func (r *LogRepository) applyQuery(tx *gorm.DB, q interfaces.LogQuery) *gorm.DB {
	if len(q.Actions) > 0 {
		acts := make([]string, len(q.Actions))
		for i, a := range q.Actions {
			acts[i] = string(a)
		}
		tx = tx.Where("action IN ?", acts)
	}
	if len(q.Countries) > 0 {
		tx = tx.Where("lower(country) IN ?", lowerAll(q.Countries))
	}
	if len(q.Cities) > 0 {
		tx = tx.Where("lower(city) IN ?", lowerAll(q.Cities))
	}
	if len(q.UserIDs) > 0 {
		tx = tx.Where("user_id IN ?", q.UserIDs)
	}
	if len(q.IPs) > 0 {
		tx = tx.Where("ip_address IN ?", q.IPs)
	}
	if q.Since != nil {
		tx = tx.Where("ts >= ?", q.Since.UTC())
	}
	if q.Until != nil {
		tx = tx.Where("ts <= ?", q.Until.UTC())
	}
	if q.FlaggedOnly {
		tx = tx.Where("flagged")
	}
	if s := strings.TrimSpace(q.Search); s != "" {
		pattern := "%" + escapeLike(strings.ToLower(s)) + "%"
		tx = tx.Where("(lower(user_id) LIKE ? ESCAPE '\\' OR ip_address LIKE ? ESCAPE '\\' OR lower(log_id) LIKE ? ESCAPE '\\')",
			pattern, pattern, pattern)
	}
	return tx
}

func (r *LogRepository) List(ctx context.Context, q interfaces.LogQuery) ([]entities.RawLog, int, error) {
	var total int64
	if err := r.applyQuery(conn(ctx, r.db).Model(&dbmodels.RawLog{}), q).Count(&total).Error; err != nil {
		return nil, 0, translate(err)
	}
	var ms []dbmodels.RawLog
	err := r.applyQuery(conn(ctx, r.db), q).
		Order("ts DESC, log_id").
		Limit(clampLimit(q.Limit, 50, 500)).Offset(max(q.Offset, 0)).
		Find(&ms).Error
	if err != nil {
		return nil, 0, translate(err)
	}
	out := make([]entities.RawLog, len(ms))
	for i, m := range ms {
		out[i] = toRawLog(m)
	}
	return out, int(total), nil
}

func (r *LogRepository) Countries(ctx context.Context) ([]string, error) {
	var out []string
	err := conn(ctx, r.db).Model(&dbmodels.RawLog{}).
		Where("country <> ''").Distinct("country").Order("country").Limit(500).Pluck("country", &out).Error
	return out, translate(err)
}

func (r *LogRepository) unanalyzed(ctx context.Context, since time.Time) *gorm.DB {
	return conn(ctx, r.db).Model(&dbmodels.RawLog{}).
		Where("flagged AND ts >= ?", since.UTC()).
		Where("NOT EXISTS (SELECT 1 FROM batch_logs bl WHERE bl.log_id = raw_logs.log_id)")
}

func (r *LogRepository) UnanalyzedFlagged(ctx context.Context, since time.Time, limit int) ([]entities.RawLog, error) {
	var ms []dbmodels.RawLog
	if err := r.unanalyzed(ctx, since).Order("ts ASC").Limit(clampLimit(limit, 500, 5000)).Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	out := make([]entities.RawLog, len(ms))
	for i, m := range ms {
		out[i] = toRawLog(m)
	}
	return out, nil
}

func (r *LogRepository) CountUnanalyzedFlagged(ctx context.Context, since time.Time) (int, error) {
	var n int64
	err := r.unanalyzed(ctx, since).Count(&n).Error
	return int(n), translate(err)
}

func (r *LogRepository) SuccessfulLoginsForUsers(ctx context.Context, userIDs []string, from, to time.Time, limit int) ([]entities.RawLog, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	var ms []dbmodels.RawLog
	err := conn(ctx, r.db).
		Where("action = ? AND user_id IN ? AND ts BETWEEN ? AND ?", string(enums.ActionLoginSuccess), userIDs, from.UTC(), to.UTC()).
		Order("ts ASC").Limit(clampLimit(limit, 200, 2000)).Find(&ms).Error
	if err != nil {
		return nil, translate(err)
	}
	out := make([]entities.RawLog, len(ms))
	for i, m := range ms {
		out[i] = toRawLog(m)
	}
	return out, nil
}

func (r *LogRepository) ByBatch(ctx context.Context, batchID string) ([]entities.RawLog, error) {
	if _, err := uuid.Parse(batchID); err != nil {
		return nil, interfaces.ErrNotFound
	}
	var ms []dbmodels.RawLog
	err := conn(ctx, r.db).
		Joins("JOIN batch_logs bl ON bl.log_id = raw_logs.log_id").
		Where("bl.batch_id = ?", batchID).Order("raw_logs.ts ASC").Limit(5000).Find(&ms).Error
	if err != nil {
		return nil, translate(err)
	}
	out := make([]entities.RawLog, len(ms))
	for i, m := range ms {
		out[i] = toRawLog(m)
	}
	return out, nil
}

func (r *LogRepository) CountIngestedSince(ctx context.Context, t time.Time) (int, error) {
	var n int64
	err := conn(ctx, r.db).Model(&dbmodels.RawLog{}).Where("ts >= ?", t.UTC()).Count(&n).Error
	return int(n), translate(err)
}

func (r *LogRepository) CountFlaggedSince(ctx context.Context, t time.Time) (int, error) {
	var n int64
	err := conn(ctx, r.db).Model(&dbmodels.RawLog{}).Where("flagged AND ts >= ?", t.UTC()).Count(&n).Error
	return int(n), translate(err)
}

func (r *LogRepository) CountAnalyzedSince(ctx context.Context, t time.Time) (int, error) {
	var n int64
	err := conn(ctx, r.db).Model(&dbmodels.BatchLog{}).
		Joins("JOIN analysis_batches ab ON ab.id = batch_logs.batch_id").
		Where("ab.status = ? AND ab.analyzed_at >= ?", string(entities.BatchDone), t.UTC()).
		Count(&n).Error
	return int(n), translate(err)
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

// escapeLike neutralises LIKE wildcards in user input.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
