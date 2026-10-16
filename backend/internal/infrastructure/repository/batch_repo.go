package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

type BatchRepository struct{ db *gorm.DB }

var _ interfaces.BatchRepository = (*BatchRepository)(nil)

func NewBatchRepository(db *gorm.DB) *BatchRepository { return &BatchRepository{db: db} }

func fromBatch(b *entities.AnalysisBatch) dbmodels.AnalysisBatch {
	var risk *string
	if b.RiskScore != "" {
		s := string(b.RiskScore)
		risk = &s
	}
	return dbmodels.AnalysisBatch{
		ID: b.ID, ScanRunID: dbmodels.StrPtr(b.ScanRunID), WindowStart: b.WindowStart.UTC(), WindowEnd: b.WindowEnd.UTC(),
		Status: string(b.Status), Attempts: b.Attempts, Model: b.Model, RiskScore: risk, Summary: b.Summary,
		RecommendedAction: b.RecommendedAction, SuspiciousIPs: b.SuspiciousIPs, Patterns: b.Patterns,
		AffectedUsers: b.AffectedUsers, TopIP: b.TopIP, RawResponse: b.RawResponse, Error: dbmodels.StrPtr(b.Error),
		CreatedAt: b.CreatedAt, AnalyzedAt: b.AnalyzedAt,
	}
}

func toBatch(m dbmodels.AnalysisBatch) entities.AnalysisBatch {
	return entities.AnalysisBatch{
		ID: m.ID, ScanRunID: dbmodels.StrVal(m.ScanRunID), WindowStart: m.WindowStart.UTC(), WindowEnd: m.WindowEnd.UTC(),
		Status: entities.BatchStatus(m.Status), Attempts: m.Attempts, Model: m.Model,
		RiskScore: enums.RiskLevel(dbmodels.StrVal(m.RiskScore)), Summary: m.Summary,
		RecommendedAction: m.RecommendedAction, SuspiciousIPs: m.SuspiciousIPs, Patterns: m.Patterns,
		AffectedUsers: m.AffectedUsers, TopIP: m.TopIP, RawResponse: m.RawResponse, Error: dbmodels.StrVal(m.Error),
		CreatedAt: m.CreatedAt.UTC(), AnalyzedAt: m.AnalyzedAt,
	}
}

func (r *BatchRepository) Create(ctx context.Context, b *entities.AnalysisBatch, logIDs []string) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	m := fromBatch(b)
	db := conn(ctx, r.db)
	if err := db.Create(&m).Error; err != nil {
		return translate(err)
	}
	if len(logIDs) == 0 {
		return nil
	}
	links := make([]dbmodels.BatchLog, len(logIDs))
	for i, id := range logIDs {
		links[i] = dbmodels.BatchLog{LogID: id, BatchID: b.ID}
	}
	// A duplicate log_id means another scan already claimed this log: the
	// caller's transaction is rolled back with ErrConflict.
	return translate(db.CreateInBatches(links, 500).Error)
}

func (r *BatchRepository) Update(ctx context.Context, b *entities.AnalysisBatch) error {
	m := fromBatch(b)
	res := conn(ctx, r.db).Model(&dbmodels.AnalysisBatch{}).Where("id = ?", b.ID).Updates(map[string]any{
		"scan_run_id":        m.ScanRunID,
		"status":             m.Status,
		"attempts":           m.Attempts,
		"model":              m.Model,
		"risk_score":         m.RiskScore,
		"summary":            m.Summary,
		"recommended_action": m.RecommendedAction,
		"suspicious_ips":     m.SuspiciousIPs,
		"patterns":           m.Patterns,
		"affected_users":     m.AffectedUsers,
		"top_ip":             m.TopIP,
		"raw_response":       m.RawResponse,
		"error":              m.Error,
		"analyzed_at":        m.AnalyzedAt,
	})
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return interfaces.ErrNotFound
	}
	return nil
}

func (r *BatchRepository) Retryable(ctx context.Context, maxAttempts, limit int) ([]entities.AnalysisBatch, error) {
	var ms []dbmodels.AnalysisBatch
	err := conn(ctx, r.db).
		Where("status IN ? AND attempts < ?", []string{string(entities.BatchDeferred), string(entities.BatchFailed), string(entities.BatchPending)}, maxAttempts).
		Order("created_at ASC").Limit(clampLimit(limit, 3, 50)).Find(&ms).Error
	if err != nil {
		return nil, translate(err)
	}
	out := make([]entities.AnalysisBatch, len(ms))
	for i, m := range ms {
		out[i] = toBatch(m)
	}
	return out, nil
}
