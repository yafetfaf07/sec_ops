package repository

import (
	"context"
	"time"

	"gorm.io/gorm"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

// auditChainLockKey serialises appends so the hash chain has a single order.
const auditChainLockKey int64 = 0x5EC0_A0D1

type AuditRepository struct {
	db *gorm.DB
	tx *TxManager
}

var _ interfaces.AuditRepository = (*AuditRepository)(nil)

func NewAuditRepository(db *gorm.DB, tx *TxManager) *AuditRepository {
	return &AuditRepository{db: db, tx: tx}
}

// Append inserts the entry as the next chain link. It joins the caller's
// transaction when there is one, so an audited change and its audit row
// commit or roll back together. The transaction-scoped advisory lock is
// released at commit and works behind transaction-mode poolers.
func (r *AuditRepository) Append(ctx context.Context, e *entities.AuditEntry) error {
	return r.tx.WithinTx(ctx, func(ctx context.Context) error {
		db := conn(ctx, r.db)
		if err := db.Exec("SELECT pg_advisory_xact_lock(?)", auditChainLockKey).Error; err != nil {
			return translate(err)
		}
		var prev string
		if err := db.Raw("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&prev).Error; err != nil {
			return translate(err)
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}
		e.Timestamp = e.Timestamp.UTC().Truncate(time.Microsecond)
		if e.Metadata == nil {
			e.Metadata = map[string]string{}
		}
		e.PrevHash = prev
		e.Hash = entities.AuditHash(prev, *e)

		m := dbmodels.AuditLog{
			Ts: e.Timestamp, UserID: e.UserID, ActionType: string(e.ActionType), EntityType: e.EntityType,
			EntityID: e.EntityID, Details: e.Details, Metadata: e.Metadata, PrevHash: e.PrevHash, Hash: e.Hash,
		}
		if err := db.Create(&m).Error; err != nil {
			return translate(err)
		}
		e.ID = m.ID
		return nil
	})
}

func toAudit(m dbmodels.AuditLog) entities.AuditEntry {
	return entities.AuditEntry{
		ID: m.ID, Timestamp: m.Ts.UTC(), UserID: m.UserID, ActionType: enums.AuditAction(m.ActionType),
		EntityType: m.EntityType, EntityID: m.EntityID, Details: m.Details, Metadata: m.Metadata,
		PrevHash: m.PrevHash, Hash: m.Hash,
	}
}

func (r *AuditRepository) List(ctx context.Context, q interfaces.AuditQuery) ([]entities.AuditEntry, error) {
	tx := conn(ctx, r.db).Model(&dbmodels.AuditLog{})
	if q.ActionType != "" {
		tx = tx.Where("action_type = ?", q.ActionType)
	}
	if q.UserID != "" {
		tx = tx.Where("user_id = ?", q.UserID)
	}
	if q.Since != nil {
		tx = tx.Where("ts >= ?", q.Since.UTC())
	}
	if q.Until != nil {
		tx = tx.Where("ts <= ?", q.Until.UTC())
	}
	var ms []dbmodels.AuditLog
	if err := tx.Order("id DESC").Limit(clampLimit(q.Limit, 200, 1000)).Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	out := make([]entities.AuditEntry, len(ms))
	for i, m := range ms {
		out[i] = toAudit(m)
	}
	return out, nil
}

func (r *AuditRepository) Ascending(ctx context.Context, afterID int64, limit int) ([]entities.AuditEntry, error) {
	var ms []dbmodels.AuditLog
	err := conn(ctx, r.db).Where("id > ?", afterID).Order("id ASC").Limit(clampLimit(limit, 500, 2000)).Find(&ms).Error
	if err != nil {
		return nil, translate(err)
	}
	out := make([]entities.AuditEntry, len(ms))
	for i, m := range ms {
		out[i] = toAudit(m)
	}
	return out, nil
}
