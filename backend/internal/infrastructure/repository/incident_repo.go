package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

type IncidentRepository struct{ db *gorm.DB }

var _ interfaces.IncidentRepository = (*IncidentRepository)(nil)

func NewIncidentRepository(db *gorm.DB) *IncidentRepository { return &IncidentRepository{db: db} }

// riskRankSQL orders text risk levels by severity.
const riskRankSQL = "CASE risk_score WHEN 'Low' THEN 0 WHEN 'Medium' THEN 1 WHEN 'High' THEN 2 WHEN 'Critical' THEN 3 END"

func toIncident(m dbmodels.Incident) entities.Incident {
	return entities.Incident{
		ID: m.ID, BatchID: m.BatchID, Fingerprint: m.Fingerprint,
		AIRiskScore: enums.RiskLevel(m.AIRiskScore), RiskScore: enums.RiskLevel(m.RiskScore),
		Status: enums.IncidentStatus(m.Status), AISummary: m.AISummary, RecommendedAction: m.RecommendedAction,
		SuspiciousIPs: m.SuspiciousIPs, Patterns: m.Patterns, AffectedUsers: m.AffectedUsers,
		TopIP: m.TopIP, Country: m.Country, AbuseIPDBConfidence: m.AbuseIPDBConfidence,
		DetectedAt: m.DetectedAt.UTC(), AcknowledgedAt: utcPtr(m.AcknowledgedAt), AcknowledgedBy: dbmodels.StrVal(m.AcknowledgedBy),
		ResolvedAt: utcPtr(m.ResolvedAt), ResolvedBy: dbmodels.StrVal(m.ResolvedBy), UpdatedAt: m.UpdatedAt.UTC(),
	}
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func (r *IncidentRepository) Create(ctx context.Context, inc *entities.Incident) error {
	now := time.Now().UTC()
	if inc.ID == "" {
		inc.ID = uuid.NewString()
	}
	if inc.DetectedAt.IsZero() {
		inc.DetectedAt = now
	}
	if inc.Status == "" {
		inc.Status = enums.StatusOpen
	}
	inc.UpdatedAt = now
	m := dbmodels.Incident{
		ID: inc.ID, BatchID: inc.BatchID, Fingerprint: inc.Fingerprint,
		AIRiskScore: string(inc.AIRiskScore), RiskScore: string(inc.RiskScore), Status: string(inc.Status),
		AISummary: inc.AISummary, RecommendedAction: inc.RecommendedAction,
		SuspiciousIPs: inc.SuspiciousIPs, Patterns: inc.Patterns, AffectedUsers: inc.AffectedUsers,
		TopIP: inc.TopIP, Country: inc.Country, AbuseIPDBConfidence: inc.AbuseIPDBConfidence,
		DetectedAt: inc.DetectedAt, UpdatedAt: now,
	}
	return translate(conn(ctx, r.db).Create(&m).Error)
}

func (r *IncidentRepository) get(ctx context.Context, id string, lock bool) (*entities.Incident, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, interfaces.ErrNotFound
	}
	q := conn(ctx, r.db)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var m dbmodels.Incident
	if err := q.Where("id = ?", id).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	inc := toIncident(m)
	comments, err := r.comments(ctx, []string{inc.ID})
	if err != nil {
		return nil, err
	}
	inc.Comments = comments[inc.ID]
	return &inc, nil
}

func (r *IncidentRepository) Get(ctx context.Context, id string) (*entities.Incident, error) {
	return r.get(ctx, id, false)
}

func (r *IncidentRepository) GetForUpdate(ctx context.Context, id string) (*entities.Incident, error) {
	return r.get(ctx, id, true)
}

func (r *IncidentRepository) comments(ctx context.Context, ids []string) (map[string][]entities.IncidentComment, error) {
	out := map[string][]entities.IncidentComment{}
	if len(ids) == 0 {
		return out, nil
	}
	var ms []dbmodels.IncidentComment
	if err := conn(ctx, r.db).Where("incident_id IN ?", ids).Order("created_at ASC").Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	for _, m := range ms {
		out[m.IncidentID] = append(out[m.IncidentID], entities.IncidentComment{
			ID: m.ID, IncidentID: m.IncidentID, Author: m.Author, Role: m.Role, Body: m.Body, CreatedAt: m.CreatedAt.UTC(),
		})
	}
	return out, nil
}

func (r *IncidentRepository) List(ctx context.Context, q interfaces.IncidentQuery) ([]entities.Incident, error) {
	tx := conn(ctx, r.db).Model(&dbmodels.Incident{})
	if len(q.Statuses) > 0 {
		s := make([]string, len(q.Statuses))
		for i, v := range q.Statuses {
			s[i] = string(v)
		}
		tx = tx.Where("status IN ?", s)
	}
	if len(q.Risks) > 0 {
		s := make([]string, len(q.Risks))
		for i, v := range q.Risks {
			s[i] = string(v)
		}
		tx = tx.Where("risk_score IN ?", s)
	}
	if len(q.Countries) > 0 {
		tx = tx.Where("lower(country) IN ?", lowerAll(q.Countries))
	}
	if len(q.IPs) > 0 {
		// jsonb_exists_any instead of the ?| operator: GORM would treat that
		// "?" as a bind placeholder. GORM expands the slice into ARRAY['a','b'].
		tx = tx.Where("(top_ip IN ? OR jsonb_exists_any(suspicious_ips, ARRAY[?]::text[]))", q.IPs, q.IPs)
	}
	if q.Since != nil {
		tx = tx.Where("detected_at >= ?", q.Since.UTC())
	}
	dir := " ASC"
	if q.Desc {
		dir = " DESC"
	}
	// Only two fixed expressions: user input never reaches ORDER BY.
	if q.SortBy == "risk_score" {
		tx = tx.Order(riskRankSQL + dir).Order("detected_at DESC")
	} else {
		tx = tx.Order("detected_at" + dir)
	}

	var ms []dbmodels.Incident
	if err := tx.Limit(clampLimit(q.Limit, 200, 500)).Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.ID
	}
	comments, err := r.comments(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]entities.Incident, len(ms))
	for i, m := range ms {
		out[i] = toIncident(m)
		out[i].Comments = comments[m.ID]
	}
	return out, nil
}

func (r *IncidentRepository) FindOpenByFingerprint(ctx context.Context, fp string) (*entities.Incident, error) {
	var m dbmodels.Incident
	if err := conn(ctx, r.db).Where("fingerprint = ? AND status <> ?", fp, string(enums.StatusResolved)).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	inc := toIncident(m)
	return &inc, nil
}

func (r *IncidentRepository) LastResolvedByFingerprint(ctx context.Context, fp string) (*entities.Incident, error) {
	var m dbmodels.Incident
	err := conn(ctx, r.db).Where("fingerprint = ? AND status = ?", fp, string(enums.StatusResolved)).
		Order("resolved_at DESC").Take(&m).Error
	if err != nil {
		return nil, translate(err)
	}
	inc := toIncident(m)
	return &inc, nil
}

func (r *IncidentRepository) UpdateStatus(ctx context.Context, inc *entities.Incident) error {
	inc.UpdatedAt = time.Now().UTC()
	res := conn(ctx, r.db).Model(&dbmodels.Incident{}).Where("id = ?", inc.ID).Updates(map[string]any{
		"status":          string(inc.Status),
		"acknowledged_at": inc.AcknowledgedAt,
		"acknowledged_by": dbmodels.StrPtr(inc.AcknowledgedBy),
		"resolved_at":     inc.ResolvedAt,
		"resolved_by":     dbmodels.StrPtr(inc.ResolvedBy),
		"updated_at":      inc.UpdatedAt,
	})
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return interfaces.ErrNotFound
	}
	return nil
}

func (r *IncidentRepository) UpdateEnrichment(ctx context.Context, id string, risk enums.RiskLevel, confidence int) error {
	res := conn(ctx, r.db).Model(&dbmodels.Incident{}).Where("id = ?", id).Updates(map[string]any{
		"risk_score":           string(risk),
		"abuseipdb_confidence": confidence,
		"updated_at":           time.Now().UTC(),
	})
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return interfaces.ErrNotFound
	}
	return nil
}

func (r *IncidentRepository) AddComment(ctx context.Context, c *entities.IncidentComment) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	m := dbmodels.IncidentComment{ID: c.ID, IncidentID: c.IncidentID, Author: c.Author, Role: c.Role, Body: c.Body, CreatedAt: c.CreatedAt}
	return translate(conn(ctx, r.db).Create(&m).Error)
}

func (r *IncidentRepository) CountActiveByRisk(ctx context.Context) (map[enums.RiskLevel]int, error) {
	type row struct {
		RiskScore string
		N         int
	}
	var rows []row
	err := conn(ctx, r.db).Model(&dbmodels.Incident{}).
		Select("risk_score, count(*) AS n").
		Where("status <> ?", string(enums.StatusResolved)).
		Group("risk_score").Scan(&rows).Error
	if err != nil {
		return nil, translate(err)
	}
	out := map[enums.RiskLevel]int{}
	for _, l := range enums.AllRiskLevels() {
		out[l] = 0
	}
	for _, rw := range rows {
		out[enums.RiskLevel(rw.RiskScore)] = rw.N
	}
	return out, nil
}
