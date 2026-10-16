// Package incident implements incident listing and the Acknowledge/Resolve
// lifecycle (FR-SEC-010, FR-SEC-012).
package incident

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

const maxCommentLen = 2000

type Service struct {
	repo  interfaces.IncidentRepository
	audit *audit.Service
	tx    interfaces.TxManager
	clock interfaces.Clock
}

func NewService(repo interfaces.IncidentRepository, auditSvc *audit.Service, tx interfaces.TxManager, clock interfaces.Clock) *Service {
	return &Service{repo: repo, audit: auditSvc, tx: tx, clock: clock}
}

func requireTriage(p entities.Principal) error {
	if !p.Role.CanTriage() {
		return interfaces.ErrForbidden
	}
	return nil
}

func (s *Service) List(ctx context.Context, q dtos.IncidentListQuery) ([]dtos.Incident, error) {
	iq := interfaces.IncidentQuery{Desc: true}
	if q.Status != "" && q.Status != "All" {
		st, err := enums.ParseIncidentStatus(q.Status)
		if err != nil {
			return nil, fmt.Errorf("%w: unknown status", interfaces.ErrValidation)
		}
		iq.Statuses = []enums.IncidentStatus{st}
	}
	if q.Risk != "" && q.Risk != "All" {
		r, err := enums.ParseRiskLevel(q.Risk)
		if err != nil {
			return nil, fmt.Errorf("%w: unknown risk level", interfaces.ErrValidation)
		}
		iq.Risks = []enums.RiskLevel{r}
	}
	switch q.Sort {
	case "", "detected_at":
		iq.SortBy = "detected_at"
	case "risk_score":
		iq.SortBy = "risk_score"
	default:
		return nil, fmt.Errorf("%w: sort must be detected_at or risk_score", interfaces.ErrValidation)
	}
	iq.Desc = q.Dir != "asc"

	rows, err := s.repo.List(ctx, iq)
	if err != nil {
		return nil, err
	}
	out := make([]dtos.Incident, len(rows))
	for i, r := range rows {
		out[i] = dtos.ToIncident(r)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id string) (*dtos.Incident, error) {
	inc, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out := dtos.ToIncident(*inc)
	return &out, nil
}

// Acknowledge: Open -> Acknowledged.
func (s *Service) Acknowledge(ctx context.Context, p entities.Principal, id string) (*dtos.Incident, error) {
	if err := requireTriage(p); err != nil {
		return nil, err
	}
	return s.transition(ctx, p, id, enums.StatusAcknowledged, "", enums.AuditIncidentAcknowledged,
		func(now interfaces.Clock, inc *entities.Incident) {
			t := now.Now().UTC()
			inc.AcknowledgedAt, inc.AcknowledgedBy = &t, p.UserID
		})
}

// Resolve: Open|Acknowledged -> Resolved. Requires a non-empty comment, which
// is stored as both an incident comment and the audit detail.
func (s *Service) Resolve(ctx context.Context, p entities.Principal, id string, req dtos.ResolveRequest) (*dtos.Incident, error) {
	if err := requireTriage(p); err != nil {
		return nil, err
	}
	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		return nil, fmt.Errorf("%w: a resolution comment is required", interfaces.ErrValidation)
	}
	if utf8.RuneCountInString(comment) > maxCommentLen {
		return nil, fmt.Errorf("%w: comment must be at most %d characters", interfaces.ErrValidation, maxCommentLen)
	}
	return s.transition(ctx, p, id, enums.StatusResolved, comment, enums.AuditIncidentResolved,
		func(now interfaces.Clock, inc *entities.Incident) {
			t := now.Now().UTC()
			inc.ResolvedAt, inc.ResolvedBy = &t, p.UserID
		})
}

func (s *Service) transition(ctx context.Context, p entities.Principal, id string, to enums.IncidentStatus, comment string,
	action enums.AuditAction, apply func(interfaces.Clock, *entities.Incident)) (*dtos.Incident, error) {
	var result *entities.Incident
	err := s.tx.WithinTx(ctx, func(ctx context.Context) error {
		inc, err := s.repo.GetForUpdate(ctx, id)
		if err != nil {
			return err
		}
		if !inc.Status.CanTransitionTo(to) {
			return fmt.Errorf("%w: cannot move incident from %s to %s", interfaces.ErrInvalidTransition, inc.Status, to)
		}
		inc.Status = to
		apply(s.clock, inc)
		if err := s.repo.UpdateStatus(ctx, inc); err != nil {
			return err
		}
		if comment != "" {
			if err := s.repo.AddComment(ctx, &entities.IncidentComment{IncidentID: id, Author: p.Actor(), Role: string(p.Role), Body: comment}); err != nil {
				return err
			}
		}
		if err := s.audit.Record(ctx, audit.Event{
			Actor: p, Action: action, EntityType: "incident", EntityID: id,
			Details: fmt.Sprintf("Incident %s moved to %s by %s.", id, to, p.Actor()),
		}); err != nil {
			return err
		}
		result, err = s.repo.Get(ctx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := dtos.ToIncident(*result)
	return &out, nil
}
