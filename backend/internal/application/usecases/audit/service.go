// Package audit records and serves the immutable audit trail (FR-SEC-031).
package audit

import (
	"context"
	"strconv"
	"time"
	"unicode/utf8"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

const maxDetails = 2000

type Service struct {
	repo  interfaces.AuditRepository
	clock interfaces.Clock
}

func NewService(repo interfaces.AuditRepository, clock interfaces.Clock) *Service {
	return &Service{repo: repo, clock: clock}
}

// Event is one auditable action.
type Event struct {
	Actor      entities.Principal
	Action     enums.AuditAction
	EntityType string
	EntityID   string
	Details    string
	Metadata   map[string]string
}

// Record appends the event. Call it with the ctx of the transaction that
// performs the audited change so both commit together.
func (s *Service) Record(ctx context.Context, e Event) error {
	userID := e.Actor.UserID
	if userID == "" {
		userID = enums.SystemActor
	}
	details := e.Details
	if utf8.RuneCountInString(details) > maxDetails {
		details = string([]rune(details)[:maxDetails])
	}
	meta := map[string]string{}
	for k, v := range e.Metadata {
		meta[k] = v
	}
	if !e.Actor.IsSystem() && e.Actor.Email != "" {
		meta["actor_email"] = e.Actor.Email
		meta["actor_role"] = string(e.Actor.Role)
	}
	return s.repo.Append(ctx, &entities.AuditEntry{
		Timestamp: s.clock.Now().UTC(), UserID: userID, ActionType: e.Action,
		EntityType: e.EntityType, EntityID: e.EntityID, Details: details, Metadata: meta,
	})
}

func (s *Service) List(ctx context.Context, q interfaces.AuditQuery) ([]dtos.AuditEntry, error) {
	entries, err := s.repo.List(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]dtos.AuditEntry, len(entries))
	for i, e := range entries {
		out[i] = dtos.AuditEntry{
			ID: strconv.FormatInt(e.ID, 10), Timestamp: e.Timestamp, UserID: e.UserID,
			ActionType: string(e.ActionType), Details: e.Details, EntityType: e.EntityType,
			EntityID: e.EntityID, Metadata: e.Metadata,
		}
	}
	return out, nil
}

// Verify walks the whole chain and recomputes every hash. Any UPDATE that
// slipped past the triggers (e.g. by a superuser) breaks the chain here.
func (s *Service) Verify(ctx context.Context) (*dtos.AuditVerifyResult, error) {
	res := &dtos.AuditVerifyResult{Valid: true}
	var afterID int64
	prev := ""
	deadline := time.Now().Add(20 * time.Second)
	for {
		page, err := s.repo.Ascending(ctx, afterID, 1000)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			res.Checked++
			if e.PrevHash != prev {
				return &dtos.AuditVerifyResult{Valid: false, Checked: res.Checked, FirstBadID: e.ID, Reason: "prev_hash does not link to the previous entry"}, nil
			}
			if entities.AuditHash(prev, e) != e.Hash {
				return &dtos.AuditVerifyResult{Valid: false, Checked: res.Checked, FirstBadID: e.ID, Reason: "hash does not match entry contents"}, nil
			}
			prev = e.Hash
			afterID = e.ID
		}
		if time.Now().After(deadline) {
			res.Reason = "verification stopped early (time budget); chain valid up to latest_hash"
			break
		}
	}
	res.LatestHash = prev
	return res, nil
}
