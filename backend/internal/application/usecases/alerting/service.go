// Package alerting dispatches incident notifications to Slack/Discord and
// records delivery status (FR-SEC-005).
package alerting

import (
	"context"
	"fmt"

	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

type Service struct {
	notifiers  []interfaces.AlertNotifier
	deliveries interfaces.AlertDeliveryRepository
	audit      *audit.Service
}

// NewService takes zero or more configured notifiers (Slack, Discord, both,
// or neither). With none, Dispatch records SUPPRESSED in the audit log and
// returns no error: an unreachable webhook must not fail a scan.
func NewService(notifiers []interfaces.AlertNotifier, deliveries interfaces.AlertDeliveryRepository, auditSvc *audit.Service) *Service {
	return &Service{notifiers: notifiers, deliveries: deliveries, audit: auditSvc}
}

// Dispatch sends m to every configured channel. Each attempt is recorded
// individually; a failure on one channel does not stop the others. Call this
// with the ctx of the transaction that created the incident so the delivery
// rows and the audit entries are consistent with it, but note that the
// outbound HTTP calls themselves are not part of that transaction (they
// cannot be rolled back).
func (s *Service) Dispatch(ctx context.Context, m interfaces.AlertMessage) (sent int, err error) {
	if len(s.notifiers) == 0 {
		return 0, s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditAlertSuppressed, EntityType: "incident", EntityID: m.IncidentID,
			Details: "No alert channel is configured; incident was not dispatched.",
		})
	}
	for _, n := range s.notifiers {
		status, sendErr := n.Send(ctx, m)
		d := &entities.AlertDelivery{IncidentID: m.IncidentID, Channel: n.Channel(), Success: sendErr == nil, HTTPStatus: status}
		action := enums.AuditAlertSent
		details := fmt.Sprintf("%s alert sent for incident %s.", n.Channel(), m.IncidentID)
		if sendErr != nil {
			d.Error = "delivery failed" // never store the error text: it can embed the webhook URL
			action = enums.AuditAlertFailed
			details = fmt.Sprintf("%s alert FAILED for incident %s (status %d).", n.Channel(), m.IncidentID, status)
		} else {
			sent++
		}
		if err := s.deliveries.Insert(ctx, d); err != nil {
			return sent, err
		}
		if err := s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: action, EntityType: "incident", EntityID: m.IncidentID,
			Details: details, Metadata: map[string]string{"channel": n.Channel()},
		}); err != nil {
			return sent, err
		}
	}
	return sent, nil
}
