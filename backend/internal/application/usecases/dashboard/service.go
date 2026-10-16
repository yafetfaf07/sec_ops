// Package dashboard implements the SecOps overview (FR-SEC-010).
package dashboard

import (
	"context"
	"errors"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

type Service struct {
	logs      interfaces.LogRepository
	incidents interfaces.IncidentRepository
	scanRuns  interfaces.ScanRunRepository
	clock     interfaces.Clock
}

func NewService(logs interfaces.LogRepository, incidents interfaces.IncidentRepository, scanRuns interfaces.ScanRunRepository, clock interfaces.Clock) *Service {
	return &Service{logs: logs, incidents: incidents, scanRuns: scanRuns, clock: clock}
}

func (s *Service) Summary(ctx context.Context) (*dtos.DashboardSummary, error) {
	startOfDay := s.clock.Now().UTC().Truncate(24 * time.Hour)

	analyzed, err := s.logs.CountAnalyzedSince(ctx, startOfDay)
	if err != nil {
		return nil, err
	}
	ingested, err := s.logs.CountIngestedSince(ctx, startOfDay)
	if err != nil {
		return nil, err
	}
	flagged, err := s.logs.CountFlaggedSince(ctx, startOfDay)
	if err != nil {
		return nil, err
	}
	pending, err := s.logs.CountUnanalyzedFlagged(ctx, s.clock.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	active, err := s.incidents.CountActiveByRisk(ctx)
	if err != nil {
		return nil, err
	}

	var lastScan *time.Time
	if run, err := s.scanRuns.LastFinished(ctx); err == nil {
		t := run.StartedAt
		if run.FinishedAt != nil {
			t = *run.FinishedAt
		}
		lastScan = &t
	} else if !errors.Is(err, interfaces.ErrNotFound) {
		return nil, err
	}

	return &dtos.DashboardSummary{
		LogsAnalyzedToday: analyzed,
		ActiveThreats:     active,
		LastScanTime:      lastScan,
		CriticalIncidents: active[enums.RiskCritical] + active[enums.RiskHigh],
		FlaggedLogs:       flagged,
		LogsIngestedToday: ingested,
		PendingAnalysis:   pending,
	}, nil
}
