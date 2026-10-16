package dashboard

import (
	"context"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
)

func TestDashboardService_Summary_AggregatesCorrectly(t *testing.T) {
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 30, 0, 0, time.UTC)}

	svc := NewService(logs, incidents, scanRuns, clock)

	// Insert logs: 3 today (2 flagged, 1 analyzed via batch link)
	startOfDay := clock.T.Truncate(24 * time.Hour)
	_, _ = logs.InsertMany(context.Background(), []entities.RawLog{
		{LogID: "log1", Timestamp: clock.T.Add(-1 * time.Hour), UserID: "user1", IPAddress: "1.2.3.4", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log2", Timestamp: clock.T.Add(-2 * time.Hour), UserID: "user2", IPAddress: "5.6.7.8", Country: "CA", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: clock.T},
		{LogID: "log3", Timestamp: clock.T.Add(-3 * time.Hour), UserID: "user3", IPAddress: "9.10.11.12", Country: "US", Action: enums.ActionLoginSuccess, Flagged: false, IngestedAt: clock.T},
		{LogID: "log_old", Timestamp: startOfDay.Add(-25 * time.Hour), UserID: "user4", IPAddress: "1.1.1.1", Country: "US", Action: enums.ActionLoginFailed, Flagged: true, IngestedAt: startOfDay.Add(-25 * time.Hour)},
	})

	// Mark log1 as analyzed
	batches := testfakes.NewBatchRepository(logs)
	_ = batches.Create(context.Background(), &entities.AnalysisBatch{
		ScanRunID: "run1",
		Status:    entities.BatchDone,
	}, []string{"log1"})

	// Create incidents: 2 Critical, 1 High, 1 Medium (all Open/Ack - not resolved)
	_ = incidents.Create(context.Background(), &entities.Incident{
		RiskScore:     enums.RiskCritical,
		Status:        enums.StatusOpen,
		AISummary:     "Critical 1",
		SuspiciousIPs: []string{"1.2.3.4"},
		Patterns:      []string{"p1"},
		AffectedUsers: []string{"u1"},
		Fingerprint:   "fp1",
	})
	_ = incidents.Create(context.Background(), &entities.Incident{
		RiskScore:     enums.RiskCritical,
		Status:        enums.StatusOpen,
		AISummary:     "Critical 2",
		SuspiciousIPs: []string{"5.6.7.8"},
		Patterns:      []string{"p2"},
		AffectedUsers: []string{"u2"},
		Fingerprint:   "fp2",
	})
	_ = incidents.Create(context.Background(), &entities.Incident{
		RiskScore:     enums.RiskHigh,
		Status:        enums.StatusOpen,
		AISummary:     "High 1",
		SuspiciousIPs: []string{"9.10.11.12"},
		Patterns:      []string{"p3"},
		AffectedUsers: []string{"u3"},
		Fingerprint:   "fp3",
	})
	_ = incidents.Create(context.Background(), &entities.Incident{
		RiskScore:     enums.RiskMedium,
		Status:        enums.StatusOpen,
		AISummary:     "Medium 1",
		SuspiciousIPs: []string{"1.1.1.1"},
		Patterns:      []string{"p4"},
		AffectedUsers: []string{"u4"},
		Fingerprint:   "fp4",
	})

	// Create a finished scan run
	finishedAt := clock.T.Add(-10 * time.Minute)
	_ = scanRuns.Start(context.Background(), &entities.ScanRun{
		Trigger:   entities.TriggerScheduler,
		Actor:     "SYSTEM",
		StartedAt: clock.T.Add(-15 * time.Minute),
	})
	runs, _ := scanRuns.List(context.Background(), 10)
	if len(runs) > 0 {
		runs[0].FinishedAt = &finishedAt
		_ = scanRuns.Finish(context.Background(), &runs[0])
	}

	summary, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary failed: %v", err)
	}

	// Verify counts
	if summary.LogsIngestedToday != 3 {
		t.Errorf("expected 3 logs ingested today, got %d", summary.LogsIngestedToday)
	}
	if summary.FlaggedLogs != 2 {
		t.Errorf("expected 2 flagged logs today, got %d", summary.FlaggedLogs)
	}
	if summary.LogsAnalyzedToday != 1 {
		t.Errorf("expected 1 log analyzed today, got %d", summary.LogsAnalyzedToday)
	}
	if summary.PendingAnalysis != 1 {
		t.Errorf("expected 1 pending analysis (log2 flagged but not analyzed in last 24h), got %d", summary.PendingAnalysis)
	}

	// ActiveThreats: only non-resolved
	if summary.ActiveThreats[enums.RiskCritical] != 2 {
		t.Errorf("expected 2 Critical active, got %d", summary.ActiveThreats[enums.RiskCritical])
	}
	if summary.ActiveThreats[enums.RiskHigh] != 1 {
		t.Errorf("expected 1 High active, got %d", summary.ActiveThreats[enums.RiskHigh])
	}
	if summary.ActiveThreats[enums.RiskMedium] != 1 {
		t.Errorf("expected 1 Medium active, got %d", summary.ActiveThreats[enums.RiskMedium])
	}

	// CriticalIncidents = Critical + High = 3
	if summary.CriticalIncidents != 3 {
		t.Errorf("expected 3 critical incidents (Critical+High), got %d", summary.CriticalIncidents)
	}

	// LastScanTime should be set
	if summary.LastScanTime == nil {
		t.Error("expected LastScanTime to be set")
	}
}

func TestDashboardService_Summary_LastScanTime_NilWhenNone(t *testing.T) {
	// When ScanRunRepository.LastFinished returns ErrNotFound, LastScanTime is nil
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 30, 0, 0, time.UTC)}

	svc := NewService(logs, incidents, scanRuns, clock)

	summary, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary failed: %v", err)
	}

	if summary.LastScanTime != nil {
		t.Errorf("expected LastScanTime to be nil when no scans exist, got %v", summary.LastScanTime)
	}
}

func TestDashboardService_Summary_HandlesEmptyData(t *testing.T) {
	logs := testfakes.NewLogRepository()
	incidents := testfakes.NewIncidentRepository()
	scanRuns := testfakes.NewScanRunRepository()
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 14, 30, 0, 0, time.UTC)}

	svc := NewService(logs, incidents, scanRuns, clock)

	summary, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary failed: %v", err)
	}

	if summary.LogsIngestedToday != 0 {
		t.Errorf("expected 0 logs ingested, got %d", summary.LogsIngestedToday)
	}
	if summary.FlaggedLogs != 0 {
		t.Errorf("expected 0 flagged logs, got %d", summary.FlaggedLogs)
	}
	if summary.LogsAnalyzedToday != 0 {
		t.Errorf("expected 0 logs analyzed, got %d", summary.LogsAnalyzedToday)
	}
	if summary.PendingAnalysis != 0 {
		t.Errorf("expected 0 pending, got %d", summary.PendingAnalysis)
	}
	if summary.CriticalIncidents != 0 {
		t.Errorf("expected 0 critical incidents, got %d", summary.CriticalIncidents)
	}
	if len(summary.ActiveThreats) != 0 {
		t.Errorf("expected empty ActiveThreats, got %v", summary.ActiveThreats)
	}
	if summary.LastScanTime != nil {
		t.Errorf("expected nil LastScanTime, got %v", summary.LastScanTime)
	}
}
