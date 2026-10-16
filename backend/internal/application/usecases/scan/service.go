// Package scan orchestrates the proactive daily scan (FR-SEC-003): fetch
// unanalyzed flagged logs, analyze them (FR-SEC-002), enrich high-risk IPs
// (FR-SEC-004), create/suppress incidents, and dispatch alerts (FR-SEC-005).
//
// The whole pipeline runs synchronously inside the HTTP request: Cloud Run
// throttles CPU once a response is written, so a background goroutine here
// would stall.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/alerting"
	"sec_ops/internal/application/usecases/analysis"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/enrichment"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// staleAfter marks a "running" scan abandoned by a killed instance as failed,
// so the one-running lock cannot wedge forever.
const staleAfter = 20 * time.Minute

type Service struct {
	logs      interfaces.LogRepository
	batches   interfaces.BatchRepository
	incidents interfaces.IncidentRepository
	scanRuns  interfaces.ScanRunRepository
	analysis  *analysis.Service
	enrich    *enrichment.Service
	alert     *alerting.Service
	audit     *audit.Service
	tx        interfaces.TxManager
	clock     interfaces.Clock
	log       *slog.Logger

	window          time.Duration
	maxBatches      int
	maxLogsPerBatch int
	maxAttempts     int
	suppressionDays int
	dashboardURL    string
}

type Config struct {
	Window          time.Duration // how far back to look for unanalyzed logs
	MaxBatches      int
	MaxLogsPerBatch int
	MaxAttempts     int
	SuppressionDays int
	DashboardURL    string
}

func NewService(logs interfaces.LogRepository, batches interfaces.BatchRepository, incidents interfaces.IncidentRepository,
	scanRuns interfaces.ScanRunRepository, analysisSvc *analysis.Service, enrich *enrichment.Service, alert *alerting.Service,
	auditSvc *audit.Service, tx interfaces.TxManager, clock interfaces.Clock, log *slog.Logger, cfg Config) *Service {
	if cfg.Window <= 0 {
		cfg.Window = 24 * time.Hour
	}
	if cfg.MaxBatches <= 0 {
		cfg.MaxBatches = 3
	}
	if cfg.MaxLogsPerBatch <= 0 {
		cfg.MaxLogsPerBatch = 500
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.SuppressionDays <= 0 {
		cfg.SuppressionDays = 7
	}
	return &Service{
		logs: logs, batches: batches, incidents: incidents, scanRuns: scanRuns, analysis: analysisSvc, enrich: enrich,
		alert: alert, audit: auditSvc, tx: tx, clock: clock, log: log,
		window: cfg.Window, maxBatches: cfg.MaxBatches, maxLogsPerBatch: cfg.MaxLogsPerBatch,
		maxAttempts: cfg.MaxAttempts, suppressionDays: cfg.SuppressionDays, dashboardURL: cfg.DashboardURL,
	}
}

// Run executes one scan. trigger/actor identify who/what started it.
func (s *Service) Run(ctx context.Context, trigger entities.ScanTrigger, actor string) (*dtos.ScanResult, error) {
	now := s.clock.Now().UTC()

	// Best-effort: free a lock abandoned by a crashed instance before trying
	// to take it ourselves. Failure here is not fatal to the attempt.
	if _, err := s.scanRuns.FailStale(ctx, now.Add(-staleAfter)); err != nil {
		s.log.Warn("failed to clear stale scan runs", "error", err)
	}

	run := &entities.ScanRun{Trigger: trigger, Actor: actor, StartedAt: now}
	if err := s.scanRuns.Start(ctx, run); err != nil {
		if errors.Is(err, interfaces.ErrConflict) {
			return nil, fmt.Errorf("%w: a scan is already running", interfaces.ErrConflict)
		}
		return nil, err
	}

	result, runErr := s.execute(ctx, run)
	run.FinishedAt = ptrTime(s.clock.Now().UTC())
	if runErr != nil {
		run.Status, run.Error = entities.ScanFailed, safeErrText(runErr)
	} else {
		run.Status = entities.ScanSucceeded
		run.LogsFetched, run.Analyzed, run.NewAlerts = result.LogsFetched, result.Analyzed, result.NewAlerts
	}
	if ferr := s.scanRuns.Finish(ctx, run); ferr != nil {
		s.log.Error("failed to finalize scan run", "scan_run_id", run.ID, "error", ferr)
	}

	action, details := enums.AuditScheduledScan, "Scheduled scan completed."
	if runErr != nil {
		action, details = enums.AuditScanFailed, "Scheduled scan failed: "+run.Error
	} else if result != nil {
		details = fmt.Sprintf("Scan completed: %d logs fetched, %d analyzed, %d new alerts, %d incidents, %d deferred, %d suppressed.",
			result.LogsFetched, result.Analyzed, result.NewAlerts, result.Incidents, result.Deferred, result.Suppressed)
	}
	if aerr := s.audit.Record(ctx, audit.Event{
		Actor: entities.Principal{UserID: actorOrSystem(actor)}, Action: action, EntityType: "scan_run", EntityID: run.ID, Details: details,
	}); aerr != nil {
		s.log.Error("failed to audit scan completion", "scan_run_id", run.ID, "error", aerr)
	}

	if runErr != nil {
		return nil, runErr
	}
	result.ScanID = run.ID
	result.ExecutedAt = *run.FinishedAt
	result.Status = string(run.Status)
	return result, nil
}

func (s *Service) execute(ctx context.Context, run *entities.ScanRun) (*dtos.ScanResult, error) {
	res := &dtos.ScanResult{}
	since := s.clock.Now().UTC().Add(-s.window)

	flagged, err := s.logs.UnanalyzedFlagged(ctx, since, s.maxLogsPerBatch*s.maxBatches)
	if err != nil {
		return nil, err
	}
	res.LogsFetched = len(flagged)
	batches := chunk(flagged, s.maxLogsPerBatch, s.maxBatches)

	for _, logs := range batches {
		if err := s.processBatch(ctx, run.ID, logs, res); err != nil {
			// A failed/deferred batch does not abort the scan; other batches
			// and retryable ones still get a chance.
			s.log.Warn("batch analysis failed", "scan_run_id", run.ID, "error", err)
		}
	}

	retryable, err := s.batches.Retryable(ctx, s.maxAttempts, s.maxBatches)
	if err != nil {
		return nil, err
	}
	for _, b := range retryable {
		if err := s.retryBatch(ctx, run.ID, b, res); err != nil {
			s.log.Warn("batch retry failed", "batch_id", b.ID, "error", err)
		}
	}
	return res, nil
}

// chunk splits logs into at most maxBatches groups of up to maxPerBatch.
// Remaining logs beyond the cap are left unanalyzed and picked up by the
// next scan (their log_id is not yet linked to any batch).
func chunk(logs []entities.RawLog, maxPerBatch, maxBatches int) [][]entities.RawLog {
	var out [][]entities.RawLog
	for i := 0; i < len(logs) && len(out) < maxBatches; i += maxPerBatch {
		end := min(i+maxPerBatch, len(logs))
		out = append(out, logs[i:end])
	}
	return out
}

func (s *Service) processBatch(ctx context.Context, scanRunID string, logs []entities.RawLog, res *dtos.ScanResult) error {
	windowStart, windowEnd := windowOf(logs)
	userIDs := userIDsOf(logs)

	successLogins, err := s.logs.SuccessfulLoginsForUsers(ctx, userIDs, windowStart.Add(-s.window), windowEnd, 2000)
	if err != nil {
		return err
	}
	outcome, agg, analyzeErr := s.analysis.Analyze(ctx, logs, successLogins, windowStart, windowEnd)

	logIDs := make([]string, len(logs))
	for i, l := range logs {
		logIDs[i] = l.LogID
	}
	batch := &entities.AnalysisBatch{ScanRunID: scanRunID, WindowStart: windowStart, WindowEnd: windowEnd, Model: "", Attempts: 1}

	if analyzeErr != nil {
		deferable := errors.Is(analyzeErr, interfaces.ErrQuotaExceeded) || errors.Is(analyzeErr, interfaces.ErrUpstreamUnavailable)
		if deferable {
			batch.Status, batch.Error = entities.BatchDeferred, safeErrText(analyzeErr)
		} else {
			batch.Status, batch.Error = entities.BatchFailed, safeErrText(analyzeErr)
		}
		return s.tx.WithinTx(ctx, func(ctx context.Context) error {
			if err := s.batches.Create(ctx, batch, logIDs); err != nil {
				return err
			}
			return s.audit.Record(ctx, audit.Event{
				Actor: entities.SystemPrincipal, Action: enums.AuditAIAnalysisDeferred, EntityType: "analysis_batch", EntityID: batch.ID,
				Details: fmt.Sprintf("Batch of %d logs deferred/failed: %s", len(logs), batch.Error),
			})
		})
	}

	batch.Status = entities.BatchDone
	batch.RiskScore, batch.Summary, batch.RecommendedAction = outcome.RiskScore, outcome.Summary, outcome.RecommendedAction
	batch.SuspiciousIPs, batch.Patterns, batch.AffectedUsers = outcome.SuspiciousIPs, outcome.Patterns, outcome.AffectedUsers
	batch.RawResponse, batch.TopIP = outcome.RawResponse, topIP(agg)
	t := s.clock.Now().UTC()
	batch.AnalyzedAt = &t

	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.batches.Create(ctx, batch, logIDs); err != nil {
			return err
		}
		res.Analyzed += len(logs)
		if err := s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditAIAnalysis, EntityType: "analysis_batch", EntityID: batch.ID,
			Details:  fmt.Sprintf("Analyzed %d logs: risk=%s.", len(logs), batch.RiskScore),
			Metadata: map[string]string{"risk_score": string(batch.RiskScore)},
		}); err != nil {
			return err
		}
		return s.handleOutcome(ctx, batch, outcome, res)
	})
}

// retryBatch re-runs analysis for a previously deferred/failed batch, using
// the logs already linked to it (they cannot be re-linked elsewhere).
func (s *Service) retryBatch(ctx context.Context, scanRunID string, b entities.AnalysisBatch, res *dtos.ScanResult) error {
	logs, err := s.logs.ByBatch(ctx, b.ID)
	if err != nil {
		return err
	}
	if len(logs) == 0 {
		return nil
	}
	userIDs := userIDsOf(logs)
	successLogins, err := s.logs.SuccessfulLoginsForUsers(ctx, userIDs, b.WindowStart.Add(-s.window), b.WindowEnd, 2000)
	if err != nil {
		return err
	}
	outcome, agg, analyzeErr := s.analysis.Analyze(ctx, logs, successLogins, b.WindowStart, b.WindowEnd)
	b.ScanRunID, b.Attempts = scanRunID, b.Attempts+1

	if analyzeErr != nil {
		if b.Attempts >= s.maxAttempts {
			b.Status = entities.BatchFailed
		} else {
			b.Status = entities.BatchDeferred
		}
		b.Error = safeErrText(analyzeErr)
		return s.tx.WithinTx(ctx, func(ctx context.Context) error { return s.batches.Update(ctx, &b) })
	}

	b.Status = entities.BatchDone
	b.RiskScore, b.Summary, b.RecommendedAction = outcome.RiskScore, outcome.Summary, outcome.RecommendedAction
	b.SuspiciousIPs, b.Patterns, b.AffectedUsers = outcome.SuspiciousIPs, outcome.Patterns, outcome.AffectedUsers
	b.RawResponse, b.TopIP, b.Error = outcome.RawResponse, topIP(agg), ""
	t := s.clock.Now().UTC()
	b.AnalyzedAt = &t

	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.batches.Update(ctx, &b); err != nil {
			return err
		}
		res.Analyzed += len(logs)
		return s.handleOutcome(ctx, &b, outcome, res)
	})
}

// handleOutcome creates/suppresses an incident for a Medium+ outcome,
// enriches via AbuseIPDB on High+, and dispatches an alert. Called inside the
// batch's transaction.
func (s *Service) handleOutcome(ctx context.Context, batch *entities.AnalysisBatch, outcome *analysis.Outcome, res *dtos.ScanResult) error {
	if !outcome.RiskScore.RequiresAlert() {
		return nil
	}
	fp := entities.IncidentFingerprint(outcome.Patterns, outcome.SuspiciousIPs, outcome.AffectedUsers)

	if open, err := s.incidents.FindOpenByFingerprint(ctx, fp); err == nil {
		// Same ongoing threat: do not create a duplicate or re-alert.
		_ = open
		return s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditAlertSuppressed, EntityType: "incident", EntityID: open.ID,
			Details: "Matching open incident already exists; not re-alerting.",
		})
	} else if !errors.Is(err, interfaces.ErrNotFound) {
		return err
	}

	if last, err := s.incidents.LastResolvedByFingerprint(ctx, fp); err == nil {
		if s.clock.Now().UTC().Sub(*last.ResolvedAt) < time.Duration(s.suppressionDays)*24*time.Hour {
			res.Suppressed++
			return s.audit.Record(ctx, audit.Event{
				Actor: entities.SystemPrincipal, Action: enums.AuditAlertSuppressed, EntityType: "incident", EntityID: last.ID,
				Details: fmt.Sprintf("Fingerprint resolved within the last %d days; suppressing re-alert.", s.suppressionDays),
			})
		}
	} else if !errors.Is(err, interfaces.ErrNotFound) {
		return err
	}

	finalRisk := outcome.RiskScore
	confidence := 0
	if outcome.RiskScore.AtLeast(enums.RiskHigh) && len(outcome.SuspiciousIPs) > 0 {
		_, maxConf, escalate, err := s.enrich.CheckIPs(ctx, outcome.SuspiciousIPs)
		if err != nil {
			return err
		}
		confidence = maxConf
		if escalate {
			finalRisk = enums.RiskCritical
		}
		if err := s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditThreatIntelLookup, EntityType: "analysis_batch", EntityID: batch.ID,
			Details:  fmt.Sprintf("AbuseIPDB max confidence %d%% across %d IP(s).", maxConf, len(outcome.SuspiciousIPs)),
			Metadata: map[string]string{"max_confidence": fmt.Sprint(maxConf)},
		}); err != nil {
			return err
		}
	}

	inc := &entities.Incident{
		BatchID: batch.ID, Fingerprint: fp, AIRiskScore: outcome.RiskScore, RiskScore: finalRisk,
		AISummary: outcome.Summary, RecommendedAction: outcome.RecommendedAction, SuspiciousIPs: outcome.SuspiciousIPs,
		Patterns: outcome.Patterns, AffectedUsers: outcome.AffectedUsers, TopIP: batch.TopIP, AbuseIPDBConfidence: confidence,
	}
	if err := s.incidents.Create(ctx, inc); err != nil {
		if errors.Is(err, interfaces.ErrConflict) {
			// Lost a race with another path creating the same open fingerprint.
			return s.audit.Record(ctx, audit.Event{
				Actor: entities.SystemPrincipal, Action: enums.AuditAlertSuppressed, EntityType: "analysis_batch", EntityID: batch.ID,
				Details: "Concurrent incident with the same fingerprint already exists.",
			})
		}
		return err
	}
	res.Incidents++
	if finalRisk != outcome.RiskScore {
		if err := s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditIncidentEscalated, EntityType: "incident", EntityID: inc.ID,
			Details: fmt.Sprintf("Escalated from %s to %s based on threat intelligence.", outcome.RiskScore, finalRisk),
		}); err != nil {
			return err
		}
	}
	if err := s.audit.Record(ctx, audit.Event{
		Actor: entities.SystemPrincipal, Action: enums.AuditIncidentCreated, EntityType: "incident", EntityID: inc.ID,
		Details: fmt.Sprintf("Incident created: risk=%s.", finalRisk),
	}); err != nil {
		return err
	}

	var scorePtr *int
	if confidence > 0 || len(outcome.SuspiciousIPs) > 0 {
		scorePtr = &confidence
	}
	link := ""
	if s.dashboardURL != "" {
		link = s.dashboardURL + "/incidents?id=" + inc.ID
	}
	sent, err := s.alert.Dispatch(ctx, interfaces.AlertMessage{
		IncidentID: inc.ID, Timestamp: s.clock.Now().UTC(), RiskScore: finalRisk, Summary: outcome.Summary,
		AbuseIPDBScore: scorePtr, RecommendedAction: outcome.RecommendedAction, TopIP: batch.TopIP, Link: link,
	})
	if err != nil {
		return err
	}
	res.NewAlerts += sent
	return nil
}

func windowOf(logs []entities.RawLog) (time.Time, time.Time) {
	if len(logs) == 0 {
		now := time.Now().UTC()
		return now, now
	}
	start, end := logs[0].Timestamp, logs[0].Timestamp
	for _, l := range logs[1:] {
		if l.Timestamp.Before(start) {
			start = l.Timestamp
		}
		if l.Timestamp.After(end) {
			end = l.Timestamp
		}
	}
	return start, end
}

func userIDsOf(logs []entities.RawLog) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range logs {
		if !seen[l.UserID] {
			seen[l.UserID] = true
			out = append(out, l.UserID)
		}
	}
	return out
}

func topIP(agg analysis.Aggregate) string {
	top := ""
	best := -1
	for _, c := range agg.FailuresByIP {
		if c.Count > best {
			best, top = c.Count, c.IP
		}
	}
	for _, c := range agg.EscalationsByIP {
		if c.Count > best {
			best, top = c.Count, c.IP
		}
	}
	return top
}

// RunsService lists past scan runs for GET /scan/runs (FR-SEC-003 observability).
type RunsService struct {
	repo  interfaces.ScanRunRepository
	limit int
}

func NewRunsService(repo interfaces.ScanRunRepository, limit int) *RunsService {
	if limit <= 0 {
		limit = 20
	}
	return &RunsService{repo: repo, limit: limit}
}

func (s *RunsService) List(ctx context.Context) ([]dtos.ScanRun, error) {
	runs, err := s.repo.List(ctx, s.limit)
	if err != nil {
		return nil, err
	}
	out := make([]dtos.ScanRun, len(runs))
	for i, r := range runs {
		out[i] = dtos.ToScanRun(r)
	}
	return out, nil
}

func ptrTime(t time.Time) *time.Time { return &t }

func actorOrSystem(a string) string {
	if a == "" {
		return enums.SystemActor
	}
	return a
}

// safeErrText returns a bounded, logged-safe error summary for storage. It
// never includes secrets because upstream adapters are required to strip
// them before returning an error (webhooks, Gemini, AbuseIPDB).
func safeErrText(err error) string {
	s := err.Error()
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
