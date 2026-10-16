// Package ingest implements log ingestion, mock generation and log browsing
// (FR-SEC-001).
package ingest

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

const (
	MaxBatch      = 1000
	maxMockCount  = 500
	maxFutureSkew = 5 * time.Minute
	maxPast       = 90 * 24 * time.Hour
)

var logIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

type Service struct {
	logs  interfaces.LogRepository
	gen   interfaces.MockLogGenerator
	audit *audit.Service
	tx    interfaces.TxManager
	clock interfaces.Clock
	// validScenario reports whether a mock scenario name exists.
	validScenario func(string) bool
}

func NewService(logs interfaces.LogRepository, gen interfaces.MockLogGenerator, validScenario func(string) bool,
	auditSvc *audit.Service, tx interfaces.TxManager, clock interfaces.Clock) *Service {
	return &Service{logs: logs, gen: gen, validScenario: validScenario, audit: auditSvc, tx: tx, clock: clock}
}

// Ingest validates and stores a batch. Invalid entries are rejected
// individually (reported back) rather than failing the batch; duplicates by
// log_id are skipped so re-sending a batch is safe.
func (s *Service) Ingest(ctx context.Context, p entities.Principal, in []dtos.IngestLog) (*dtos.IngestResult, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: logs must not be empty", interfaces.ErrValidation)
	}
	if len(in) > MaxBatch {
		return nil, fmt.Errorf("%w: at most %d logs per request", interfaces.ErrValidation, MaxBatch)
	}
	now := s.clock.Now().UTC()
	res := &dtos.IngestResult{Received: len(in), Rejected: []dtos.IngestError{}}
	valid := make([]entities.RawLog, 0, len(in))
	seen := map[string]bool{}
	for i, l := range in {
		entry, err := normalize(l, now)
		if err == nil && seen[entry.LogID] {
			err = fmt.Errorf("duplicate log_id in request")
		}
		if err != nil {
			res.Rejected = append(res.Rejected, dtos.IngestError{Index: i, LogID: truncate(l.LogID, 128), Reason: err.Error()})
			continue
		}
		seen[entry.LogID] = true
		valid = append(valid, entry)
	}
	return res, s.store(ctx, p, valid, res, "api")
}

// GenerateMock creates and ingests synthetic logs for a scenario.
func (s *Service) GenerateMock(ctx context.Context, p entities.Principal, req dtos.MockLogsRequest) (*dtos.IngestResult, error) {
	scenario := req.Scenario
	if scenario == "" {
		scenario = "mixed"
	}
	if !s.validScenario(scenario) {
		return nil, fmt.Errorf("%w: unknown scenario %q", interfaces.ErrValidation, scenario)
	}
	count := req.Count
	if count <= 0 {
		count = 100
	}
	if count > maxMockCount {
		return nil, fmt.Errorf("%w: count must be at most %d", interfaces.ErrValidation, maxMockCount)
	}
	if len(req.AttackerIPs) > 10 {
		return nil, fmt.Errorf("%w: at most 10 attacker_ips", interfaces.ErrValidation)
	}
	ips := make([]string, 0, len(req.AttackerIPs))
	for _, raw := range req.AttackerIPs {
		a, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid attacker IP %q", interfaces.ErrValidation, raw)
		}
		ips = append(ips, a.Unmap().String())
	}
	generated := s.gen.Generate(scenario, count, ips)
	for i := range generated {
		generated[i].Flagged = generated[i].Action.RequiresReview()
	}
	res := &dtos.IngestResult{Received: len(generated), Rejected: []dtos.IngestError{}}
	return res, s.store(ctx, p, generated, res, "mock:"+scenario)
}

func (s *Service) store(ctx context.Context, p entities.Principal, logs []entities.RawLog, res *dtos.IngestResult, source string) error {
	for _, l := range logs {
		if l.Flagged {
			res.Flagged++
		}
	}
	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		n, err := s.logs.InsertMany(ctx, logs)
		if err != nil {
			return err
		}
		res.Inserted = n
		res.Duplicates = len(logs) - n
		return s.audit.Record(ctx, audit.Event{
			Actor: p, Action: enums.AuditLogsIngested, EntityType: "raw_logs",
			Details: fmt.Sprintf("Ingested %d logs (%d duplicates skipped, %d rejected, %d flagged for AI review) via %s.",
				res.Inserted, res.Duplicates, len(res.Rejected), res.Flagged, source),
			Metadata: map[string]string{"source": source, "inserted": fmt.Sprint(res.Inserted)},
		})
	})
}

func normalize(l dtos.IngestLog, now time.Time) (entities.RawLog, error) {
	var zero entities.RawLog
	id := strings.TrimSpace(l.LogID)
	if !logIDPattern.MatchString(id) {
		return zero, fmt.Errorf("log_id must be 1-128 chars of [A-Za-z0-9._:-]")
	}
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(l.Timestamp))
	if err != nil {
		return zero, fmt.Errorf("timestamp must be RFC 3339")
	}
	ts = ts.UTC()
	if ts.After(now.Add(maxFutureSkew)) || ts.Before(now.Add(-maxPast)) {
		return zero, fmt.Errorf("timestamp must be within the last 90 days")
	}
	user := strings.TrimSpace(l.UserID)
	if user == "" || utf8.RuneCountInString(user) > 256 {
		return zero, fmt.Errorf("user_id is required (max 256 chars)")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(l.IPAddress))
	if err != nil {
		return zero, fmt.Errorf("ip_address must be a valid IPv4 or IPv6 address")
	}
	action, err := enums.ParseLogAction(strings.TrimSpace(l.Action))
	if err != nil {
		return zero, fmt.Errorf("action must be one of Login Success, Login Failed, Privilege Escalation")
	}
	return entities.RawLog{
		LogID: id, Timestamp: ts, UserID: user, IPAddress: addr.Unmap().WithZone("").String(),
		Country: truncate(clean(l.Country), 100), City: truncate(clean(l.City), 100), Action: action,
		UserAgent: truncate(clean(l.UserAgent), 1024),
		// Server-derived; never taken from the client.
		Flagged: action.RequiresReview(),
	}, nil
}

// clean strips control characters so log fields cannot inject terminal
// escapes or break prompt delimiters later.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// ----------------------------------------------------------------- browsing

func (s *Service) List(ctx context.Context, q dtos.LogListQuery) (*dtos.LogPage, error) {
	page := max(q.Page, 1)
	size := q.PageSize
	if size <= 0 {
		size = 12
	}
	if size > 200 {
		size = 200
	}
	lq := interfaces.LogQuery{Search: truncate(q.Search, 100), Limit: size, Offset: (page - 1) * size}
	if q.Action != "" && q.Action != "All" {
		a, err := enums.ParseLogAction(q.Action)
		if err != nil {
			return nil, fmt.Errorf("%w: unknown action", interfaces.ErrValidation)
		}
		lq.Actions = []enums.LogAction{a}
	}
	if q.Country != "" && q.Country != "All" {
		lq.Countries = []string{truncate(q.Country, 100)}
	}
	if lq.Offset > 100000 {
		return nil, fmt.Errorf("%w: page too large", interfaces.ErrValidation)
	}
	rows, total, err := s.logs.List(ctx, lq)
	if err != nil {
		return nil, err
	}
	out := &dtos.LogPage{Rows: make([]dtos.LogEntry, len(rows)), Total: total, Page: page, PageSize: size}
	for i, r := range rows {
		out.Rows[i] = dtos.ToLogEntry(r)
	}
	return out, nil
}

func (s *Service) Countries(ctx context.Context) ([]string, error) {
	c, err := s.logs.Countries(ctx)
	if c == nil {
		c = []string{}
	}
	return c, err
}
