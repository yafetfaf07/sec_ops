// Package testfakes provides hand-written fake implementations of domain
// interfaces for use-case tests. They are in-memory, deterministic, and
// thread-unsafe (tests run sequentially by default).
package testfakes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// FixedClock always returns the same time.
type FixedClock struct {
	T time.Time
}

func (c *FixedClock) Now() time.Time { return c.T }

// TxManager is a pass-through: no real transaction, but fn is called.
type TxManager struct{}

func (t *TxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// LogRepository stores logs in memory.
type LogRepository struct {
	logs      []entities.RawLog
	batchLogs map[string][]string // batchID -> []logID
	mu        sync.Mutex
}

func NewLogRepository() *LogRepository {
	return &LogRepository{batchLogs: make(map[string][]string)}
}

func (r *LogRepository) InsertMany(ctx context.Context, logs []entities.RawLog) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inserted := 0
	for _, l := range logs {
		found := false
		for _, existing := range r.logs {
			if existing.LogID == l.LogID {
				found = true
				break
			}
		}
		if !found {
			r.logs = append(r.logs, l)
			inserted++
		}
	}
	return inserted, nil
}

func (r *LogRepository) List(ctx context.Context, q interfaces.LogQuery) ([]entities.RawLog, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.RawLog
	for _, l := range r.logs {
		if !matchesLogQuery(l, q) {
			continue
		}
		out = append(out, l)
	}
	total := len(out)
	if q.Offset >= len(out) {
		return nil, total, nil
	}
	out = out[q.Offset:]
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, total, nil
}

func matchesLogQuery(l entities.RawLog, q interfaces.LogQuery) bool {
	if len(q.Actions) > 0 {
		found := false
		for _, a := range q.Actions {
			if l.Action == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(q.Countries) > 0 {
		found := false
		for _, c := range q.Countries {
			if l.Country == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if q.Since != nil && l.Timestamp.Before(*q.Since) {
		return false
	}
	if q.Until != nil && l.Timestamp.After(*q.Until) {
		return false
	}
	if q.FlaggedOnly && !l.Flagged {
		return false
	}
	return true
}

func (r *LogRepository) Countries(ctx context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]bool)
	for _, l := range r.logs {
		if l.Country != "" {
			seen[l.Country] = true
		}
	}
	var out []string
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

func (r *LogRepository) UnanalyzedFlagged(ctx context.Context, since time.Time, limit int) ([]entities.RawLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	analyzed := make(map[string]bool)
	for _, ids := range r.batchLogs {
		for _, id := range ids {
			analyzed[id] = true
		}
	}
	var out []entities.RawLog
	for _, l := range r.logs {
		if l.Flagged && !l.Timestamp.Before(since) && !analyzed[l.LogID] {
			out = append(out, l)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *LogRepository) CountUnanalyzedFlagged(ctx context.Context, since time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	analyzed := make(map[string]bool)
	for _, ids := range r.batchLogs {
		for _, id := range ids {
			analyzed[id] = true
		}
	}
	count := 0
	for _, l := range r.logs {
		if l.Flagged && !l.Timestamp.Before(since) && !analyzed[l.LogID] {
			count++
		}
	}
	return count, nil
}

func (r *LogRepository) SuccessfulLoginsForUsers(ctx context.Context, userIDs []string, from, to time.Time, limit int) ([]entities.RawLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	userSet := make(map[string]bool)
	for _, u := range userIDs {
		userSet[u] = true
	}
	var out []entities.RawLog
	for _, l := range r.logs {
		if l.Action == enums.ActionLoginSuccess && userSet[l.UserID] && !l.Timestamp.Before(from) && !l.Timestamp.After(to) {
			out = append(out, l)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *LogRepository) ByBatch(ctx context.Context, batchID string) ([]entities.RawLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids, ok := r.batchLogs[batchID]
	if !ok {
		return nil, nil
	}
	logMap := make(map[string]entities.RawLog)
	for _, l := range r.logs {
		logMap[l.LogID] = l
	}
	var out []entities.RawLog
	for _, id := range ids {
		if l, ok := logMap[id]; ok {
			out = append(out, l)
		}
	}
	return out, nil
}

func (r *LogRepository) CountIngestedSince(ctx context.Context, t time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, l := range r.logs {
		if !l.IngestedAt.Before(t) {
			count++
		}
	}
	return count, nil
}

func (r *LogRepository) CountFlaggedSince(ctx context.Context, t time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, l := range r.logs {
		if l.Flagged && !l.IngestedAt.Before(t) {
			count++
		}
	}
	return count, nil
}

func (r *LogRepository) CountAnalyzedSince(ctx context.Context, t time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	analyzed := make(map[string]bool)
	for _, ids := range r.batchLogs {
		for _, id := range ids {
			analyzed[id] = true
		}
	}
	count := 0
	for _, l := range r.logs {
		if analyzed[l.LogID] && !l.IngestedAt.Before(t) {
			count++
		}
	}
	return count, nil
}

func (r *LogRepository) LinkBatch(batchID string, logIDs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batchLogs[batchID] = append(r.batchLogs[batchID], logIDs...)
}

// BatchRepository stores batches in memory.
type BatchRepository struct {
	batches map[string]*entities.AnalysisBatch
	logs    *LogRepository
	mu      sync.Mutex
}

func NewBatchRepository(logs *LogRepository) *BatchRepository {
	return &BatchRepository{batches: make(map[string]*entities.AnalysisBatch), logs: logs}
}

func (r *BatchRepository) Create(ctx context.Context, b *entities.AnalysisBatch, logIDs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b.ID == "" {
		b.ID = fmt.Sprintf("batch-%d", len(r.batches)+1)
	}
	r.batches[b.ID] = b
	r.logs.LinkBatch(b.ID, logIDs)
	return nil
}

func (r *BatchRepository) Update(ctx context.Context, b *entities.AnalysisBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.batches[b.ID]; !ok {
		return interfaces.ErrNotFound
	}
	r.batches[b.ID] = b
	return nil
}

func (r *BatchRepository) Retryable(ctx context.Context, maxAttempts, limit int) ([]entities.AnalysisBatch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.AnalysisBatch
	for _, b := range r.batches {
		if (b.Status == entities.BatchDeferred || b.Status == entities.BatchFailed) && b.Attempts < maxAttempts {
			out = append(out, *b)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// IncidentRepository stores incidents in memory.
type IncidentRepository struct {
	incidents map[string]*entities.Incident
	mu        sync.Mutex
}

func NewIncidentRepository() *IncidentRepository {
	return &IncidentRepository{incidents: make(map[string]*entities.Incident)}
}

func (r *IncidentRepository) Create(ctx context.Context, inc *entities.Incident) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if inc.ID == "" {
		inc.ID = fmt.Sprintf("inc-%d", len(r.incidents)+1)
	}
	// Simulate partial unique index: fingerprint unique WHERE status != 'Resolved'
	for _, existing := range r.incidents {
		if existing.Fingerprint == inc.Fingerprint && existing.Status != enums.StatusResolved {
			return interfaces.ErrConflict
		}
	}
	inc.DetectedAt = time.Now().UTC()
	inc.UpdatedAt = time.Now().UTC()
	if inc.Status == "" {
		inc.Status = enums.StatusOpen
	}
	r.incidents[inc.ID] = inc
	return nil
}

func (r *IncidentRepository) Get(ctx context.Context, id string) (*entities.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inc, ok := r.incidents[id]
	if !ok {
		return nil, interfaces.ErrNotFound
	}
	return inc, nil
}

func (r *IncidentRepository) GetForUpdate(ctx context.Context, id string) (*entities.Incident, error) {
	return r.Get(ctx, id)
}

func (r *IncidentRepository) List(ctx context.Context, q interfaces.IncidentQuery) ([]entities.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.Incident
	for _, inc := range r.incidents {
		if matchesIncidentQuery(*inc, q) {
			out = append(out, *inc)
		}
	}
	return out, nil
}

func matchesIncidentQuery(inc entities.Incident, q interfaces.IncidentQuery) bool {
	if len(q.Statuses) > 0 {
		found := false
		for _, s := range q.Statuses {
			if inc.Status == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(q.Risks) > 0 {
		found := false
		for _, r := range q.Risks {
			if inc.RiskScore == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if q.Since != nil && inc.DetectedAt.Before(*q.Since) {
		return false
	}
	return true
}

func (r *IncidentRepository) FindOpenByFingerprint(ctx context.Context, fp string) (*entities.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inc := range r.incidents {
		if inc.Fingerprint == fp && inc.Status != enums.StatusResolved {
			return inc, nil
		}
	}
	return nil, interfaces.ErrNotFound
}

func (r *IncidentRepository) LastResolvedByFingerprint(ctx context.Context, fp string) (*entities.Incident, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var last *entities.Incident
	for _, inc := range r.incidents {
		if inc.Fingerprint == fp && inc.Status == enums.StatusResolved && inc.ResolvedAt != nil {
			if last == nil || inc.ResolvedAt.After(*last.ResolvedAt) {
				last = inc
			}
		}
	}
	if last == nil {
		return nil, interfaces.ErrNotFound
	}
	return last, nil
}

func (r *IncidentRepository) UpdateStatus(ctx context.Context, inc *entities.Incident) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.incidents[inc.ID]; !ok {
		return interfaces.ErrNotFound
	}
	r.incidents[inc.ID] = inc
	return nil
}

func (r *IncidentRepository) UpdateEnrichment(ctx context.Context, id string, risk enums.RiskLevel, confidence int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inc, ok := r.incidents[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	inc.RiskScore = risk
	inc.AbuseIPDBConfidence = confidence
	return nil
}

func (r *IncidentRepository) AddComment(ctx context.Context, c *entities.IncidentComment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inc, ok := r.incidents[c.IncidentID]
	if !ok {
		return interfaces.ErrNotFound
	}
	if c.ID == "" {
		c.ID = fmt.Sprintf("comment-%d", len(inc.Comments)+1)
	}
	inc.Comments = append(inc.Comments, *c)
	return nil
}

func (r *IncidentRepository) CountActiveByRisk(ctx context.Context) (map[enums.RiskLevel]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := make(map[enums.RiskLevel]int)
	for _, inc := range r.incidents {
		if inc.Status != enums.StatusResolved {
			counts[inc.RiskScore]++
		}
	}
	return counts, nil
}

// SetIncident is a test helper to populate the repository with a specific incident
func (r *IncidentRepository) SetIncident(id string, inc *entities.Incident) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.incidents[id] = inc
}

// ScanRunRepository simulates the advisory lock via a running flag.
type ScanRunRepository struct {
	runs    []*entities.ScanRun
	running bool
	mu      sync.Mutex
}

func NewScanRunRepository() *ScanRunRepository {
	return &ScanRunRepository{}
}

func (r *ScanRunRepository) Start(ctx context.Context, run *entities.ScanRun) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return interfaces.ErrConflict
	}
	if run.ID == "" {
		run.ID = fmt.Sprintf("run-%d", len(r.runs)+1)
	}
	run.Status = entities.ScanRunning
	r.runs = append(r.runs, run)
	r.running = true
	return nil
}

func (r *ScanRunRepository) Finish(ctx context.Context, run *entities.ScanRun) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	for i, existing := range r.runs {
		if existing.ID == run.ID {
			r.runs[i] = run
			return nil
		}
	}
	return interfaces.ErrNotFound
}

func (r *ScanRunRepository) FailStale(ctx context.Context, startedBefore time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, run := range r.runs {
		if run.Status == entities.ScanRunning && run.StartedAt.Before(startedBefore) {
			run.Status = entities.ScanFailed
			run.Error = "stale scan run"
			count++
		}
	}
	if count > 0 {
		r.running = false
	}
	return count, nil
}

func (r *ScanRunRepository) LastFinished(ctx context.Context) (*entities.ScanRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var last *entities.ScanRun
	for _, run := range r.runs {
		if run.FinishedAt != nil {
			if last == nil || run.FinishedAt.After(*last.FinishedAt) {
				last = run
			}
		}
	}
	if last == nil {
		return nil, interfaces.ErrNotFound
	}
	return last, nil
}

func (r *ScanRunRepository) List(ctx context.Context, limit int) ([]entities.ScanRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.ScanRun
	for i := len(r.runs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, *r.runs[i])
	}
	return out, nil
}

// AuditRepository implements hash-chain semantics in memory.
type AuditRepository struct {
	entries []*entities.AuditEntry
	mu      sync.Mutex
}

func NewAuditRepository() *AuditRepository {
	return &AuditRepository{}
}

func (r *AuditRepository) Append(ctx context.Context, e *entities.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.ID = int64(len(r.entries) + 1)
	prevHash := ""
	if len(r.entries) > 0 {
		prevHash = r.entries[len(r.entries)-1].Hash
	}
	e.PrevHash = prevHash
	e.Hash = entities.AuditHash(prevHash, *e)
	r.entries = append(r.entries, e)
	return nil
}

func (r *AuditRepository) List(ctx context.Context, q interfaces.AuditQuery) ([]entities.AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.AuditEntry
	for _, e := range r.entries {
		if matchesAuditQuery(*e, q) {
			out = append(out, *e)
		}
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

func matchesAuditQuery(e entities.AuditEntry, q interfaces.AuditQuery) bool {
	if q.ActionType != "" && string(e.ActionType) != q.ActionType {
		return false
	}
	if q.UserID != "" && e.UserID != q.UserID {
		return false
	}
	if q.Since != nil && e.Timestamp.Before(*q.Since) {
		return false
	}
	if q.Until != nil && e.Timestamp.After(*q.Until) {
		return false
	}
	return true
}

func (r *AuditRepository) Ascending(ctx context.Context, afterID int64, limit int) ([]entities.AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entities.AuditEntry
	for _, e := range r.entries {
		if e.ID > afterID {
			out = append(out, *e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// FindAction is a test helper to find the first entry with a specific action
func (r *AuditRepository) FindAction(action enums.AuditAction) *entities.AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.ActionType == action {
			return e
		}
	}
	return nil
}

// GetAll is a test helper to retrieve all audit entries
func (r *AuditRepository) GetAll() []entities.AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]entities.AuditEntry, len(r.entries))
	for i, e := range r.entries {
		out[i] = *e
	}
	return out
}

// CorruptHash corrupts a stored hash for testing Verify.
func (r *AuditRepository) CorruptHash(id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.ID == id {
			e.Hash = "corrupted"
			return nil
		}
	}
	return errors.New("entry not found")
}

// ScriptedLLM returns scripted JSON responses per call.
type ScriptedLLM struct {
	Responses [][]byte
	Errors    []error
	CallCount int
	mu        sync.Mutex
}

func (l *ScriptedLLM) GenerateJSON(ctx context.Context, req interfaces.JSONGenerationRequest) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.CallCount >= len(l.Responses) {
		return nil, fmt.Errorf("%w: no more scripted responses", interfaces.ErrUpstreamUnavailable)
	}
	idx := l.CallCount
	l.CallCount++
	if l.Errors != nil && idx < len(l.Errors) && l.Errors[idx] != nil {
		return nil, l.Errors[idx]
	}
	return l.Responses[idx], nil
}

func (l *ScriptedLLM) Configured() bool { return true }

// FakeAlertNotifier counts calls.
type FakeAlertNotifier struct {
	CallCount int
	Messages  []interfaces.AlertMessage
	mu        sync.Mutex
}

func (n *FakeAlertNotifier) Channel() string { return "fake" }

func (n *FakeAlertNotifier) Send(ctx context.Context, m interfaces.AlertMessage) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.CallCount++
	n.Messages = append(n.Messages, m)
	return 200, nil
}

// FakeSchedulerControl records calls.
type FakeSchedulerControl struct {
	CallCount int
	LastCall  *SchedulerCall
	mu        sync.Mutex
}

type SchedulerCall struct {
	Enabled  bool
	CronHour int
	Timezone string
}

func (s *FakeSchedulerControl) Configured() bool { return true }

func (s *FakeSchedulerControl) Apply(ctx context.Context, enabled bool, cronHour int, timezone string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CallCount++
	s.LastCall = &SchedulerCall{Enabled: enabled, CronHour: cronHour, Timezone: timezone}
	return nil
}

// SettingsRepository stores settings in memory.
type SettingsRepository struct {
	current *entities.Settings
	mu      sync.Mutex
}

func NewSettingsRepository() *SettingsRepository {
	return &SettingsRepository{}
}

func (r *SettingsRepository) Get(ctx context.Context) (*entities.Settings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return nil, interfaces.ErrNotFound
	}
	return r.current, nil
}

func (r *SettingsRepository) Save(ctx context.Context, s *entities.Settings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.UpdatedAt = time.Now().UTC()
	r.current = s
	return nil
}

// UsageRepository tracks daily budgets in memory.
type UsageRepository struct {
	usage map[string]int
	mu    sync.Mutex
}

func NewUsageRepository() *UsageRepository {
	return &UsageRepository{usage: make(map[string]int)}
}

func (r *UsageRepository) Consume(ctx context.Context, provider string, day time.Time, limit int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := fmt.Sprintf("%s-%s", provider, day.Format("2006-01-02"))
	count := r.usage[key]
	if count >= limit {
		return false, nil
	}
	r.usage[key] = count + 1
	return true, nil
}

// AlertDeliveryRepository stores deliveries in memory.
type AlertDeliveryRepository struct {
	deliveries []entities.AlertDelivery
	mu         sync.Mutex
}

func NewAlertDeliveryRepository() *AlertDeliveryRepository {
	return &AlertDeliveryRepository{}
}

func (r *AlertDeliveryRepository) Insert(ctx context.Context, d *entities.AlertDelivery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d.ID == "" {
		d.ID = fmt.Sprintf("delivery-%d", len(r.deliveries)+1)
	}
	r.deliveries = append(r.deliveries, *d)
	return nil
}

func (r *AlertDeliveryRepository) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.deliveries)
}

// ThreatIntelCache stores threat intel in memory.
type ThreatIntelCache struct {
	cache map[string]*entities.ThreatIntel
	mu    sync.Mutex
}

func NewThreatIntelCache() *ThreatIntelCache {
	return &ThreatIntelCache{cache: make(map[string]*entities.ThreatIntel)}
}

func (c *ThreatIntelCache) Get(ctx context.Context, ip string, now time.Time) (*entities.ThreatIntel, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ti, ok := c.cache[ip]
	if !ok || ti.ExpiresAt.Before(now) {
		return nil, interfaces.ErrNotFound
	}
	return ti, nil
}

func (c *ThreatIntelCache) Put(ctx context.Context, ti *entities.ThreatIntel) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ti.IP] = ti
	return nil
}

// -------------------------------------------------------------------- LLM

type FakeLLM struct {
	Response  []byte
	Err       error
	ConfigOK  bool
	CallCount int
}

func (f *FakeLLM) GenerateJSON(ctx context.Context, req interfaces.JSONGenerationRequest) ([]byte, error) {
	f.CallCount++
	return f.Response, f.Err
}

func (f *FakeLLM) Configured() bool { return f.ConfigOK }

// -------------------------------------------------------------------- UsageRepository

type FakeUsageRepository struct {
	mu       sync.Mutex
	counters map[string]int // key = "provider:YYYY-MM-DD"
}

func NewFakeUsageRepository() *FakeUsageRepository {
	return &FakeUsageRepository{counters: make(map[string]int)}
}

func (f *FakeUsageRepository) Consume(ctx context.Context, provider string, day time.Time, limit int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fmt.Sprintf("%s:%s", provider, day.Format("2006-01-02"))
	count := f.counters[key]
	if count >= limit {
		return false, nil
	}
	f.counters[key] = count + 1
	return true, nil
}

func (f *FakeUsageRepository) GetCount(provider string, day time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fmt.Sprintf("%s:%s", provider, day.Format("2006-01-02"))
	return f.counters[key]
}

// -------------------------------------------------------------------- ThreatIntelClient

type FakeThreatIntelClient struct {
	Results  map[string]*entities.ThreatIntel
	Err      error
	ConfigOK bool
	CallLog  []string
}

func NewFakeThreatIntelClient() *FakeThreatIntelClient {
	return &FakeThreatIntelClient{
		Results: make(map[string]*entities.ThreatIntel),
		CallLog: []string{},
	}
}

func (f *FakeThreatIntelClient) Check(ctx context.Context, ip string) (*entities.ThreatIntel, error) {
	if f.CallLog != nil {
		f.CallLog = append(f.CallLog, ip)
	}
	if f.Err != nil {
		return nil, f.Err
	}
	if ti, ok := f.Results[ip]; ok {
		return ti, nil
	}
	return &entities.ThreatIntel{IP: ip, AbuseConfidence: 0}, nil
}

func (f *FakeThreatIntelClient) Configured() bool { return f.ConfigOK }

// -------------------------------------------------------------------- ThreatIntelCache

type FakeThreatIntelCache struct {
	mu    sync.Mutex
	cache map[string]*entities.ThreatIntel
}

func NewFakeThreatIntelCache() *FakeThreatIntelCache {
	return &FakeThreatIntelCache{cache: make(map[string]*entities.ThreatIntel)}
}

func (f *FakeThreatIntelCache) Get(ctx context.Context, ip string, now time.Time) (*entities.ThreatIntel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ti, ok := f.cache[ip]
	if !ok || ti.ExpiresAt.Before(now) {
		return nil, interfaces.ErrNotFound
	}
	return ti, nil
}

func (f *FakeThreatIntelCache) Put(ctx context.Context, ti *entities.ThreatIntel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache[ti.IP] = ti
	return nil
}

func (f *FakeThreatIntelCache) SetCached(ip string, confidence int, expiresAt time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache[ip] = &entities.ThreatIntel{IP: ip, AbuseConfidence: confidence, ExpiresAt: expiresAt}
}

// -------------------------------------------------------------------- AlertNotifier helpers

// ConfigurableAlertNotifier wraps FakeAlertNotifier to support custom channels and failures
type ConfigurableAlertNotifier struct {
	ChannelName string
	Err         error
	Status      int
	Calls       []interfaces.AlertMessage
}

func (f *ConfigurableAlertNotifier) Channel() string { return f.ChannelName }

func (f *ConfigurableAlertNotifier) Send(ctx context.Context, m interfaces.AlertMessage) (int, error) {
	f.Calls = append(f.Calls, m)
	return f.Status, f.Err
}

// NewSuccessNotifier creates a notifier that always succeeds with 200.
func NewSuccessNotifier(channel string) *ConfigurableAlertNotifier {
	return &ConfigurableAlertNotifier{ChannelName: channel, Status: 200}
}

// NewFailingNotifier creates a notifier that always fails with the given status.
func NewFailingNotifier(channel string, status int) *ConfigurableAlertNotifier {
	return &ConfigurableAlertNotifier{ChannelName: channel, Status: status, Err: errors.New("webhook delivery failed")}
}

// -------------------------------------------------------------------- AlertDeliveryRepository

type FakeAlertDeliveryRepository struct {
	mu         sync.Mutex
	deliveries []*entities.AlertDelivery
}

func (f *FakeAlertDeliveryRepository) Insert(ctx context.Context, d *entities.AlertDelivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries = append(f.deliveries, d)
	return nil
}

func (f *FakeAlertDeliveryRepository) GetAll() []*entities.AlertDelivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*entities.AlertDelivery, len(f.deliveries))
	copy(out, f.deliveries)
	return out
}

// -------------------------------------------------------------------- Helper for building LLM JSON responses

func BuildLLMResponse(riskScore string, summary string, action string, ips []string, patterns []string, users []string) []byte {
	type llmResp struct {
		RiskScore         string   `json:"risk_score"`
		Summary           string   `json:"summary"`
		RecommendedAction string   `json:"recommended_action"`
		SuspiciousIPs     []string `json:"suspicious_ips"`
		Patterns          []string `json:"patterns"`
		AffectedUsers     []string `json:"affected_users"`
	}
	resp := llmResp{
		RiskScore:         riskScore,
		Summary:           summary,
		RecommendedAction: action,
		SuspiciousIPs:     ips,
		Patterns:          patterns,
		AffectedUsers:     users,
	}
	data, _ := json.Marshal(resp)
	return data
}
