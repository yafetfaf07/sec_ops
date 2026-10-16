package enrichment

import (
	"context"
	"testing"
	"time"

	"sec_ops/internal/application/usecases/testfakes"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/interfaces"
)

func TestCheckIPs_SkipsPrivateAddresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"private_10", "10.0.0.1"},
		{"private_192", "192.168.1.1"},
		{"private_172", "172.16.0.1"},
		{"loopback_ipv4", "127.0.0.1"},
		{"loopback_ipv6", "::1"},
		{"link_local", "169.254.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			client := &testfakes.FakeThreatIntelClient{ConfigOK: true, CallLog: []string{}}
			cache := testfakes.NewFakeThreatIntelCache()
			usage := testfakes.NewFakeUsageRepository()

			svc := NewService(client, cache, usage, clock, 100, 50)

			results, _, _, err := svc.CheckIPs(context.Background(), []string{tt.ip})
			if err != nil {
				t.Fatalf("CheckIPs failed: %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}

			if !results[0].Skipped {
				t.Errorf("result.Skipped = false, want true for %s", tt.ip)
			}

			if results[0].Checked {
				t.Errorf("result.Checked = true, want false for %s", tt.ip)
			}

			// Verify client was not called
			if len(client.CallLog) > 0 {
				t.Errorf("client was called %d times, want 0 for private IP", len(client.CallLog))
			}

			// Verify usage was not consumed
			if usage.GetCount("abuseipdb", clock.Now()) > 0 {
				t.Error("usage was consumed for private IP")
			}
		})
	}
}

func TestCheckIPs_SkipsRFC5737DocumentationAddresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"doc_192", "192.0.2.1"},
		{"doc_198", "198.51.100.1"},
		{"doc_203", "203.0.113.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			client := &testfakes.FakeThreatIntelClient{ConfigOK: true, CallLog: []string{}}
			cache := testfakes.NewFakeThreatIntelCache()
			usage := testfakes.NewFakeUsageRepository()

			svc := NewService(client, cache, usage, clock, 100, 50)

			results, _, _, err := svc.CheckIPs(context.Background(), []string{tt.ip})
			if err != nil {
				t.Fatalf("CheckIPs failed: %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}

			if !results[0].Skipped {
				t.Errorf("result.Skipped = false, want true for RFC5737 IP %s", tt.ip)
			}

			// Verify client was not called
			if len(client.CallLog) > 0 {
				t.Errorf("client was called for documentation IP %s", tt.ip)
			}
		})
	}
}

func TestCheckIPs_UsesCacheOnHit(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{ConfigOK: true, CallLog: []string{}}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	// Pre-populate cache with a valid entry
	cache.SetCached("1.2.3.4", 75, clock.Now().Add(24*time.Hour))

	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, escalate, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	result := results[0]
	if !result.FromCache {
		t.Error("result.FromCache = false, want true")
	}
	if !result.Checked {
		t.Error("result.Checked = false, want true")
	}
	if result.Confidence != 75 {
		t.Errorf("result.Confidence = %d, want 75", result.Confidence)
	}
	if maxConf != 75 {
		t.Errorf("maxConfidence = %d, want 75", maxConf)
	}

	// With threshold=50 and confidence=75, should escalate
	if !escalate {
		t.Error("escalate = false, want true (75 > 50)")
	}

	// Verify client was NOT called
	if len(client.CallLog) > 0 {
		t.Errorf("client was called %d times, want 0 (cache hit)", len(client.CallLog))
	}

	// Verify usage was NOT consumed
	if usage.GetCount("abuseipdb", clock.Now()) > 0 {
		t.Error("usage was consumed on cache hit")
	}
}

func TestCheckIPs_EscalatesOnlyWhenConfidenceStrictlyExceedsThreshold(t *testing.T) {
	tests := []struct {
		name       string
		confidence int
		threshold  int
		want       bool
	}{
		{"below", 40, 50, false},
		{"equal", 50, 50, false}, // Must be strictly greater
		{"above", 51, 50, true},
		{"high", 80, 50, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
			cache := testfakes.NewFakeThreatIntelCache()
			usage := testfakes.NewFakeUsageRepository()

			// Set up cache with the test confidence
			cache.SetCached("1.2.3.4", tt.confidence, clock.Now().Add(24*time.Hour))

			client := &testfakes.FakeThreatIntelClient{ConfigOK: true}
			svc := NewService(client, cache, usage, clock, 100, tt.threshold)

			_, _, escalate, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4"})
			if err != nil {
				t.Fatalf("CheckIPs failed: %v", err)
			}

			if escalate != tt.want {
				t.Errorf("escalate = %v, want %v (confidence=%d, threshold=%d)",
					escalate, tt.want, tt.confidence, tt.threshold)
			}
		})
	}
}

func TestCheckIPs_UsageBudgetExhaustedMarksSkipped(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{
		ConfigOK: true,
		CallLog:  []string{},
		Results: map[string]*entities.ThreatIntel{
			"1.2.3.4": {IP: "1.2.3.4", AbuseConfidence: 60},
			"5.6.7.8": {IP: "5.6.7.8", AbuseConfidence: 70},
		},
	}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	// Budget of 1 - first IP will consume it, second should be skipped
	svc := NewService(client, cache, usage, clock, 1, 50)

	results, maxConf, _, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	// First IP should succeed
	if results[0].Skipped {
		t.Error("results[0].Skipped = true, want false")
	}
	if !results[0].Checked {
		t.Error("results[0].Checked = false, want true")
	}
	if results[0].Confidence != 60 {
		t.Errorf("results[0].Confidence = %d, want 60", results[0].Confidence)
	}

	// Second IP should be skipped (budget exhausted)
	if !results[1].Skipped {
		t.Error("results[1].Skipped = false, want true (budget exhausted)")
	}
	if results[1].Checked {
		t.Error("results[1].Checked = true, want false (budget exhausted)")
	}

	// Max confidence should be from the first IP only
	if maxConf != 60 {
		t.Errorf("maxConfidence = %d, want 60", maxConf)
	}

	// Verify only one client call was made
	if len(client.CallLog) != 1 {
		t.Errorf("client call count = %d, want 1", len(client.CallLog))
	}
}

func TestCheckIPs_CallsClientOnCacheMiss(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{
		ConfigOK: true,
		CallLog:  []string{},
		Results: map[string]*entities.ThreatIntel{
			"1.2.3.4": {
				IP:              "1.2.3.4",
				AbuseConfidence: 85,
				TotalReports:    100,
				Country:         "CN",
				FetchedAt:       clock.Now(),
				ExpiresAt:       clock.Now().Add(24 * time.Hour),
			},
		},
	}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, escalate, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	result := results[0]
	if result.FromCache {
		t.Error("result.FromCache = true, want false (cache miss)")
	}
	if !result.Checked {
		t.Error("result.Checked = false, want true")
	}
	if result.Confidence != 85 {
		t.Errorf("result.Confidence = %d, want 85", result.Confidence)
	}
	if maxConf != 85 {
		t.Errorf("maxConfidence = %d, want 85", maxConf)
	}
	if !escalate {
		t.Error("escalate = false, want true (85 > 50)")
	}

	// Verify client was called
	if len(client.CallLog) != 1 || client.CallLog[0] != "1.2.3.4" {
		t.Errorf("client.CallLog = %v, want [1.2.3.4]", client.CallLog)
	}

	// Verify usage was consumed
	if usage.GetCount("abuseipdb", clock.Now()) != 1 {
		t.Errorf("usage count = %d, want 1", usage.GetCount("abuseipdb", clock.Now()))
	}

	// Verify result was cached
	cached, err := cache.Get(context.Background(), "1.2.3.4", clock.Now())
	if err != nil {
		t.Fatalf("cache.Get failed after Put: %v", err)
	}
	if cached.AbuseConfidence != 85 {
		t.Errorf("cached confidence = %d, want 85", cached.AbuseConfidence)
	}
}

func TestCheckIPs_DisabledServiceSkipsAll(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{ConfigOK: false, CallLog: []string{}} // Not configured
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, escalate, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	// All should be skipped
	for i, r := range results {
		if !r.Skipped {
			t.Errorf("results[%d].Skipped = false, want true (service disabled)", i)
		}
		if r.Checked {
			t.Errorf("results[%d].Checked = true, want false (service disabled)", i)
		}
	}

	if maxConf != 0 {
		t.Errorf("maxConfidence = %d, want 0", maxConf)
	}
	if escalate {
		t.Error("escalate = true, want false (service disabled)")
	}

	// Verify client was not called
	if len(client.CallLog) > 0 {
		t.Errorf("client was called when disabled")
	}
}

func TestCheckIPs_MultipleIPs_ReturnsMaxConfidence(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	// Pre-populate cache with different confidences
	cache.SetCached("1.2.3.4", 30, clock.Now().Add(24*time.Hour))
	cache.SetCached("5.6.7.8", 90, clock.Now().Add(24*time.Hour))
	cache.SetCached("9.9.9.9", 45, clock.Now().Add(24*time.Hour))

	client := &testfakes.FakeThreatIntelClient{ConfigOK: true}
	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, escalate, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}

	// Max should be 90
	if maxConf != 90 {
		t.Errorf("maxConfidence = %d, want 90", maxConf)
	}

	// Should escalate because 90 > 50
	if !escalate {
		t.Error("escalate = false, want true (90 > 50)")
	}
}

func TestCheckIPs_InvalidIPSkipped(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{ConfigOK: true, CallLog: []string{}}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	svc := NewService(client, cache, usage, clock, 100, 50)

	results, _, _, err := svc.CheckIPs(context.Background(), []string{"not-an-ip"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	if !results[0].Skipped {
		t.Error("result.Skipped = false, want true for invalid IP")
	}

	// Client should not be called
	if len(client.CallLog) > 0 {
		t.Error("client was called for invalid IP")
	}
}

func TestCheckIPs_ExpiredCacheEntryTriggersLookup(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{
		ConfigOK: true,
		CallLog:  []string{},
		Results: map[string]*entities.ThreatIntel{
			"1.2.3.4": {
				IP:              "1.2.3.4",
				AbuseConfidence: 55,
				ExpiresAt:       clock.Now().Add(24 * time.Hour),
			},
		},
	}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	// Set cache entry that expired 1 hour ago
	cache.SetCached("1.2.3.4", 30, clock.Now().Add(-1*time.Hour))

	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, _, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}

	// Should have fresh data, not cached
	if results[0].FromCache {
		t.Error("result.FromCache = true, want false (cache expired)")
	}
	if results[0].Confidence != 55 {
		t.Errorf("result.Confidence = %d, want 55 (fresh lookup)", results[0].Confidence)
	}
	if maxConf != 55 {
		t.Errorf("maxConfidence = %d, want 55", maxConf)
	}

	// Verify client was called
	if len(client.CallLog) != 1 {
		t.Errorf("client call count = %d, want 1", len(client.CallLog))
	}

	// Verify usage was consumed
	if usage.GetCount("abuseipdb", clock.Now()) != 1 {
		t.Error("usage was not consumed for expired cache")
	}
}

func TestCheckIPs_ClientErrorPropagates(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	client := &testfakes.FakeThreatIntelClient{
		ConfigOK: true,
		CallLog:  []string{},
		Err:      interfaces.ErrUpstreamUnavailable,
	}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	svc := NewService(client, cache, usage, clock, 100, 50)

	_, _, _, err := svc.CheckIPs(context.Background(), []string{"1.2.3.4"})
	if err == nil {
		t.Fatal("Expected error from client, got nil")
	}
	if err != interfaces.ErrUpstreamUnavailable {
		t.Errorf("err = %v, want ErrUpstreamUnavailable", err)
	}
}

func TestCheckIPs_MixedPublicAndPrivate(t *testing.T) {
	clock := &testfakes.FixedClock{T: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	cache := testfakes.NewFakeThreatIntelCache()
	usage := testfakes.NewFakeUsageRepository()

	cache.SetCached("8.8.8.8", 70, clock.Now().Add(24*time.Hour))

	client := &testfakes.FakeThreatIntelClient{ConfigOK: true, CallLog: []string{}}
	svc := NewService(client, cache, usage, clock, 100, 50)

	results, maxConf, escalate, err := svc.CheckIPs(context.Background(), []string{"10.0.0.1", "8.8.8.8", "127.0.0.1"})
	if err != nil {
		t.Fatalf("CheckIPs failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}

	// First and third are private, should be skipped
	if !results[0].Skipped {
		t.Error("results[0] (10.0.0.1) should be skipped")
	}
	if !results[2].Skipped {
		t.Error("results[2] (127.0.0.1) should be skipped")
	}

	// Second is public, should be checked
	if results[1].Skipped {
		t.Error("results[1] (8.8.8.8) should not be skipped")
	}
	if !results[1].Checked {
		t.Error("results[1] (8.8.8.8) should be checked")
	}
	if results[1].Confidence != 70 {
		t.Errorf("results[1].Confidence = %d, want 70", results[1].Confidence)
	}

	if maxConf != 70 {
		t.Errorf("maxConfidence = %d, want 70", maxConf)
	}
	if !escalate {
		t.Error("escalate = false, want true (70 > 50)")
	}
}
