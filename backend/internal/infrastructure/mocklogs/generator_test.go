package mocklogs

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"sec_ops/internal/domain/enums"
)

func TestGenerate_Deterministic(t *testing.T) {
	const seed = uint64(12345)
	const count = 50

	now := func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }

	gen1 := New(seed, now)
	gen2 := New(seed, now)

	scenarios := []string{ScenarioBenign, ScenarioBruteForce, ScenarioImpossibleTravel, ScenarioPrivilegeEscalation, ScenarioMixed}

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			logs1 := gen1.Generate(scenario, count, nil)
			logs2 := gen2.Generate(scenario, count, nil)

			if len(logs1) != len(logs2) {
				t.Fatalf("different lengths: %d vs %d", len(logs1), len(logs2))
			}

			for i := range logs1 {
				// Compare marshaled JSON for complete equality
				json1, _ := json.Marshal(logs1[i])
				json2, _ := json.Marshal(logs2[i])
				if string(json1) != string(json2) {
					t.Errorf("entry %d differs:\n%s\n%s", i, json1, json2)
				}

				// Also compare field-by-field for better error messages
				if logs1[i].LogID != logs2[i].LogID {
					t.Errorf("entry %d: LogID %s != %s", i, logs1[i].LogID, logs2[i].LogID)
				}
				if !logs1[i].Timestamp.Equal(logs2[i].Timestamp) {
					t.Errorf("entry %d: Timestamp %v != %v", i, logs1[i].Timestamp, logs2[i].Timestamp)
				}
				if logs1[i].UserID != logs2[i].UserID {
					t.Errorf("entry %d: UserID %s != %s", i, logs1[i].UserID, logs2[i].UserID)
				}
				if logs1[i].IPAddress != logs2[i].IPAddress {
					t.Errorf("entry %d: IPAddress %s != %s", i, logs1[i].IPAddress, logs2[i].IPAddress)
				}
				if logs1[i].Country != logs2[i].Country {
					t.Errorf("entry %d: Country %s != %s", i, logs1[i].Country, logs2[i].Country)
				}
				if logs1[i].City != logs2[i].City {
					t.Errorf("entry %d: City %s != %s", i, logs1[i].City, logs2[i].City)
				}
				if logs1[i].Action != logs2[i].Action {
					t.Errorf("entry %d: Action %s != %s", i, logs1[i].Action, logs2[i].Action)
				}
				if logs1[i].UserAgent != logs2[i].UserAgent {
					t.Errorf("entry %d: UserAgent differs", i)
				}
			}
		})
	}
}

func TestGenerate_BenignIPsInDocumentationRanges(t *testing.T) {
	// RFC 5737 documentation ranges
	docRanges := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}

	gen := New(42, time.Now)

	scenarios := []string{ScenarioBenign, ScenarioMixed}

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			logs := gen.Generate(scenario, 100, nil)

			for i, log := range logs {
				addr, err := netip.ParseAddr(log.IPAddress)
				if err != nil {
					t.Errorf("entry %d: invalid IP address %q: %v", i, log.IPAddress, err)
					continue
				}

				// Check if IP is in any of the documentation ranges
				inDocRange := false
				for _, prefix := range docRanges {
					if prefix.Contains(addr) {
						inDocRange = true
						break
					}
				}

				if !inDocRange {
					t.Errorf("entry %d: IP %s not in RFC5737 documentation ranges", i, log.IPAddress)
				}
			}
		})
	}
}

func TestGenerate_BruteForceOnlyOneSourceIP(t *testing.T) {
	gen := New(123, time.Now)
	logs := gen.Generate(ScenarioBruteForce, 50, nil)

	if len(logs) == 0 {
		t.Fatal("no logs generated")
	}

	firstIP := logs[0].IPAddress
	for i, log := range logs {
		if log.IPAddress != firstIP {
			t.Errorf("entry %d: expected IP %s, got %s (brute force should use single IP)", i, firstIP, log.IPAddress)
		}
	}
}

func TestGenerate_ImpossibleTravelDifferentCountries(t *testing.T) {
	gen := New(456, time.Now)
	logs := gen.Generate(ScenarioImpossibleTravel, 30, nil)

	// Track countries per user
	userCountries := make(map[string]map[string]bool)
	for _, log := range logs {
		if userCountries[log.UserID] == nil {
			userCountries[log.UserID] = make(map[string]bool)
		}
		userCountries[log.UserID][log.Country] = true
	}

	// At least one user should have logins from different countries
	foundImpossibleTravel := false
	for user, countries := range userCountries {
		if len(countries) > 1 {
			foundImpossibleTravel = true
			t.Logf("user %s has logins from %d countries (impossible travel pattern)", user, len(countries))
		}
	}

	if !foundImpossibleTravel {
		t.Error("impossible travel scenario should produce entries with same user in different countries")
	}
}

func TestGenerate_PrivilegeEscalationFirstIsLoginSuccess(t *testing.T) {
	gen := New(789, time.Now)
	logs := gen.Generate(ScenarioPrivilegeEscalation, 20, nil)

	if len(logs) == 0 {
		t.Fatal("no logs generated")
	}

	if logs[0].Action != enums.ActionLoginSuccess {
		t.Errorf("first entry should be Login Success, got %s", logs[0].Action)
	}

	// Rest should be privilege escalation
	for i := 1; i < len(logs); i++ {
		if logs[i].Action != enums.ActionPrivilegeEscalation {
			t.Errorf("entry %d: expected Privilege Escalation, got %s", i, logs[i].Action)
		}
	}
}

func TestGenerate_AllIPsInDocRanges(t *testing.T) {
	// All IPs generated should be in RFC5737 ranges
	docRanges := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}

	gen := New(999, time.Now)

	allScenarios := Scenarios()

	for _, scenario := range allScenarios {
		t.Run(scenario, func(t *testing.T) {
			logs := gen.Generate(scenario, 100, nil)

			for i, log := range logs {
				addr, err := netip.ParseAddr(log.IPAddress)
				if err != nil {
					t.Errorf("entry %d: invalid IP %q: %v", i, log.IPAddress, err)
					continue
				}

				inDocRange := false
				for _, prefix := range docRanges {
					if prefix.Contains(addr) {
						inDocRange = true
						break
					}
				}

				if !inDocRange {
					t.Errorf("%s entry %d: IP %s not in RFC5737 ranges", scenario, i, log.IPAddress)
				}
			}
		})
	}
}

func TestGenerate_ConcurrencySafe(t *testing.T) {
	gen := New(555, time.Now)

	const goroutines = 10
	const logsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Run with -race flag to detect race conditions
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			scenario := Scenarios()[id%len(Scenarios())]
			logs := gen.Generate(scenario, logsPerGoroutine, nil)

			if len(logs) == 0 {
				t.Errorf("goroutine %d: no logs generated", id)
			}

			// Validate generated logs
			for j, log := range logs {
				if log.LogID == "" {
					t.Errorf("goroutine %d, log %d: empty LogID", id, j)
				}
				if log.UserID == "" {
					t.Errorf("goroutine %d, log %d: empty UserID", id, j)
				}
				if log.IPAddress == "" {
					t.Errorf("goroutine %d, log %d: empty IPAddress", id, j)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestGenerate_LogIDsAreUnique(t *testing.T) {
	gen := New(111, time.Now)
	logs := gen.Generate(ScenarioMixed, 200, nil)

	seen := make(map[string]bool)
	for i, log := range logs {
		if seen[log.LogID] {
			t.Errorf("entry %d: duplicate LogID %s", i, log.LogID)
		}
		seen[log.LogID] = true
	}
}

func TestGenerate_TimestampsWithinLast24Hours(t *testing.T) {
	now := time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)
	gen := New(222, func() time.Time { return now })

	scenarios := Scenarios()
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			logs := gen.Generate(scenario, 50, nil)

			cutoff := now.Add(-24 * time.Hour)
			for i, log := range logs {
				if log.Timestamp.After(now) {
					t.Errorf("entry %d: timestamp %v is in the future (now=%v)", i, log.Timestamp, now)
				}
				if log.Timestamp.Before(cutoff) {
					t.Errorf("entry %d: timestamp %v is older than 24h (cutoff=%v)", i, log.Timestamp, cutoff)
				}
			}
		})
	}
}

func TestGenerate_ValidActions(t *testing.T) {
	gen := New(333, time.Now)

	validActions := map[enums.LogAction]bool{
		enums.ActionLoginSuccess:        true,
		enums.ActionLoginFailed:         true,
		enums.ActionPrivilegeEscalation: true,
	}

	scenarios := Scenarios()
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			logs := gen.Generate(scenario, 50, nil)

			for i, log := range logs {
				if !validActions[log.Action] {
					t.Errorf("entry %d: invalid action %q", i, log.Action)
				}
			}
		})
	}
}

func TestGenerate_AttackerIPsRespected(t *testing.T) {
	gen := New(444, time.Now)

	attackerIPs := []string{"1.2.3.4", "5.6.7.8"}
	logs := gen.Generate(ScenarioBruteForce, 30, attackerIPs)

	// For brute force, all IPs should be from the provided list
	for i, log := range logs {
		found := false
		for _, ip := range attackerIPs {
			if log.IPAddress == ip {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("entry %d: IP %s not in provided attacker IPs %v", i, log.IPAddress, attackerIPs)
		}
	}
}

func TestGenerate_MixedScenarioDistribution(t *testing.T) {
	gen := New(666, time.Now)
	logs := gen.Generate(ScenarioMixed, 100, nil)

	// Mixed should contain variety of patterns
	actions := make(map[enums.LogAction]int)
	for _, log := range logs {
		actions[log.Action]++
	}

	// Should have at least 2 different action types
	if len(actions) < 2 {
		t.Errorf("mixed scenario should have variety, got only %d action types: %v", len(actions), actions)
	}

	// Should have some benign activity (login success)
	if actions[enums.ActionLoginSuccess] == 0 {
		t.Error("mixed scenario should include some benign login successes")
	}

	// Should have some suspicious activity
	if actions[enums.ActionLoginFailed] == 0 && actions[enums.ActionPrivilegeEscalation] == 0 {
		t.Error("mixed scenario should include some suspicious activity")
	}
}

func TestGenerate_CountRespected(t *testing.T) {
	gen := New(777, time.Now)

	tests := []struct {
		scenario string
		count    int
	}{
		{ScenarioBenign, 10},
		{ScenarioBruteForce, 25},
		{ScenarioImpossibleTravel, 30},
		{ScenarioPrivilegeEscalation, 15},
		{ScenarioMixed, 100},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			logs := gen.Generate(tt.scenario, tt.count, nil)

			// Some scenarios may produce slightly different counts due to their structure
			// but should be close to the requested count
			if len(logs) < tt.count/2 || len(logs) > tt.count*2 {
				t.Errorf("requested %d logs, got %d (too far from expected)", tt.count, len(logs))
			}
		})
	}
}

func TestGenerate_BruteForceHasFailures(t *testing.T) {
	gen := New(888, time.Now)
	logs := gen.Generate(ScenarioBruteForce, 30, nil)

	failureCount := 0
	for _, log := range logs {
		if log.Action == enums.ActionLoginFailed {
			failureCount++
		}
	}

	if failureCount == 0 {
		t.Error("brute force scenario should include login failures")
	}

	// Most entries should be failures in a brute force attack
	if float64(failureCount)/float64(len(logs)) < 0.5 {
		t.Errorf("brute force should be mostly failures, got %d/%d", failureCount, len(logs))
	}
}

func TestGenerate_PrivilegeEscalationSameUser(t *testing.T) {
	gen := New(999, time.Now)
	logs := gen.Generate(ScenarioPrivilegeEscalation, 20, nil)

	if len(logs) == 0 {
		t.Fatal("no logs generated")
	}

	firstUser := logs[0].UserID
	for i, log := range logs {
		if log.UserID != firstUser {
			t.Errorf("entry %d: expected user %s, got %s (privilege escalation should be same user)", i, firstUser, log.UserID)
		}
	}
}

func TestValidScenario(t *testing.T) {
	tests := []struct {
		scenario string
		want     bool
	}{
		{ScenarioBenign, true},
		{ScenarioBruteForce, true},
		{ScenarioImpossibleTravel, true},
		{ScenarioPrivilegeEscalation, true},
		{ScenarioMixed, true},
		{"invalid_scenario", false},
		{"", false},
		{"BENIGN", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			if got := ValidScenario(tt.scenario); got != tt.want {
				t.Errorf("ValidScenario(%q) = %v, want %v", tt.scenario, got, tt.want)
			}
		})
	}
}

func TestScenarios(t *testing.T) {
	scenarios := Scenarios()

	if len(scenarios) == 0 {
		t.Fatal("Scenarios() returned empty list")
	}

	// Verify all returned scenarios are valid
	for _, s := range scenarios {
		if !ValidScenario(s) {
			t.Errorf("Scenarios() returned invalid scenario: %s", s)
		}
	}

	// Verify expected scenarios are present
	expected := []string{ScenarioBenign, ScenarioBruteForce, ScenarioImpossibleTravel, ScenarioPrivilegeEscalation, ScenarioMixed}
	for _, exp := range expected {
		found := false
		for _, s := range scenarios {
			if s == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected scenario %q not in Scenarios()", exp)
		}
	}
}

func TestGenerate_NoEmptyFields(t *testing.T) {
	gen := New(1111, time.Now)

	scenarios := Scenarios()
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			logs := gen.Generate(scenario, 20, nil)

			for i, log := range logs {
				if log.LogID == "" {
					t.Errorf("entry %d: empty LogID", i)
				}
				if log.UserID == "" {
					t.Errorf("entry %d: empty UserID", i)
				}
				if log.IPAddress == "" {
					t.Errorf("entry %d: empty IPAddress", i)
				}
				if log.Country == "" {
					t.Errorf("entry %d: empty Country", i)
				}
				if log.City == "" {
					t.Errorf("entry %d: empty City", i)
				}
				if log.Action == "" {
					t.Errorf("entry %d: empty Action", i)
				}
				if log.UserAgent == "" {
					t.Errorf("entry %d: empty UserAgent", i)
				}
			}
		})
	}
}
