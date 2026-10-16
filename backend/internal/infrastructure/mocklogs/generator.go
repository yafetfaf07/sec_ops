// Package mocklogs generates realistic synthetic SaaS access logs for
// FR-SEC-001. Scenarios plant patterns the analysis pipeline should detect.
package mocklogs

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
)

const (
	ScenarioBenign              = "benign"
	ScenarioBruteForce          = "brute_force"
	ScenarioImpossibleTravel    = "impossible_travel"
	ScenarioPrivilegeEscalation = "privilege_escalation"
	ScenarioMixed               = "mixed"
)

func Scenarios() []string {
	return []string{ScenarioMixed, ScenarioBenign, ScenarioBruteForce, ScenarioImpossibleTravel, ScenarioPrivilegeEscalation}
}

func ValidScenario(s string) bool {
	for _, v := range Scenarios() {
		if v == s {
			return true
		}
	}
	return false
}

type place struct{ Country, City string }

var places = []place{
	{"United States", "New York"}, {"United States", "San Francisco"}, {"Germany", "Berlin"}, {"Germany", "Frankfurt"},
	{"United Kingdom", "London"}, {"France", "Paris"}, {"Netherlands", "Amsterdam"}, {"Ethiopia", "Addis Ababa"},
	{"India", "Bengaluru"}, {"Japan", "Tokyo"}, {"Brazil", "São Paulo"}, {"Canada", "Toronto"},
}

var attackerPlaces = []place{{"Russia", "Moscow"}, {"China", "Shenzhen"}, {"Nigeria", "Lagos"}, {"Romania", "Bucharest"}, {"Vietnam", "Hanoi"}}

var users = []string{
	"alice@acme.io", "bob@acme.io", "carol@acme.io", "dave@acme.io", "erin@acme.io",
	"frank@acme.io", "grace@acme.io", "heidi@acme.io", "ivan@acme.io", "judy@acme.io",
}

var agents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
}

var attackAgents = []string{"python-requests/2.32.3", "curl/8.9.1", "Go-http-client/1.1", "Hydra/9.5"}

// Generator is safe for concurrent use. LogID generation is deterministic
// for a fixed seed: it uses the seeded RNG plus a monotonically increasing
// counter, never uuid.NewString() or wall-clock time, so Generate(seed, ...)
// called twice with the same seed and no shared state produces identical
// output, and no two logs from one Generator ever collide.
type Generator struct {
	mu      sync.Mutex
	rng     *rand.Rand
	now     func() time.Time
	counter uint64
}

func New(seed uint64, now func() time.Time) *Generator {
	if now == nil {
		now = time.Now
	}
	return &Generator{rng: rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)), now: now}
}

// docIP returns an address from the RFC 5737 documentation ranges so mock
// data never points at a real host.
func (g *Generator) docIP(benign bool) string {
	if benign {
		return fmt.Sprintf("192.0.2.%d", 1+g.rng.IntN(250))
	}
	if g.rng.IntN(2) == 0 {
		return fmt.Sprintf("198.51.100.%d", 1+g.rng.IntN(250))
	}
	return fmt.Sprintf("203.0.113.%d", 1+g.rng.IntN(250))
}

func (g *Generator) pick(s []string) string { return s[g.rng.IntN(len(s))] }

func (g *Generator) entry(ts time.Time, user, ip string, p place, action enums.LogAction, ua string) entities.RawLog {
	g.counter++
	return entities.RawLog{
		LogID: fmt.Sprintf("log_%016x", g.rng.Uint64()^g.counter), Timestamp: ts.UTC().Truncate(time.Second), UserID: user,
		IPAddress: ip, Country: p.Country, City: p.City, Action: action, UserAgent: ua,
	}
}

// Generate returns count logs for the scenario within the last 24h.
// attackerIPs, when given, replace the generated attacker addresses (for
// demonstrating AbuseIPDB enrichment with known-bad public IPs).
func (g *Generator) Generate(scenario string, count int, attackerIPs []string) []entities.RawLog {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().UTC()
	attackerIP := func() string {
		if len(attackerIPs) > 0 {
			return attackerIPs[g.rng.IntN(len(attackerIPs))]
		}
		return g.docIP(false)
	}
	var out []entities.RawLog
	switch scenario {
	case ScenarioBenign:
		out = g.benign(now, count)
	case ScenarioBruteForce:
		out = g.bruteForce(now, count, attackerIP())
	case ScenarioImpossibleTravel:
		out = g.impossibleTravel(now, count, attackerIP)
	case ScenarioPrivilegeEscalation:
		out = g.privilegeEscalation(now, count, attackerIP())
	default: // mixed
		n := max(count/4, 1)
		out = append(out, g.benign(now, count-3*n)...)
		out = append(out, g.bruteForce(now, n, attackerIP())...)
		out = append(out, g.impossibleTravel(now, n, attackerIP)...)
		out = append(out, g.privilegeEscalation(now, n, attackerIP())...)
	}
	return out
}

func (g *Generator) benign(now time.Time, count int) []entities.RawLog {
	out := make([]entities.RawLog, 0, count)
	for i := 0; i < count; i++ {
		ts := now.Add(-time.Duration(g.rng.Int64N(int64(23 * time.Hour))))
		action := enums.ActionLoginSuccess
		if g.rng.IntN(12) == 0 { // the occasional typo
			action = enums.ActionLoginFailed
		}
		out = append(out, g.entry(ts, g.pick(users), g.docIP(true), places[g.rng.IntN(len(places))], action, g.pick(agents)))
	}
	return out
}

// bruteForce: one source IP hammering several accounts within minutes, with
// one success at the end (credential stuffing that worked).
func (g *Generator) bruteForce(now time.Time, count int, ip string) []entities.RawLog {
	start := now.Add(-time.Duration(1+g.rng.IntN(20)) * time.Hour)
	p := attackerPlaces[g.rng.IntN(len(attackerPlaces))]
	ua := g.pick(attackAgents)
	out := make([]entities.RawLog, 0, count)
	for i := 0; i < count; i++ {
		ts := start.Add(time.Duration(i*(2+g.rng.IntN(6))) * time.Second)
		action := enums.ActionLoginFailed
		if i == count-1 && count > 5 {
			action = enums.ActionLoginSuccess
		}
		out = append(out, g.entry(ts, g.pick(users[:4]), ip, p, action, ua))
	}
	return out
}

// impossibleTravel: the same user succeeding from distant countries minutes
// apart, followed by failures from the far location.
func (g *Generator) impossibleTravel(now time.Time, count int, attackerIP func() string) []entities.RawLog {
	out := make([]entities.RawLog, 0, count)
	for i := 0; len(out) < count; i++ {
		user := users[(i+4)%len(users)]
		base := now.Add(-time.Duration(1+g.rng.IntN(20)) * time.Hour)
		home := places[g.rng.IntN(len(places))]
		far := attackerPlaces[g.rng.IntN(len(attackerPlaces))]
		ip := attackerIP()
		out = append(out, g.entry(base, user, g.docIP(true), home, enums.ActionLoginSuccess, g.pick(agents)))
		if len(out) < count {
			out = append(out, g.entry(base.Add(time.Duration(5+g.rng.IntN(20))*time.Minute), user, ip, far, enums.ActionLoginFailed, g.pick(attackAgents)))
		}
		if len(out) < count {
			out = append(out, g.entry(base.Add(time.Duration(26+g.rng.IntN(10))*time.Minute), user, ip, far, enums.ActionLoginSuccess, g.pick(attackAgents)))
		}
	}
	return out
}

// privilegeEscalation: a normal login followed by escalation attempts.
func (g *Generator) privilegeEscalation(now time.Time, count int, ip string) []entities.RawLog {
	user := g.pick(users)
	p := attackerPlaces[g.rng.IntN(len(attackerPlaces))]
	base := now.Add(-time.Duration(1+g.rng.IntN(20)) * time.Hour)
	out := []entities.RawLog{g.entry(base, user, ip, p, enums.ActionLoginSuccess, g.pick(agents))}
	for i := 1; i < count; i++ {
		out = append(out, g.entry(base.Add(time.Duration(i*(30+g.rng.IntN(90)))*time.Second), user, ip, p, enums.ActionPrivilegeEscalation, g.pick(agents)))
	}
	return out
}
