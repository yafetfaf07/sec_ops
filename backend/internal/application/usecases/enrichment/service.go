// Package enrichment cross-references suspicious IPs against AbuseIPDB,
// cached for 24h, and escalates incident risk on a high confidence score
// (FR-SEC-004).
package enrichment

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"sec_ops/internal/domain/interfaces"
)

const abuseProvider = "abuseipdb"

type Service struct {
	client      interfaces.ThreatIntelClient
	cache       interfaces.ThreatIntelCache
	usage       interfaces.UsageRepository
	clock       interfaces.Clock
	dailyBudget int
	threshold   int
}

func NewService(client interfaces.ThreatIntelClient, cache interfaces.ThreatIntelCache, usage interfaces.UsageRepository,
	clock interfaces.Clock, dailyBudget, escalateThreshold int) *Service {
	return &Service{client: client, cache: cache, usage: usage, clock: clock, dailyBudget: dailyBudget, threshold: escalateThreshold}
}

func (s *Service) Enabled() bool { return s.client.Configured() }

// Result is the enrichment outcome for one IP.
type Result struct {
	IP         string
	Confidence int
	FromCache  bool
	Skipped    bool // private/reserved address, or enrichment disabled
	Checked    bool // an actual lookup (cached or live) happened
}

// CheckIPs looks up each public IP (skipping private/reserved/loopback
// addresses), preferring the cache, and returns the highest confidence score
// seen plus whether it crossed the escalation threshold.
func (s *Service) CheckIPs(ctx context.Context, ips []string) (results []Result, maxConfidence int, escalate bool, err error) {
	if !s.Enabled() {
		for _, ip := range ips {
			results = append(results, Result{IP: ip, Skipped: true})
		}
		return results, 0, false, nil
	}
	now := s.clock.Now().UTC()
	for _, ip := range ips {
		addr, perr := netip.ParseAddr(ip)
		if perr != nil || isPrivate(addr) {
			results = append(results, Result{IP: ip, Skipped: true})
			continue
		}
		r, lerr := s.checkOne(ctx, addr.String(), now)
		if lerr != nil {
			if errors.Is(lerr, interfaces.ErrQuotaExceeded) {
				results = append(results, Result{IP: ip, Skipped: true})
				continue // keep going with the rest; log at caller via error below
			}
			return results, maxConfidence, escalate, lerr
		}
		results = append(results, r)
		if r.Confidence > maxConfidence {
			maxConfidence = r.Confidence
		}
	}
	escalate = maxConfidence > s.threshold
	return results, maxConfidence, escalate, nil
}

func (s *Service) checkOne(ctx context.Context, ip string, now time.Time) (Result, error) {
	if cached, err := s.cache.Get(ctx, ip, now); err == nil {
		return Result{IP: ip, Confidence: cached.AbuseConfidence, FromCache: true, Checked: true}, nil
	} else if !errors.Is(err, interfaces.ErrNotFound) {
		return Result{}, err
	}

	ok, err := s.usage.Consume(ctx, abuseProvider, now, s.dailyBudget)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{IP: ip, Skipped: true}, nil
	}

	ti, err := s.client.Check(ctx, ip)
	if err != nil {
		return Result{}, err
	}
	if err := s.cache.Put(ctx, ti); err != nil {
		return Result{}, err
	}
	return Result{IP: ip, Confidence: ti.AbuseConfidence, Checked: true}, nil
}

// isPrivate reports whether addr should never be sent to a third-party API:
// private, loopback, link-local, or documentation ranges (mock data).
func isPrivate(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() || isDocumentation(addr)
}

// isDocumentation covers RFC 5737 / RFC 3849 ranges used by the mock
// generator, so demo data never triggers a real API call.
func isDocumentation(addr netip.Addr) bool {
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		prefix := netip.MustParsePrefix(p)
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
