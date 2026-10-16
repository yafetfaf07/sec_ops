// Package abuseipdb implements the threat-intel port against AbuseIPDB v2.
package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/httpx"
)

type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
	now     func() time.Time
}

var _ interfaces.ThreatIntelClient = (*Client)(nil)

func New(apiKey, baseURL string, client *http.Client) *Client {
	if client == nil {
		client = httpx.NewClient(10 * time.Second)
	}
	return &Client{apiKey: apiKey, baseURL: strings.TrimRight(baseURL, "/"), http: client, now: time.Now}
}

func (c *Client) Configured() bool { return c != nil && c.apiKey != "" }

type checkResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// Check calls GET /api/v2/check. The caller is responsible for caching and
// budget; this adapter only validates input and maps errors.
func (c *Client) Check(ctx context.Context, ip string) (*entities.ThreatIntel, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("%w: ABUSEIPDB_API_KEY is not configured", interfaces.ErrUpstreamUnavailable)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid IP", interfaces.ErrValidation)
	}
	q := url.Values{"ipAddress": {addr.String()}, "maxAgeInDays": {"90"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/check?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: abuseipdb request failed", interfaces.ErrUpstreamUnavailable)
	}
	defer resp.Body.Close()
	raw, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading abuseipdb response", interfaces.ErrUpstreamUnavailable)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: abuseipdb daily limit reached", interfaces.ErrQuotaExceeded)
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: abuseipdb status %d", interfaces.ErrUpstreamUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("abuseipdb rejected request: status %d", resp.StatusCode)
	}
	var cr checkResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, fmt.Errorf("%w: malformed abuseipdb response", interfaces.ErrUpstreamUnavailable)
	}
	score := cr.Data.AbuseConfidenceScore
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	now := c.now().UTC()
	return &entities.ThreatIntel{
		IP: addr.String(), AbuseConfidence: score, TotalReports: max(cr.Data.TotalReports, 0),
		Country: cr.Data.CountryCode, FetchedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}, nil
}
