// Package scheduler implements SchedulerControl against the Cloud Scheduler
// REST API, authenticating with the Cloud Run service account's token from
// the metadata server (no client library, no key file).
package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/httpx"
)

const (
	defaultAPIBase  = "https://cloudscheduler.googleapis.com/v1"
	defaultTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

type Client struct {
	jobName  string
	apiBase  string
	tokenURL string
	http     *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

var _ interfaces.SchedulerControl = (*Client)(nil)

// New returns a client for jobName (projects/P/locations/L/jobs/J). An empty
// jobName yields an unconfigured client whose Apply is a no-op error.
func New(jobName, apiBase, tokenURL string, client *http.Client) *Client {
	jobName = strings.TrimSpace(jobName)
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	if client == nil {
		client = httpx.NewClient(15 * time.Second)
	}
	return &Client{jobName: jobName, apiBase: strings.TrimRight(apiBase, "/"), tokenURL: tokenURL, http: client}
}

// Configured reports whether a job name was given. jobName is trimmed and
// normalised in New, so a whitespace-only value here is never mistaken for
// "configured" (which would otherwise call the metadata server needlessly).
func (c *Client) Configured() bool { return c != nil && c.jobName != "" }

// Apply sets the daily schedule ("0 H * * *") and time zone, then pauses or
// resumes the job.
func (c *Client) Apply(ctx context.Context, enabled bool, cronHour int, timezone string) error {
	if !c.Configured() {
		return fmt.Errorf("%w: SCHEDULER_JOB_NAME is not configured", interfaces.ErrUpstreamUnavailable)
	}
	if cronHour < 0 || cronHour > 23 {
		return fmt.Errorf("%w: cron hour must be 0-23", interfaces.ErrValidation)
	}
	body, _ := json.Marshal(map[string]string{"schedule": fmt.Sprintf("0 %d * * *", cronHour), "timeZone": timezone})
	patchURL := c.apiBase + "/" + c.jobName + "?" + url.Values{"updateMask": {"schedule,timeZone"}}.Encode()
	if err := c.call(ctx, http.MethodPatch, patchURL, body); err != nil {
		return err
	}
	verb := ":pause"
	if enabled {
		verb = ":resume"
	}
	return c.call(ctx, http.MethodPost, c.apiBase+"/"+c.jobName+verb, []byte("{}"))
}

func (c *Client) call(ctx context.Context, method, u string, body []byte) error {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: cloud scheduler unreachable", interfaces.ErrUpstreamUnavailable)
	}
	defer resp.Body.Close()
	_, _ = httpx.ReadLimited(resp.Body)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: cloud scheduler rate limited", interfaces.ErrQuotaExceeded)
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: cloud scheduler status %d", interfaces.ErrUpstreamUnavailable, resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: service account lacks cloudscheduler.jobs.update/pause/resume (status %d)", interfaces.ErrUpstreamUnavailable, resp.StatusCode)
	case resp.StatusCode >= 300:
		return fmt.Errorf("cloud scheduler rejected request: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiry) > time.Minute {
		return c.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: metadata server unreachable (not running on GCP?)", interfaces.ErrUpstreamUnavailable)
	}
	defer resp.Body.Close()
	raw, _ := httpx.ReadLimited(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: metadata token status %d", interfaces.ErrUpstreamUnavailable, resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("%w: malformed metadata token", interfaces.ErrUpstreamUnavailable)
	}
	c.token, c.expiry = tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return c.token, nil
}
