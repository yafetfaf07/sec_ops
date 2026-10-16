// Package notify implements the alert ports for Slack and Discord incoming
// webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/httpx"
)

// Webhook posts AlertMessages to a Slack or Discord incoming webhook. The
// URL is a secret: it is never logged or included in returned errors.
type Webhook struct {
	channel string
	url     string
	http    *http.Client
}

var (
	_ interfaces.AlertNotifier = (*Webhook)(nil)
)

func NewSlack(url string, client *http.Client) *Webhook   { return newWebhook("slack", url, client) }
func NewDiscord(url string, client *http.Client) *Webhook { return newWebhook("discord", url, client) }

func newWebhook(channel, url string, client *http.Client) *Webhook {
	if client == nil {
		client = httpx.NewClient(10 * time.Second)
	}
	return &Webhook{channel: channel, url: url, http: client}
}

func (w *Webhook) Channel() string { return w.channel }

func (w *Webhook) Send(ctx context.Context, m interfaces.AlertMessage) (int, error) {
	var payload any
	if w.channel == "slack" {
		payload = slackPayload(m)
	} else {
		payload = discordPayload(m)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build %s request failed", w.channel)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.http.Do(req)
	if err != nil {
		// *url.Error embeds the URL (the secret); return a generic message.
		return 0, fmt.Errorf("%w: %s webhook unreachable", interfaces.ErrUpstreamUnavailable, w.channel)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("%s webhook returned status %d", w.channel, resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func scoreText(m interfaces.AlertMessage) string {
	if m.AbuseIPDBScore == nil {
		return "not checked"
	}
	return fmt.Sprintf("%d%%", *m.AbuseIPDBScore)
}

// sanitize keeps attacker-influenced text (AI summaries derived from logs)
// from pinging channels or injecting markup: it strips mention syntax and
// truncates.
func sanitize(s string, n int) string {
	r := strings.NewReplacer("@everyone", "everyone", "@here", "here", "<!", "<", "<@", "<", "```", "'''")
	s = r.Replace(strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}

func slackPayload(m interfaces.AlertMessage) map[string]any {
	title := fmt.Sprintf("%s risk security incident", m.RiskScore)
	fields := []map[string]any{
		{"type": "mrkdwn", "text": "*Timestamp*\n" + m.Timestamp.UTC().Format(time.RFC3339)},
		{"type": "mrkdwn", "text": "*Risk*\n" + string(m.RiskScore)},
		{"type": "mrkdwn", "text": "*AbuseIPDB score*\n" + scoreText(m)},
		{"type": "mrkdwn", "text": "*Top IP*\n" + sanitize(m.TopIP, 64)},
	}
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": title}},
		{"type": "section", "fields": fields},
		{"type": "section", "text": map[string]any{"type": "plain_text", "text": "AI summary: " + sanitize(m.Summary, 2500)}},
		{"type": "section", "text": map[string]any{"type": "plain_text", "text": "Recommended action: " + sanitize(m.RecommendedAction, 1500)}},
	}
	if m.Link != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "<" + m.Link + "|Open incident>"}})
	}
	return map[string]any{"text": title + ": " + sanitize(m.Summary, 300), "blocks": blocks}
}

var discordColor = map[string]int{"Low": 0x22c55e, "Medium": 0xeab308, "High": 0xef4444, "Critical": 0x991b1b}

func discordPayload(m interfaces.AlertMessage) map[string]any {
	embed := map[string]any{
		"title":       fmt.Sprintf("%s risk security incident", m.RiskScore),
		"description": sanitize(m.Summary, 3500),
		"color":       discordColor[string(m.RiskScore)],
		"timestamp":   m.Timestamp.UTC().Format(time.RFC3339),
		"fields": []map[string]any{
			{"name": "Timestamp", "value": m.Timestamp.UTC().Format(time.RFC3339), "inline": true},
			{"name": "AbuseIPDB score", "value": scoreText(m), "inline": true},
			{"name": "Top IP", "value": nonEmpty(sanitize(m.TopIP, 64)), "inline": true},
			{"name": "Recommended action", "value": nonEmpty(sanitize(m.RecommendedAction, 1000))},
		},
	}
	if m.Link != "" {
		embed["url"] = m.Link
	}
	return map[string]any{
		"content":          "",
		"embeds":           []any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}},
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
