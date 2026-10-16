// Package gemini implements the LLM port against the Gemini Developer API
// (generateContent, REST) with structured JSON output.
package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/httpx"
)

type Config struct {
	APIKey       string
	BaseURL      string // https://generativelanguage.googleapis.com
	DefaultModel string
	RPM          int
	MaxAttempts  int
	HTTPClient   *http.Client
}

type Client struct {
	cfg     Config
	limiter *httpx.Limiter
	sleep   func(context.Context, time.Duration) error
}

var _ interfaces.LLM = (*Client)(nil)

func New(cfg Config) *Client {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = httpx.NewClient(90 * time.Second)
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg, limiter: httpx.NewLimiter(cfg.RPM), sleep: httpx.Sleep}
}

func (c *Client) Configured() bool { return c != nil && c.cfg.APIKey != "" }

type part struct {
	Text string `json:"text"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type generateRequest struct {
	SystemInstruction *content       `json:"systemInstruction,omitempty"`
	Contents          []content      `json:"contents"`
	GenerationConfig  map[string]any `json:"generationConfig"`
}

type generateResponse struct {
	Candidates []struct {
		Content      content `json:"content"`
		FinishReason string  `json:"finishReason"`
	} `json:"candidates"`
	PromptFeedback struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
}

type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Details []struct {
			Type       string `json:"@type"`
			RetryDelay string `json:"retryDelay"`
		} `json:"details"`
	} `json:"error"`
}

// GenerateJSON calls generateContent with responseMimeType=application/json
// and the given responseSchema, temperature 0. Retries 429/5xx with backoff,
// honouring the server's RetryInfo delay. Returns the JSON text.
func (c *Client) GenerateJSON(ctx context.Context, req interfaces.JSONGenerationRequest) ([]byte, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("%w: GEMINI_API_KEY is not configured", interfaces.ErrUpstreamUnavailable)
	}
	model := req.Model
	if model == "" {
		model = c.cfg.DefaultModel
	}
	body := generateRequest{
		Contents: []content{{Role: "user", Parts: []part{{Text: req.Prompt}}}},
		GenerationConfig: map[string]any{
			"temperature":      0,
			"responseMimeType": "application/json",
			"responseSchema":   req.Schema,
			"maxOutputTokens":  2048,
		},
	}
	if req.SystemInstruction != "" {
		body.SystemInstruction = &content{Parts: []part{{Text: req.SystemInstruction}}}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	// The model id is validated by config/settings; PathEscape is defence in depth.
	endpoint := c.cfg.BaseURL + "/v1beta/models/" + url.PathEscape(model) + ":generateContent"

	attempts := req.MaxAttempts
	if attempts <= 0 {
		attempts = c.cfg.MaxAttempts
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		out, retryAfter, err := c.do(ctx, endpoint, payload)
		if err == nil {
			return out, nil
		}
		lastErr = err
		retryable := errors.Is(err, interfaces.ErrQuotaExceeded) || errors.Is(err, interfaces.ErrUpstreamUnavailable)
		if !retryable || attempt == attempts {
			break
		}
		wait := httpx.Backoff(attempt, 2*time.Second, 30*time.Second)
		if retryAfter > wait {
			wait = retryAfter
		}
		if retryAfter > 60*time.Second {
			// Server asks us to wait longer than a scan should: give up now and
			// let the batch be deferred to the next scan.
			break
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) do(ctx context.Context, endpoint string, payload []byte) ([]byte, time.Duration, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Header, not ?key= query param, so the key never appears in URL logs.
	httpReq.Header.Set("x-goog-api-key", c.cfg.APIKey)

	resp, err := c.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, fmt.Errorf("%w: gemini request failed", interfaces.ErrUpstreamUnavailable)
	}
	defer resp.Body.Close()
	raw, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading gemini response", interfaces.ErrUpstreamUnavailable)
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, retryDelay(raw, resp.Header), fmt.Errorf("%w: gemini rate limited", interfaces.ErrQuotaExceeded)
	case resp.StatusCode >= 500:
		return nil, httpx.RetryAfter(resp.Header), fmt.Errorf("%w: gemini status %d", interfaces.ErrUpstreamUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		// 400/401/403/404: configuration problems, not retryable. Do not echo
		// the body; it can include the request.
		return nil, 0, fmt.Errorf("gemini rejected request: status %d", resp.StatusCode)
	}

	var gr generateResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		return nil, 0, fmt.Errorf("%w: malformed gemini response", interfaces.ErrUpstreamUnavailable)
	}
	if gr.PromptFeedback.BlockReason != "" {
		return nil, 0, fmt.Errorf("gemini blocked prompt: %s", gr.PromptFeedback.BlockReason)
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil, 0, fmt.Errorf("%w: empty gemini response", interfaces.ErrUpstreamUnavailable)
	}
	var sb strings.Builder
	for _, p := range gr.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	text := strings.TrimSpace(sb.String())
	if !json.Valid([]byte(text)) {
		return nil, 0, fmt.Errorf("gemini returned non-JSON output (finishReason=%s)", gr.Candidates[0].FinishReason)
	}
	return []byte(text), 0, nil
}

func retryDelay(raw []byte, h http.Header) time.Duration {
	var ae apiError
	if json.Unmarshal(raw, &ae) == nil {
		for _, d := range ae.Error.Details {
			if strings.HasSuffix(d.Type, "google.rpc.RetryInfo") {
				if dur, err := time.ParseDuration(d.RetryDelay); err == nil {
					return dur
				}
			}
		}
	}
	return httpx.RetryAfter(h)
}
