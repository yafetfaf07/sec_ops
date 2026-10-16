package config

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	geminiModelID    = regexp.MustCompile(`^gemini-[a-z0-9][a-z0-9.\-]{0,62}$`)
	schedulerJobName = regexp.MustCompile(`^projects/[a-z0-9\-]+/locations/[a-z0-9\-]+/jobs/[A-Za-z0-9_\-]+$`)
)

// ValidGeminiModel reports whether s is a syntactically valid Gemini model id.
// The model id is interpolated into the request path, so it must be strict.
func ValidGeminiModel(s string) bool { return geminiModelID.MatchString(s) }

// webhookHostAllowed pins webhook URLs to the vendor's host so a mistyped or
// malicious value cannot turn alert dispatch into an SSRF primitive.
func webhookHostAllowed(raw string, hosts ...string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, allowed := range hosts {
		if h == allowed {
			return true
		}
	}
	return false
}
