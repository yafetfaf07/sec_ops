package entities

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"sec_ops/internal/domain/enums"
)

// AuditHash computes the hash-chain link for an audit entry:
// sha256(prev_hash || canonical fields). The timestamp is truncated to
// microseconds (Postgres precision) so the value recomputed from a stored row
// matches the one computed before insert. Metadata is map[string]string and
// encoding/json sorts map keys, so its encoding is canonical.
func AuditHash(prevHash string, e AuditEntry) string {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	metaJSON, _ := json.Marshal(meta)

	var b strings.Builder
	for _, part := range []string{
		prevHash,
		e.Timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		e.UserID,
		string(e.ActionType),
		e.EntityType,
		e.EntityID,
		e.Details,
		string(metaJSON),
	} {
		// Length-prefix each field so "ab"+"c" never collides with "a"+"bc".
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
		b.WriteByte('|')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// IncidentFingerprint identifies "the same threat" across scans so a resolved
// incident is not re-alerted (FR-SEC-012). It is built from the attack
// patterns, source IPs and targeted users, order-insensitively.
func IncidentFingerprint(patterns, ips, users []string) string {
	norm := func(in []string) string {
		out := make([]string, 0, len(in))
		seen := map[string]bool{}
		for _, s := range in {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	sum := sha256.Sum256([]byte("p=" + norm(patterns) + ";i=" + norm(ips) + ";u=" + norm(users)))
	return hex.EncodeToString(sum[:16])
}

// SeverityOrder is used where callers need an explicit Low..Critical ordering.
func SeverityOrder() []enums.RiskLevel { return enums.AllRiskLevels() }
