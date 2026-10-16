package security

import (
	"strings"
	"testing"
	"time"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func newTestJWT(t *testing.T, now time.Time) *JWTService {
	svc, err := NewJWTService(strings.Repeat("k", 32), 15*time.Minute, 7*24*time.Hour, fixedNow(now))
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	return svc
}

func testUser() *entities.User {
	return &entities.User{ID: "11111111-1111-1111-1111-111111111111", Role: enums.RoleAnalyst, TokenVersion: 3}
}

func TestNewJWTServiceRejectsShortSecret(t *testing.T) {
	if _, err := NewJWTService("short", time.Minute, time.Hour, time.Now); err == nil {
		t.Fatal("expected error for a secret shorter than 32 bytes")
	}
}

func TestIssueAndParseAccess(t *testing.T) {
	now := time.Now().UTC()
	svc := newTestJWT(t, now)
	u := testUser()

	tok, exp, err := svc.IssueAccess(u)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if !exp.After(now) {
		t.Fatal("expiry must be in the future")
	}
	claims, err := svc.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.UserID != u.ID || claims.Role != u.Role || claims.TokenVersion != u.TokenVersion {
		t.Errorf("claims = %+v", claims)
	}
}

func TestParseRejectsWrongTokenType(t *testing.T) {
	svc := newTestJWT(t, time.Now())
	u := testUser()
	access, _, _ := svc.IssueAccess(u)
	refresh, _, _ := svc.IssueRefresh(u)

	if _, err := svc.ParseRefresh(access); err == nil {
		t.Error("an access token must not be accepted as a refresh token")
	}
	if _, err := svc.ParseAccess(refresh); err == nil {
		t.Error("a refresh token must not be accepted as an access token")
	}
}

func TestParseRejectsExpiredToken(t *testing.T) {
	issued := time.Now().UTC()
	svc := newTestJWT(t, issued)
	tok, _, err := svc.IssueAccess(testUser())
	if err != nil {
		t.Fatal(err)
	}

	// Move the clock well past expiry + skew leeway.
	svc.now = fixedNow(issued.Add(20 * time.Minute))
	if _, err := svc.ParseAccess(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestParseRejectsTamperedSignature(t *testing.T) {
	svc := newTestJWT(t, time.Now())
	tok, _, _ := svc.IssueAccess(testUser())
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	if _, err := svc.ParseAccess(tampered); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestParseRejectsTamperedPayload(t *testing.T) {
	svc := newTestJWT(t, time.Now())
	tok, _, _ := svc.IssueAccess(testUser())
	parts := strings.Split(tok, ".")
	// Flip the payload but keep the original signature.
	tampered := parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"secops-api","sub":"x","typ":"access","role":"admin","ver":0,"exp":9999999999}`)) + "." + parts[2]
	if _, err := svc.ParseAccess(tampered); err == nil {
		t.Fatal("tampered payload must be rejected")
	}
}

// TestParseRejectsAlgNoneConfusion guards against the classic JWT
// algorithm-confusion attack: a token whose header claims alg=none (or any
// algorithm other than exactly our fixed HS256 header) must never validate,
// even with a syntactically valid-looking signature segment.
func TestParseRejectsAlgNoneConfusion(t *testing.T) {
	svc := newTestJWT(t, time.Now())
	payload := `{"iss":"secops-api","sub":"11111111-1111-1111-1111-111111111111","typ":"access","role":"admin","ver":0,"exp":9999999999,"nbf":0,"iat":0}`
	forged := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64.EncodeToString([]byte(payload)) + "."
	if _, err := svc.ParseAccess(forged); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	svc := newTestJWT(t, time.Now())
	for _, tok := range []string{"", "not-a-jwt", "a.b", strings.Repeat("a", 5000)} {
		if _, err := svc.ParseAccess(tok); err == nil {
			t.Errorf("expected rejection for %q", truncate(tok))
		}
	}
}

func truncate(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

func TestParseRejectsRoleTamperingViaTokenVersion(t *testing.T) {
	// token_version is the server-side revocation handle; a stale token
	// should still parse (the auth use case re-checks token_version against
	// the DB), but ParseAccess itself must faithfully report the version.
	svc := newTestJWT(t, time.Now())
	u := testUser()
	tok, _, _ := svc.IssueAccess(u)
	claims, err := svc.ParseAccess(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TokenVersion != u.TokenVersion {
		t.Fatalf("token_version = %d, want %d", claims.TokenVersion, u.TokenVersion)
	}
}

var _ = interfaces.ErrUnauthorized
