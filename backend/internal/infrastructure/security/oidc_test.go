package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// jwksServer serves a single RSA public key under the given kid, mimicking
// Google's certs endpoint.
func jwksServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big1(pub.E)
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{"kty": "RSA", "kid": kid, "alg": "RS256", "n": n, "e": e}},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func big1(e int) []byte {
	// Minimal big-endian encoding of a small odd exponent (65537 -> 3 bytes).
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://accounts.google.com", "aud": "https://secops-api.example.run.app",
		"email": "scheduler@my-project.iam.gserviceaccount.com", "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
}

func newVerifier(t *testing.T, srv *httptest.Server, now time.Time) *OIDCVerifier {
	return NewOIDCVerifier("https://secops-api.example.run.app", "scheduler@my-project.iam.gserviceaccount.com",
		srv.URL, srv.Client(), fixedNow(now))
}

func TestOIDCVerifyAcceptsValidToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	tok := signRS256(t, priv, "key1", validClaims(now))
	if err := v.Verify(t.Context(), tok); err != nil {
		t.Fatalf("expected valid token to verify, got %v", err)
	}
}

func TestOIDCVerifyRejectsWrongAudience(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	claims := validClaims(now)
	claims["aud"] = "https://someone-elses-service.run.app"
	tok := signRS256(t, priv, "key1", claims)
	if err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected rejection for wrong audience")
	}
}

func TestOIDCVerifyRejectsWrongServiceAccount(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	claims := validClaims(now)
	claims["email"] = "attacker@evil-project.iam.gserviceaccount.com"
	tok := signRS256(t, priv, "key1", claims)
	if err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected rejection for an unexpected service account email")
	}
}

func TestOIDCVerifyRejectsUnverifiedEmail(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	claims := validClaims(now)
	claims["email_verified"] = false
	tok := signRS256(t, priv, "key1", claims)
	if err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected rejection when email_verified is false")
	}
}

func TestOIDCVerifyRejectsExpiredToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	issued := time.Now().UTC().Add(-2 * time.Hour)
	v := newVerifier(t, srv, issued.Add(2*time.Hour)) // verifier clock is "now", well past exp
	tok := signRS256(t, priv, "key1", validClaims(issued))
	if err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected rejection for expired token")
	}
}

func TestOIDCVerifyRejectsTamperedSignature(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &priv.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	tok := signRS256(t, priv, "key1", validClaims(now))
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	if err := v.Verify(t.Context(), tampered); err == nil {
		t.Fatal("expected rejection for tampered signature")
	}
}

// TestOIDCVerifyRejectsForeignKey ensures a token signed by a DIFFERENT key
// than the one Google's JWKS actually serves is rejected, even if the token
// claims a kid that happens to exist (key-confusion / unverified-source test).
func TestOIDCVerifyRejectsForeignKey(t *testing.T) {
	realKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "key1", &realKey.PublicKey)
	defer srv.Close()

	now := time.Now().UTC()
	v := newVerifier(t, srv, now)
	tok := signRS256(t, attackerKey, "key1", validClaims(now)) // signed with the wrong private key
	if err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected rejection for a token signed by a key not in the JWKS")
	}
}

func TestOIDCNotConfiguredRejectsEverything(t *testing.T) {
	v := NewOIDCVerifier("", "", "", nil, nil)
	if v.Configured() {
		t.Fatal("expected Configured() == false")
	}
	if err := v.Verify(t.Context(), "anything"); err == nil {
		t.Fatal("an unconfigured verifier must reject all tokens")
	}
}
