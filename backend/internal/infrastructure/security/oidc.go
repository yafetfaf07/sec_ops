package security

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"sec_ops/internal/domain/interfaces"
)

// GoogleCertsURL serves Google's OIDC signing keys (JWKS).
const GoogleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// OIDCVerifier validates Google-signed ID tokens such as the ones Cloud
// Scheduler attaches with --oidc-service-account-email. It checks the RS256
// signature against Google's JWKS, issuer, audience, expiry, and that the
// token belongs to the expected, verified service-account email.
type OIDCVerifier struct {
	audience string
	email    string
	certsURL string
	client   *http.Client
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func NewOIDCVerifier(audience, email, certsURL string, client *http.Client, now func() time.Time) *OIDCVerifier {
	if certsURL == "" {
		certsURL = GoogleCertsURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &OIDCVerifier{audience: audience, email: strings.ToLower(email), certsURL: certsURL, client: client, now: now}
}

func (v *OIDCVerifier) Configured() bool { return v != nil && v.audience != "" && v.email != "" }

type oidcClaims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
}

// Verify returns nil only for a valid token issued to the configured service account.
func (v *OIDCVerifier) Verify(ctx context.Context, token string) error {
	invalid := fmt.Errorf("%w: invalid scheduler token", interfaces.ErrUnauthorized)
	if !v.Configured() || token == "" || len(token) > 8192 {
		return invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalid
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return invalid
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Alg != "RS256" || header.Kid == "" {
		return invalid
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return invalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return invalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return invalid
	}

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return invalid
	}
	var c oidcClaims
	if json.Unmarshal(payload, &c) != nil {
		return invalid
	}
	now := v.now()
	if c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com" {
		return invalid
	}
	if c.Aud != v.audience || !c.EmailVerified || strings.ToLower(c.Email) != v.email {
		return invalid
	}
	if now.After(time.Unix(c.Exp, 0).Add(clockSkewLeeway)) || now.Add(clockSkewLeeway).Before(time.Unix(c.Iat, 0)) {
		return invalid
	}
	return nil
}

func (v *OIDCVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && v.now().Sub(v.fetchedAt) < 6*time.Hour {
		return k, nil
	}
	// Unknown kid: Google rotates keys, so refetch (at most once a minute).
	if v.now().Sub(v.fetchedAt) < time.Minute && v.keys != nil {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
		return nil, errors.New("unknown key id")
	}
	keys, err := v.fetch(ctx)
	if err != nil {
		return nil, err
	}
	v.keys, v.fetchedAt = keys, v.now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown key id")
}

func (v *OIDCVerifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid, Kty, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err1 := b64.DecodeString(k.N)
		eb, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) > 4 {
			continue
		}
		e := 0
		for _, by := range eb {
			e = e<<8 | int(by)
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	if len(out) == 0 {
		return nil, errors.New("no RSA keys in jwks")
	}
	return out, nil
}
