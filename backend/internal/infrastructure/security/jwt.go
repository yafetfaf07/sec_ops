package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

const (
	issuer          = "secops-api"
	typAccess       = "access"
	typRefresh      = "refresh"
	maxTokenLength  = 4096
	clockSkewLeeway = 30 * time.Second
	headerHS256JWT  = `{"alg":"HS256","typ":"JWT"}`
)

var b64 = base64.RawURLEncoding

// JWTService issues and verifies HS256 JWTs with the standard library only.
// The algorithm is fixed: the header is compared byte-for-byte after
// decoding, so "alg":"none" or algorithm-confusion tokens are rejected.
type JWTService struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
}

var _ interfaces.TokenService = (*JWTService)(nil)

func NewJWTService(secret string, accessTTL, refreshTTL time.Duration, now func() time.Time) (*JWTService, error) {
	if len(secret) < 32 {
		return nil, errors.New("jwt secret must be at least 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	return &JWTService{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL, now: now}, nil
}

type jwtClaims struct {
	Iss  string `json:"iss"`
	Sub  string `json:"sub"`
	Typ  string `json:"typ"`
	Role string `json:"role"`
	Ver  int    `json:"ver"`
	Iat  int64  `json:"iat"`
	Nbf  int64  `json:"nbf"`
	Exp  int64  `json:"exp"`
	Jti  string `json:"jti"`
}

func (j *JWTService) IssueAccess(u *entities.User) (string, time.Time, error) {
	return j.issue(u, typAccess, j.accessTTL)
}

func (j *JWTService) IssueRefresh(u *entities.User) (string, time.Time, error) {
	return j.issue(u, typRefresh, j.refreshTTL)
}

func (j *JWTService) ParseAccess(token string) (*interfaces.TokenClaims, error) {
	return j.parse(token, typAccess)
}

func (j *JWTService) ParseRefresh(token string) (*interfaces.TokenClaims, error) {
	return j.parse(token, typRefresh)
}

func (j *JWTService) issue(u *entities.User, typ string, ttl time.Duration) (string, time.Time, error) {
	now := j.now().UTC()
	exp := now.Add(ttl)
	payload, err := json.Marshal(jwtClaims{
		Iss: issuer, Sub: u.ID, Typ: typ, Role: string(u.Role), Ver: u.TokenVersion,
		Iat: now.Unix(), Nbf: now.Unix(), Exp: exp.Unix(), Jti: uuid.NewString(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	signingInput := b64.EncodeToString([]byte(headerHS256JWT)) + "." + b64.EncodeToString(payload)
	return signingInput + "." + b64.EncodeToString(j.sign(signingInput)), exp, nil
}

func (j *JWTService) sign(input string) []byte {
	m := hmac.New(sha256.New, j.secret)
	m.Write([]byte(input))
	return m.Sum(nil)
}

func (j *JWTService) parse(token, wantTyp string) (*interfaces.TokenClaims, error) {
	invalid := fmt.Errorf("%w: invalid token", interfaces.ErrUnauthorized)
	if token == "" || len(token) > maxTokenLength {
		return nil, invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid
	}
	header, err := b64.DecodeString(parts[0])
	if err != nil || string(header) != headerHS256JWT {
		return nil, invalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, j.sign(parts[0]+"."+parts[1])) {
		return nil, invalid
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, invalid
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, invalid
	}

	now := j.now().UTC()
	if c.Iss != issuer || c.Typ != wantTyp || c.Sub == "" {
		return nil, invalid
	}
	if now.After(time.Unix(c.Exp, 0).Add(clockSkewLeeway)) {
		return nil, fmt.Errorf("%w: token expired", interfaces.ErrUnauthorized)
	}
	if now.Add(clockSkewLeeway).Before(time.Unix(c.Nbf, 0)) {
		return nil, invalid
	}
	role, err := enums.ParseRole(c.Role)
	if err != nil {
		return nil, invalid
	}
	if _, err := uuid.Parse(c.Sub); err != nil {
		return nil, invalid
	}
	return &interfaces.TokenClaims{UserID: c.Sub, Role: role, TokenVersion: c.Ver, ExpiresAt: time.Unix(c.Exp, 0).UTC()}, nil
}
