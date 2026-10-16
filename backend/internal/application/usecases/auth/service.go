// Package auth implements login, token refresh, logout and principal
// resolution (FR-SEC-030).
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// DummyComparer equalises login timing for unknown emails.
type DummyComparer interface {
	CompareDummy(password string)
}

type Service struct {
	users  interfaces.UserRepository
	hasher interfaces.PasswordHasher
	dummy  DummyComparer
	tokens interfaces.TokenService
	audit  *audit.Service
	tx     interfaces.TxManager
}

func NewService(users interfaces.UserRepository, hasher interfaces.PasswordHasher, dummy DummyComparer,
	tokens interfaces.TokenService, auditSvc *audit.Service, tx interfaces.TxManager) *Service {
	return &Service{users: users, hasher: hasher, dummy: dummy, tokens: tokens, audit: auditSvc, tx: tx}
}

var errBadCredentials = fmt.Errorf("%w: invalid email or password", interfaces.ErrUnauthorized)

func NormalizeEmail(s string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(s))
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || len(e) > 320 {
		return "", fmt.Errorf("%w: a valid email address is required", interfaces.ErrValidation)
	}
	return e, nil
}

// Login verifies credentials. All failures look identical to the caller
// (no account enumeration); the reason is recorded in the audit log.
func (s *Service) Login(ctx context.Context, req dtos.LoginRequest) (*dtos.TokenPair, error) {
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return nil, errBadCredentials
	}
	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, interfaces.ErrNotFound) {
		s.dummy.CompareDummy(req.Password)
		s.recordFailure(ctx, email, "unknown email")
		return nil, errBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := s.hasher.Compare(user.PasswordHash, req.Password); err != nil {
		s.recordFailure(ctx, email, "wrong password")
		return nil, errBadCredentials
	}
	if user.Disabled {
		s.recordFailure(ctx, email, "account disabled")
		return nil, errBadCredentials
	}
	pair, err := s.issue(user)
	if err != nil {
		return nil, err
	}
	p := principalOf(user)
	if err := s.audit.Record(ctx, audit.Event{
		Actor: p, Action: enums.AuditUserLogin, EntityType: "user", EntityID: user.ID,
		Details: fmt.Sprintf("User %s signed in.", user.Email),
	}); err != nil {
		return nil, err
	}
	return pair, nil
}

func (s *Service) recordFailure(ctx context.Context, email, reason string) {
	_ = s.audit.Record(ctx, audit.Event{
		Actor: entities.SystemPrincipal, Action: enums.AuditUserLoginFailed, EntityType: "user",
		Details:  "Failed sign-in attempt.",
		Metadata: map[string]string{"email": email, "reason": reason},
	})
}

// Refresh rotates both tokens. A refresh token minted before the user's
// token_version changed (logout, role change, disable) is rejected.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*dtos.TokenPair, error) {
	claims, err := s.tokens.ParseRefresh(refreshToken)
	if err != nil {
		return nil, err
	}
	user, err := s.validUser(ctx, claims)
	if err != nil {
		return nil, err
	}
	return s.issue(user)
}

// Logout revokes every session of the user by bumping token_version.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.tokens.ParseRefresh(refreshToken)
	if err != nil {
		return nil // nothing to revoke; logout is idempotent
	}
	user, err := s.validUser(ctx, claims)
	if err != nil {
		return nil
	}
	return s.users.BumpTokenVersion(ctx, user.ID)
}

// Authenticate resolves an access token to a principal, re-checking the user
// row so disabled users and stale roles take effect immediately.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (*entities.Principal, error) {
	claims, err := s.tokens.ParseAccess(accessToken)
	if err != nil {
		return nil, err
	}
	user, err := s.validUser(ctx, claims)
	if err != nil {
		return nil, err
	}
	p := principalOf(user)
	return &p, nil
}

func (s *Service) Me(ctx context.Context, p entities.Principal) (*dtos.UserResponse, error) {
	u, err := s.users.FindByID(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	resp := dtos.ToUserResponse(u)
	return &resp, nil
}

func (s *Service) validUser(ctx context.Context, c *interfaces.TokenClaims) (*entities.User, error) {
	user, err := s.users.FindByID(ctx, c.UserID)
	if errors.Is(err, interfaces.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown user", interfaces.ErrUnauthorized)
	}
	if err != nil {
		return nil, err
	}
	if user.Disabled || user.TokenVersion != c.TokenVersion {
		return nil, fmt.Errorf("%w: session revoked", interfaces.ErrUnauthorized)
	}
	return user, nil
}

func (s *Service) issue(u *entities.User) (*dtos.TokenPair, error) {
	access, accessExp, err := s.tokens.IssueAccess(u)
	if err != nil {
		return nil, err
	}
	refresh, refreshExp, err := s.tokens.IssueRefresh(u)
	if err != nil {
		return nil, err
	}
	return &dtos.TokenPair{
		Response:         dtos.LoginResponse{AccessToken: access, TokenType: "Bearer", ExpiresAt: accessExp, User: dtos.ToUserResponse(u)},
		RefreshToken:     refresh,
		RefreshExpiresAt: refreshExp,
	}, nil
}

func principalOf(u *entities.User) entities.Principal {
	return entities.Principal{UserID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role}
}

// EnsureBootstrapAdmin creates the first admin from config when the users
// table has no active admin. It never overwrites an existing account.
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, name, email, password string) (bool, error) {
	if email == "" {
		return false, nil
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return false, err
	}
	created := false
	err = s.tx.WithinTx(ctx, func(ctx context.Context) error {
		n, err := s.users.CountActiveAdmins(ctx)
		if err != nil || n > 0 {
			return err
		}
		if _, err := s.users.FindByEmail(ctx, email); err == nil {
			return nil // exists but is not an active admin: leave it to a human
		} else if !errors.Is(err, interfaces.ErrNotFound) {
			return err
		}
		hash, err := s.hasher.Hash(password)
		if err != nil {
			return err
		}
		u := &entities.User{Name: name, Email: email, PasswordHash: hash, Role: enums.RoleAdmin}
		if err := s.users.Create(ctx, u); err != nil {
			return err
		}
		created = true
		return s.audit.Record(ctx, audit.Event{
			Actor: entities.SystemPrincipal, Action: enums.AuditUserCreated, EntityType: "user", EntityID: u.ID,
			Details: fmt.Sprintf("Bootstrap admin %s created.", email),
		})
	})
	return created, err
}
