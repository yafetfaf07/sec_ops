package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/auth"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

// ----------------------------------------------------------------- Fakes

type fakeUserRepo struct {
	users                 map[string]*entities.User // keyed by ID
	byEmail               map[string]*entities.User
	activeAdminCount      int
	shouldFailCreate      error
	shouldFailFindByID    error
	shouldFailFindByEmail error
	shouldFailCount       error
	bumpedTokenVersions   []string
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		users:   make(map[string]*entities.User),
		byEmail: make(map[string]*entities.User),
	}
}

func (r *fakeUserRepo) Create(ctx context.Context, u *entities.User) error {
	if r.shouldFailCreate != nil {
		return r.shouldFailCreate
	}
	if _, exists := r.byEmail[u.Email]; exists {
		return interfaces.ErrConflict
	}
	if u.ID == "" {
		u.ID = fmt.Sprintf("user-%d", len(r.users)+1)
	}
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt
	r.users[u.ID] = u
	r.byEmail[u.Email] = u
	return nil
}

func (r *fakeUserRepo) FindByID(ctx context.Context, id string) (*entities.User, error) {
	if r.shouldFailFindByID != nil {
		return nil, r.shouldFailFindByID
	}
	u, ok := r.users[id]
	if !ok {
		return nil, interfaces.ErrNotFound
	}
	return u, nil
}

func (r *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	if r.shouldFailFindByEmail != nil {
		return nil, r.shouldFailFindByEmail
	}
	u, ok := r.byEmail[email]
	if !ok {
		return nil, interfaces.ErrNotFound
	}
	return u, nil
}

func (r *fakeUserRepo) List(ctx context.Context) ([]entities.User, error) {
	out := make([]entities.User, 0, len(r.users))
	for _, u := range r.users {
		out = append(out, *u)
	}
	return out, nil
}

func (r *fakeUserRepo) UpdateRole(ctx context.Context, id string, role enums.Role) error {
	u, ok := r.users[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	u.Role = role
	u.TokenVersion++
	return nil
}

func (r *fakeUserRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	u, ok := r.users[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	u.Disabled = disabled
	u.TokenVersion++
	return nil
}

func (r *fakeUserRepo) BumpTokenVersion(ctx context.Context, id string) error {
	u, ok := r.users[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	u.TokenVersion++
	r.bumpedTokenVersions = append(r.bumpedTokenVersions, id)
	return nil
}

func (r *fakeUserRepo) CountActiveAdmins(ctx context.Context) (int, error) {
	if r.shouldFailCount != nil {
		return 0, r.shouldFailCount
	}
	return r.activeAdminCount, nil
}

type fakePasswordHasher struct {
	dummyCalled int
}

func (h *fakePasswordHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (h *fakePasswordHasher) Compare(hash, password string) error {
	expected := "hashed:" + password
	if hash != expected {
		return errors.New("wrong password")
	}
	return nil
}

func (h *fakePasswordHasher) CompareDummy(password string) {
	h.dummyCalled++
}

type fakeTokenService struct {
	accessTokenVersion  int
	refreshTokenVersion int
	shouldFailParse     error
}

func (t *fakeTokenService) IssueAccess(u *entities.User) (string, time.Time, error) {
	exp := time.Now().UTC().Add(15 * time.Minute)
	token := fmt.Sprintf("access:%s:v%d", u.ID, u.TokenVersion)
	return token, exp, nil
}

func (t *fakeTokenService) IssueRefresh(u *entities.User) (string, time.Time, error) {
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)
	token := fmt.Sprintf("refresh:%s:v%d", u.ID, u.TokenVersion)
	return token, exp, nil
}

func (t *fakeTokenService) ParseAccess(token string) (*interfaces.TokenClaims, error) {
	if t.shouldFailParse != nil {
		return nil, t.shouldFailParse
	}
	var userID string
	var version int
	if _, err := fmt.Sscanf(token, "access:%s:v%d", &userID, &version); err != nil {
		return nil, fmt.Errorf("%w: invalid token format", interfaces.ErrUnauthorized)
	}
	return &interfaces.TokenClaims{
		UserID:       userID,
		TokenVersion: version,
		ExpiresAt:    time.Now().UTC().Add(15 * time.Minute),
	}, nil
}

func (t *fakeTokenService) ParseRefresh(token string) (*interfaces.TokenClaims, error) {
	if t.shouldFailParse != nil {
		return nil, t.shouldFailParse
	}
	var userID string
	var version int
	if _, err := fmt.Sscanf(token, "refresh:%s:v%d", &userID, &version); err != nil {
		return nil, fmt.Errorf("%w: invalid token format", interfaces.ErrUnauthorized)
	}
	return &interfaces.TokenClaims{
		UserID:       userID,
		TokenVersion: version,
		ExpiresAt:    time.Now().UTC().Add(7 * 24 * time.Hour),
	}, nil
}

type fakeAuditRepo struct {
	entries []entities.AuditEntry
}

func (a *fakeAuditRepo) Append(ctx context.Context, e *entities.AuditEntry) error {
	e.ID = int64(len(a.entries) + 1)
	a.entries = append(a.entries, *e)
	return nil
}

func (a *fakeAuditRepo) List(ctx context.Context, q interfaces.AuditQuery) ([]entities.AuditEntry, error) {
	return a.entries, nil
}

func (a *fakeAuditRepo) Ascending(ctx context.Context, afterID int64, limit int) ([]entities.AuditEntry, error) {
	return a.entries, nil
}

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Now().UTC()
	}
	return c.now
}

type fakeTxManager struct {
	shouldFail error
}

func (tx *fakeTxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if tx.shouldFail != nil {
		return tx.shouldFail
	}
	return fn(ctx)
}

// ----------------------------------------------------------------- Tests

func TestLogin_Success(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	// Create a test user
	testUser := &entities.User{
		ID:           "user-1",
		Name:         "Test User",
		Email:        "test@example.com",
		PasswordHash: "hashed:password123",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[testUser.ID] = testUser
	users.byEmail[testUser.Email] = testUser

	req := dtos.LoginRequest{Email: "test@example.com", Password: "password123"}
	pair, err := svc.Login(context.Background(), req)

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if pair == nil {
		t.Fatal("Expected token pair, got nil")
	}
	if pair.Response.AccessToken == "" {
		t.Error("Expected access token")
	}
	if pair.RefreshToken == "" {
		t.Error("Expected refresh token")
	}
	if pair.Response.User.Email != "test@example.com" {
		t.Errorf("Expected user email test@example.com, got %s", pair.Response.User.Email)
	}

	// Verify audit entry was created
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserLogin {
		t.Errorf("Expected action type USER_LOGIN, got %v", entry.ActionType)
	}
	if entry.UserID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, entry.UserID)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	req := dtos.LoginRequest{Email: "unknown@example.com", Password: "password123"}
	pair, err := svc.Login(context.Background(), req)

	if !errors.Is(err, interfaces.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}
	if pair != nil {
		t.Error("Expected nil token pair")
	}
	// Verify CompareDummy was called to prevent timing attacks
	if hasher.dummyCalled != 1 {
		t.Errorf("Expected CompareDummy to be called once, got %d", hasher.dummyCalled)
	}
	// Verify failure was audited
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserLoginFailed {
		t.Errorf("Expected action type USER_LOGIN_FAILED, got %v", entry.ActionType)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	testUser := &entities.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:correctpassword",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[testUser.ID] = testUser
	users.byEmail[testUser.Email] = testUser

	req := dtos.LoginRequest{Email: "test@example.com", Password: "wrongpassword"}
	pair, err := svc.Login(context.Background(), req)

	if !errors.Is(err, interfaces.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}
	if pair != nil {
		t.Error("Expected nil token pair")
	}
	// Verify failure was audited
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserLoginFailed {
		t.Errorf("Expected action type USER_LOGIN_FAILED, got %v", entry.ActionType)
	}
	if entry.Metadata["reason"] != "wrong password" {
		t.Errorf("Expected reason 'wrong password', got %s", entry.Metadata["reason"])
	}
}

func TestLogin_DisabledUser(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	testUser := &entities.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:password123",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     true,
	}
	users.users[testUser.ID] = testUser
	users.byEmail[testUser.Email] = testUser

	req := dtos.LoginRequest{Email: "test@example.com", Password: "password123"}
	pair, err := svc.Login(context.Background(), req)

	if !errors.Is(err, interfaces.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}
	if pair != nil {
		t.Error("Expected nil token pair")
	}
	// Verify failure was audited with appropriate reason
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserLoginFailed {
		t.Errorf("Expected action type USER_LOGIN_FAILED, got %v", entry.ActionType)
	}
	if entry.Metadata["reason"] != "account disabled" {
		t.Errorf("Expected reason 'account disabled', got %s", entry.Metadata["reason"])
	}
}

func TestRefresh_TokenVersionMismatch(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	testUser := &entities.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:password123",
		Role:         enums.RoleAdmin,
		TokenVersion: 2, // Bumped after token was issued
		Disabled:     false,
	}
	users.users[testUser.ID] = testUser
	users.byEmail[testUser.Email] = testUser

	// Token with old version
	oldRefreshToken := "refresh:user-1:v1"

	pair, err := svc.Refresh(context.Background(), oldRefreshToken)

	if !errors.Is(err, interfaces.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized for version mismatch, got %v", err)
	}
	if pair != nil {
		t.Error("Expected nil token pair for stale token")
	}
}

func TestAuthenticate_TokenVersionMismatch(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	testUser := &entities.User{
		ID:           "user-1",
		Email:        "test@example.com",
		Role:         enums.RoleAdmin,
		TokenVersion: 2, // Bumped after token was issued
		Disabled:     false,
	}
	users.users[testUser.ID] = testUser

	// Token with old version
	oldAccessToken := "access:user-1:v1"

	principal, err := svc.Authenticate(context.Background(), oldAccessToken)

	if !errors.Is(err, interfaces.ErrUnauthorized) {
		t.Errorf("Expected ErrUnauthorized for version mismatch, got %v", err)
	}
	if principal != nil {
		t.Error("Expected nil principal for stale token")
	}
}

func TestEnsureBootstrapAdmin_CreatesWhenNoneExist(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	users.activeAdminCount = 0

	created, err := svc.EnsureBootstrapAdmin(context.Background(), "Bootstrap Admin", "admin@example.com", "password123456")

	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin failed: %v", err)
	}
	if !created {
		t.Error("Expected admin to be created")
	}

	// Verify admin was created
	admin, err := users.FindByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Failed to find created admin: %v", err)
	}
	if admin.Role != enums.RoleAdmin {
		t.Errorf("Expected role admin, got %v", admin.Role)
	}
	if admin.Name != "Bootstrap Admin" {
		t.Errorf("Expected name 'Bootstrap Admin', got %s", admin.Name)
	}

	// Verify audit entry
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserCreated {
		t.Errorf("Expected action type USER_CREATED, got %v", entry.ActionType)
	}
}

func TestEnsureBootstrapAdmin_NoOpWhenAdminExists(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	users.activeAdminCount = 1

	created, err := svc.EnsureBootstrapAdmin(context.Background(), "Bootstrap Admin", "admin@example.com", "password123456")

	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin failed: %v", err)
	}
	if created {
		t.Error("Expected no admin to be created when one already exists")
	}

	// Verify no admin was created
	_, err = users.FindByEmail(context.Background(), "admin@example.com")
	if !errors.Is(err, interfaces.ErrNotFound) {
		t.Error("Expected no admin to be created")
	}

	// Verify no audit entry
	if len(auditRepo.entries) != 0 {
		t.Errorf("Expected 0 audit entries, got %d", len(auditRepo.entries))
	}
}

func TestEnsureBootstrapAdmin_NoOpWhenEmailEmpty(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	users.activeAdminCount = 0

	created, err := svc.EnsureBootstrapAdmin(context.Background(), "Bootstrap Admin", "", "password123456")

	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin failed: %v", err)
	}
	if created {
		t.Error("Expected no admin to be created when email is empty")
	}

	// Verify no audit entry
	if len(auditRepo.entries) != 0 {
		t.Errorf("Expected 0 audit entries, got %d", len(auditRepo.entries))
	}
}

func TestLogin_EmailCaseInsensitive(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	tokens := &fakeTokenService{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := auth.NewService(users, hasher, hasher, tokens, auditSvc, tx)

	testUser := &entities.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: "hashed:password123",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[testUser.ID] = testUser
	users.byEmail["test@example.com"] = testUser

	// Login with different case
	req := dtos.LoginRequest{Email: "TEST@EXAMPLE.COM", Password: "password123"}
	pair, err := svc.Login(context.Background(), req)

	if err != nil {
		t.Fatalf("Login with different case failed: %v", err)
	}
	if pair == nil {
		t.Fatal("Expected token pair")
	}
}
