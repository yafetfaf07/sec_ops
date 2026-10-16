package user_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/user"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"time"
)

// ----------------------------------------------------------------- Fakes (reused from auth tests with additions)

type fakeUserRepo struct {
	users                map[string]*entities.User // keyed by ID
	byEmail              map[string]*entities.User
	activeAdminCount     int
	shouldFailCreate     error
	shouldFailFindByID   error
	shouldFailUpdateRole error
	shouldFailCount      error
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
	if r.shouldFailUpdateRole != nil {
		return r.shouldFailUpdateRole
	}
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
	return nil
}

func (r *fakeUserRepo) CountActiveAdmins(ctx context.Context) (int, error) {
	if r.shouldFailCount != nil {
		return 0, r.shouldFailCount
	}
	return r.activeAdminCount, nil
}

type fakePasswordHasher struct{}

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

type fakeClock struct{}

func (c *fakeClock) Now() time.Time {
	return time.Now().UTC()
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

func TestCreate_Success(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "newuser@example.com",
		Password: "securepassword123",
		Role:     "analyst",
	}

	resp, err := svc.Create(context.Background(), admin, req)

	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected user response, got nil")
	}
	if resp.Email != "newuser@example.com" {
		t.Errorf("Expected email newuser@example.com, got %s", resp.Email)
	}
	if resp.Role != enums.RoleAnalyst {
		t.Errorf("Expected role analyst, got %v", resp.Role)
	}

	// Verify user was created in repo
	created, err := users.FindByEmail(context.Background(), "newuser@example.com")
	if err != nil {
		t.Fatalf("Failed to find created user: %v", err)
	}
	if created.PasswordHash != "hashed:securepassword123" {
		t.Errorf("Expected password hash, got %s", created.PasswordHash)
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

func TestCreate_InvalidEmail(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "not-an-email",
		Password: "securepassword123",
		Role:     "analyst",
	}

	resp, err := svc.Create(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for invalid email")
	}
}

func TestCreate_ShortPassword(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "newuser@example.com",
		Password: "short",
		Role:     "analyst",
	}

	resp, err := svc.Create(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for short password, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for short password")
	}
}

func TestCreate_InvalidRole(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "newuser@example.com",
		Password: "securepassword123",
		Role:     "superadmin",
	}

	resp, err := svc.Create(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for invalid role, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for invalid role")
	}
}

func TestCreate_DuplicateEmail(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	// Create existing user
	existingUser := &entities.User{
		ID:    "user-1",
		Email: "existing@example.com",
		Role:  enums.RoleViewer,
	}
	users.users[existingUser.ID] = existingUser
	users.byEmail[existingUser.Email] = existingUser

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "existing@example.com",
		Password: "securepassword123",
		Role:     "analyst",
	}

	resp, err := svc.Create(context.Background(), admin, req)

	if !errors.Is(err, interfaces.ErrConflict) {
		t.Errorf("Expected ErrConflict for duplicate email, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for duplicate email")
	}
}

func TestCreate_NonAdminForbidden(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	analyst := entities.Principal{UserID: "analyst-1", Email: "analyst@example.com", Role: enums.RoleAnalyst}
	req := dtos.CreateUserRequest{
		Name:     "New User",
		Email:    "newuser@example.com",
		Password: "securepassword123",
		Role:     "viewer",
	}

	resp, err := svc.Create(context.Background(), analyst, req)

	if !errors.Is(err, interfaces.ErrForbidden) {
		t.Errorf("Expected ErrForbidden for non-admin, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for non-admin")
	}
}

func TestUpdate_RoleChange(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	targetUser := &entities.User{
		ID:           "user-1",
		Email:        "target@example.com",
		Role:         enums.RoleViewer,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[targetUser.ID] = targetUser
	users.activeAdminCount = 2 // Enough admins

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	newRole := "analyst"
	req := dtos.UpdateUserRequest{Role: &newRole}

	resp, err := svc.Update(context.Background(), admin, targetUser.ID, req)

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if resp.Role != enums.RoleAnalyst {
		t.Errorf("Expected role analyst, got %v", resp.Role)
	}

	// Verify token version was bumped
	updated, _ := users.FindByID(context.Background(), targetUser.ID)
	if updated.TokenVersion != 2 {
		t.Errorf("Expected token version 2, got %d", updated.TokenVersion)
	}

	// Verify audit entry
	if len(auditRepo.entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	entry := auditRepo.entries[0]
	if entry.ActionType != enums.AuditUserRoleChanged {
		t.Errorf("Expected action type USER_ROLE_CHANGED, got %v", entry.ActionType)
	}
}

func TestUpdate_DisableUser(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	targetUser := &entities.User{
		ID:           "user-1",
		Email:        "target@example.com",
		Role:         enums.RoleAnalyst,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[targetUser.ID] = targetUser
	users.activeAdminCount = 2

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	disabled := true
	req := dtos.UpdateUserRequest{Disabled: &disabled}

	resp, err := svc.Update(context.Background(), admin, targetUser.ID, req)

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if !resp.Disabled {
		t.Error("Expected user to be disabled")
	}

	// Verify token version was bumped
	updated, _ := users.FindByID(context.Background(), targetUser.ID)
	if updated.TokenVersion != 2 {
		t.Errorf("Expected token version 2, got %d", updated.TokenVersion)
	}
}

func TestUpdate_LastAdminGuard_DemoteLastAdmin(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	lastAdmin := &entities.User{
		ID:           "admin-1",
		Email:        "admin@example.com",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[lastAdmin.ID] = lastAdmin
	users.activeAdminCount = 1 // Only one active admin

	adminPrincipal := entities.Principal{UserID: "admin-2", Email: "admin2@example.com", Role: enums.RoleAdmin}
	newRole := "analyst"
	req := dtos.UpdateUserRequest{Role: &newRole}

	resp, err := svc.Update(context.Background(), adminPrincipal, lastAdmin.ID, req)

	if !errors.Is(err, interfaces.ErrConflict) {
		t.Errorf("Expected ErrConflict for demoting last admin, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response when preventing last admin demotion")
	}

	// Verify user wasn't changed
	unchanged, _ := users.FindByID(context.Background(), lastAdmin.ID)
	if unchanged.Role != enums.RoleAdmin {
		t.Error("Last admin should not have been demoted")
	}
}

func TestUpdate_LastAdminGuard_DisableLastAdmin(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	lastAdmin := &entities.User{
		ID:           "admin-1",
		Email:        "admin@example.com",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[lastAdmin.ID] = lastAdmin
	users.activeAdminCount = 1

	adminPrincipal := entities.Principal{UserID: "admin-2", Email: "admin2@example.com", Role: enums.RoleAdmin}
	disabled := true
	req := dtos.UpdateUserRequest{Disabled: &disabled}

	resp, err := svc.Update(context.Background(), adminPrincipal, lastAdmin.ID, req)

	if !errors.Is(err, interfaces.ErrConflict) {
		t.Errorf("Expected ErrConflict for disabling last admin, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response when preventing last admin disable")
	}

	// Verify user wasn't changed
	unchanged, _ := users.FindByID(context.Background(), lastAdmin.ID)
	if unchanged.Disabled {
		t.Error("Last admin should not have been disabled")
	}
}

func TestUpdate_AllowWhenMultipleAdmins(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin1 := &entities.User{
		ID:           "admin-1",
		Email:        "admin1@example.com",
		Role:         enums.RoleAdmin,
		TokenVersion: 1,
		Disabled:     false,
	}
	users.users[admin1.ID] = admin1
	users.activeAdminCount = 2 // Multiple active admins

	adminPrincipal := entities.Principal{UserID: "admin-2", Email: "admin2@example.com", Role: enums.RoleAdmin}
	newRole := "analyst"
	req := dtos.UpdateUserRequest{Role: &newRole}

	resp, err := svc.Update(context.Background(), adminPrincipal, admin1.ID, req)

	if err != nil {
		t.Fatalf("Update should succeed with multiple admins: %v", err)
	}
	if resp.Role != enums.RoleAnalyst {
		t.Errorf("Expected role to change to analyst, got %v", resp.Role)
	}
}

func TestUpdate_NonAdminForbidden(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	targetUser := &entities.User{
		ID:       "user-1",
		Email:    "target@example.com",
		Role:     enums.RoleViewer,
		Disabled: false,
	}
	users.users[targetUser.ID] = targetUser

	analyst := entities.Principal{UserID: "analyst-1", Email: "analyst@example.com", Role: enums.RoleAnalyst}
	newRole := "admin"
	req := dtos.UpdateUserRequest{Role: &newRole}

	resp, err := svc.Update(context.Background(), analyst, targetUser.ID, req)

	if !errors.Is(err, interfaces.ErrForbidden) {
		t.Errorf("Expected ErrForbidden for non-admin, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for non-admin")
	}
}

func TestUpdate_NoChanges(t *testing.T) {
	users := newFakeUserRepo()
	hasher := &fakePasswordHasher{}
	auditRepo := &fakeAuditRepo{}
	clock := &fakeClock{}
	auditSvc := audit.NewService(auditRepo, clock)
	tx := &fakeTxManager{}
	svc := user.NewService(users, hasher, auditSvc, tx)

	admin := entities.Principal{UserID: "admin-1", Email: "admin@example.com", Role: enums.RoleAdmin}
	req := dtos.UpdateUserRequest{} // No fields set

	resp, err := svc.Update(context.Background(), admin, "user-1", req)

	if !errors.Is(err, interfaces.ErrValidation) {
		t.Errorf("Expected ErrValidation for empty update, got %v", err)
	}
	if resp != nil {
		t.Error("Expected nil response for empty update")
	}
}
