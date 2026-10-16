// Package user implements admin user management (FR-SEC-030).
package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/application/usecases/auth"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

type Service struct {
	users  interfaces.UserRepository
	hasher interfaces.PasswordHasher
	audit  *audit.Service
	tx     interfaces.TxManager
}

func NewService(users interfaces.UserRepository, hasher interfaces.PasswordHasher, auditSvc *audit.Service, tx interfaces.TxManager) *Service {
	return &Service{users: users, hasher: hasher, audit: auditSvc, tx: tx}
}

func requireAdmin(p entities.Principal) error {
	if !p.Role.CanAdminister() {
		return interfaces.ErrForbidden
	}
	return nil
}

func (s *Service) List(ctx context.Context, p entities.Principal) ([]dtos.UserResponse, error) {
	if err := requireAdmin(p); err != nil {
		return nil, err
	}
	us, err := s.users.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dtos.UserResponse, len(us))
	for i := range us {
		out[i] = dtos.ToUserResponse(&us[i])
	}
	return out, nil
}

func (s *Service) Create(ctx context.Context, p entities.Principal, req dtos.CreateUserRequest) (*dtos.UserResponse, error) {
	if err := requireAdmin(p); err != nil {
		return nil, err
	}
	email, err := auth.NormalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	role, err := enums.ParseRole(req.Role)
	if err != nil {
		return nil, fmt.Errorf("%w: role must be admin, analyst or viewer", interfaces.ErrValidation)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return nil, fmt.Errorf("%w: name is required", interfaces.ErrValidation)
	}
	if l := len(req.Password); l < 12 || l > 72 {
		return nil, fmt.Errorf("%w: password must be 12-72 characters", interfaces.ErrValidation)
	}
	hash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, err
	}
	u := &entities.User{Name: name, Email: email, PasswordHash: hash, Role: role}
	err = s.tx.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.users.Create(ctx, u); err != nil {
			if errors.Is(err, interfaces.ErrConflict) {
				return fmt.Errorf("%w: a user with that email already exists", interfaces.ErrConflict)
			}
			return err
		}
		return s.audit.Record(ctx, audit.Event{
			Actor: p, Action: enums.AuditUserCreated, EntityType: "user", EntityID: u.ID,
			Details:  fmt.Sprintf("User %s created with role %s by %s.", email, role, p.Actor()),
			Metadata: map[string]string{"role": string(role)},
		})
	})
	if err != nil {
		return nil, err
	}
	resp := dtos.ToUserResponse(u)
	return &resp, nil
}

// Update changes role and/or disabled state. Both revoke the user's sessions.
// The last active admin cannot be demoted or disabled (lock-out guard).
func (s *Service) Update(ctx context.Context, p entities.Principal, id string, req dtos.UpdateUserRequest) (*dtos.UserResponse, error) {
	if err := requireAdmin(p); err != nil {
		return nil, err
	}
	if req.Role == nil && req.Disabled == nil {
		return nil, fmt.Errorf("%w: nothing to update", interfaces.ErrValidation)
	}
	var newRole enums.Role
	if req.Role != nil {
		r, err := enums.ParseRole(*req.Role)
		if err != nil {
			return nil, fmt.Errorf("%w: role must be admin, analyst or viewer", interfaces.ErrValidation)
		}
		newRole = r
	}
	var out *entities.User
	err := s.tx.WithinTx(ctx, func(ctx context.Context) error {
		target, err := s.users.FindByID(ctx, id)
		if err != nil {
			return err
		}
		losesAdmin := target.Role == enums.RoleAdmin && !target.Disabled &&
			((req.Role != nil && newRole != enums.RoleAdmin) || (req.Disabled != nil && *req.Disabled))
		if losesAdmin {
			n, err := s.users.CountActiveAdmins(ctx)
			if err != nil {
				return err
			}
			if n <= 1 {
				return fmt.Errorf("%w: cannot remove the last active admin", interfaces.ErrConflict)
			}
		}
		meta := map[string]string{}
		if req.Role != nil && newRole != target.Role {
			if err := s.users.UpdateRole(ctx, id, newRole); err != nil {
				return err
			}
			meta["old_role"], meta["new_role"] = string(target.Role), string(newRole)
		}
		if req.Disabled != nil && *req.Disabled != target.Disabled {
			if err := s.users.SetDisabled(ctx, id, *req.Disabled); err != nil {
				return err
			}
			meta["disabled"] = fmt.Sprint(*req.Disabled)
		}
		if len(meta) == 0 {
			out = target
			return nil
		}
		if err := s.audit.Record(ctx, audit.Event{
			Actor: p, Action: enums.AuditUserRoleChanged, EntityType: "user", EntityID: id,
			Details: fmt.Sprintf("User %s updated by %s.", target.Email, p.Actor()), Metadata: meta,
		}); err != nil {
			return err
		}
		out, err = s.users.FindByID(ctx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	resp := dtos.ToUserResponse(out)
	return &resp, nil
}
