package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/database/dbmodels"
)

type UserRepository struct{ db *gorm.DB }

var _ interfaces.UserRepository = (*UserRepository)(nil)

func NewUserRepository(db *gorm.DB) *UserRepository { return &UserRepository{db: db} }

func toUser(m dbmodels.User) entities.User {
	return entities.User{
		ID: m.ID, Name: m.Name, Email: m.Email, PasswordHash: m.PasswordHash,
		Role: enums.Role(m.Role), TokenVersion: m.TokenVersion, Disabled: m.Disabled,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

func (r *UserRepository) Create(ctx context.Context, u *entities.User) error {
	now := time.Now().UTC()
	m := dbmodels.User{
		ID: uuid.NewString(), Name: u.Name, Email: u.Email, PasswordHash: u.PasswordHash,
		Role: string(u.Role), Disabled: u.Disabled, CreatedAt: now, UpdatedAt: now,
	}
	if err := conn(ctx, r.db).Create(&m).Error; err != nil {
		return translate(err)
	}
	*u = toUser(m)
	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, interfaces.ErrNotFound
	}
	var m dbmodels.User
	if err := conn(ctx, r.db).Where("id = ?", id).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	u := toUser(m)
	return &u, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	var m dbmodels.User
	if err := conn(ctx, r.db).Where("lower(email) = lower(?)", email).Take(&m).Error; err != nil {
		return nil, translate(err)
	}
	u := toUser(m)
	return &u, nil
}

func (r *UserRepository) List(ctx context.Context) ([]entities.User, error) {
	var ms []dbmodels.User
	if err := conn(ctx, r.db).Order("created_at ASC").Limit(1000).Find(&ms).Error; err != nil {
		return nil, translate(err)
	}
	out := make([]entities.User, len(ms))
	for i, m := range ms {
		out[i] = toUser(m)
	}
	return out, nil
}

func (r *UserRepository) update(ctx context.Context, id string, fields map[string]any) error {
	if _, err := uuid.Parse(id); err != nil {
		return interfaces.ErrNotFound
	}
	fields["updated_at"] = time.Now().UTC()
	fields["token_version"] = gorm.Expr("token_version + 1")
	res := conn(ctx, r.db).Model(&dbmodels.User{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return interfaces.ErrNotFound
	}
	return nil
}

func (r *UserRepository) UpdateRole(ctx context.Context, id string, role enums.Role) error {
	return r.update(ctx, id, map[string]any{"role": string(role)})
}

func (r *UserRepository) SetDisabled(ctx context.Context, id string, disabled bool) error {
	return r.update(ctx, id, map[string]any{"disabled": disabled})
}

func (r *UserRepository) BumpTokenVersion(ctx context.Context, id string) error {
	return r.update(ctx, id, map[string]any{})
}

func (r *UserRepository) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int64
	err := conn(ctx, r.db).Model(&dbmodels.User{}).
		Where("role = ? AND NOT disabled", string(enums.RoleAdmin)).Count(&n).Error
	return int(n), translate(err)
}
