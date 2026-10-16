// Package middleware holds Gin middleware: request id, logging, recovery,
// CORS, authentication and RBAC.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/entities"
	"sec_ops/internal/domain/enums"
	"sec_ops/internal/domain/interfaces"
)

const (
	// PrincipalKey holds the resolved *entities.Principal on gin.Context.
	PrincipalKey = "principal"
)

// Authenticator resolves a bearer access token to a principal.
type Authenticator interface {
	Authenticate(ctx context.Context, accessToken string) (*entities.Principal, error)
}

// RequireAuth validates the Authorization: Bearer token and stores the
// resulting principal on the context and on UserIDKey (for AccessLog).
func RequireAuth(auth Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if header == "" || token == header || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is missing or malformed"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		p, err := auth.Authenticate(ctx, token)
		if err != nil {
			status := http.StatusUnauthorized
			msg := "invalid or expired token"
			if !errors.Is(err, interfaces.ErrUnauthorized) {
				status = http.StatusInternalServerError
				msg = "internal server error"
			}
			c.AbortWithStatusJSON(status, gin.H{"error": msg})
			return
		}
		c.Set(PrincipalKey, p)
		c.Set(UserIDKey, p.UserID)
		c.Next()
	}
}

// RequireRole aborts with 403 unless the authenticated principal's role is
// allow(role) == true. RequireAuth must run first.
func RequireRole(allow func(enums.Role) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := GetPrincipal(c)
		if p == nil || !allow(p.Role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "you do not have permission to perform this action"})
			return
		}
		c.Next()
	}
}

// RequireAdmin allows only the admin role.
func RequireAdmin() gin.HandlerFunc { return RequireRole(enums.Role.CanAdminister) }

// RequireTriage allows admin and analyst roles.
func RequireTriage() gin.HandlerFunc { return RequireRole(enums.Role.CanTriage) }

// GetPrincipal returns the authenticated principal, or nil if RequireAuth did
// not run (e.g. a bug in route wiring). Handlers should treat nil as 401.
func GetPrincipal(c *gin.Context) *entities.Principal {
	v, ok := c.Get(PrincipalKey)
	if !ok {
		return nil
	}
	p, _ := v.(*entities.Principal)
	return p
}
