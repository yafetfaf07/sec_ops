package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/entities"
)

// SchedulerVerifier checks a Google OIDC token belongs to the configured
// Cloud Scheduler service account.
type SchedulerVerifier interface {
	Configured() bool
	Verify(ctx context.Context, token string) error
}

// RequireAdminOrScheduler allows POST /scan/daily to be called either by an
// authenticated admin (manual trigger from the dashboard) or by Cloud
// Scheduler's OIDC-signed request. Exactly one of the two must succeed; a
// missing/invalid token under either scheme is rejected.
func RequireAdminOrScheduler(auth Authenticator, oidc SchedulerVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearer(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is missing or malformed"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		if oidc.Configured() {
			if err := oidc.Verify(ctx, token); err == nil {
				c.Set(PrincipalKey, &entities.SystemPrincipal)
				c.Set(UserIDKey, entities.SystemPrincipal.UserID)
				c.Next()
				return
			}
		}
		if p, err := auth.Authenticate(ctx, token); err == nil && p.Role.CanAdminister() {
			c.Set(PrincipalKey, p)
			c.Set(UserIDKey, p.UserID)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "requires an admin token or a valid Cloud Scheduler OIDC token"})
	}
}

func extractBearer(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return ""
	}
	return header[len(prefix):]
}
