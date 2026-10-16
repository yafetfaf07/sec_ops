package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	corsAllowMethods = "GET, POST, PUT, PATCH, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type, X-Request-ID"
	corsMaxAge       = "600"
)

// CORS allows only the exact origins configured. Credentials are allowed
// because the refresh token travels in an httpOnly cookie, which is also why a
// wildcard origin is never permitted (config rejects "*").
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimRight(o, "/")] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			// Not a browser cross-origin request (curl, Cloud Scheduler).
			c.Next()
			return
		}

		c.Header("Vary", "Origin")
		_, ok := allowed[origin]
		preflight := c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Method") != ""

		if !ok {
			if preflight {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin not allowed"})
				return
			}
			// No CORS headers: the browser blocks the response.
			c.Next()
			return
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Expose-Headers", RequestIDHeader)

		if preflight {
			c.Header("Access-Control-Allow-Methods", corsAllowMethods)
			c.Header("Access-Control-Allow-Headers", corsAllowHeaders)
			c.Header("Access-Control-Max-Age", corsMaxAge)
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
