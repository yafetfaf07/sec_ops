package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// AccessLog writes one structured line per request. It never logs request
// bodies, query strings or headers: they can carry tokens and log data.
func AccessLog(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := c.Writer.Status()
		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		log.LogAttrs(c.Request.Context(), level, "http request",
			slog.String("request_id", c.GetString(RequestIDKey)),
			slog.String("method", c.Request.Method),
			slog.String("route", route),
			slog.Int("status", status),
			slog.Int64("latency_ms", time.Since(start).Milliseconds()),
			slog.String("user_id", c.GetString(UserIDKey)),
		)
	}
}

// Recovery converts a panic into a generic 500 and logs the cause. The panic
// value is never sent to the client.
func Recovery(log *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		log.ErrorContext(c.Request.Context(), "panic recovered",
			slog.String("request_id", c.GetString(RequestIDKey)),
			slog.String("route", c.FullPath()),
			slog.Any("panic", recovered),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	})
}

// UserIDKey is the gin.Context key set by the auth middleware (Phase 1).
// Handlers must read the actor from here, never from the request body.
const UserIDKey = "user_id"
