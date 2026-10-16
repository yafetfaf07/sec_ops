package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/http/middleware"
)

// Fail maps a domain/sentinel error to an HTTP status and writes
// {"error": "..."}. Unmapped errors become a generic 500 and are logged with
// the request id; the error text itself is never sent to the client.
func Fail(c *gin.Context, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, interfaces.ErrValidation):
		c.JSON(http.StatusBadRequest, gin.H{"error": publicMessage(err, interfaces.ErrValidation)})
	case errors.Is(err, interfaces.ErrUnauthorized):
		c.JSON(http.StatusUnauthorized, gin.H{"error": publicMessage(err, interfaces.ErrUnauthorized)})
	case errors.Is(err, interfaces.ErrForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "you do not have permission to perform this action"})
	case errors.Is(err, interfaces.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, interfaces.ErrInvalidTransition):
		c.JSON(http.StatusConflict, gin.H{"error": publicMessage(err, interfaces.ErrInvalidTransition)})
	case errors.Is(err, interfaces.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": publicMessage(err, interfaces.ErrConflict)})
	case errors.Is(err, interfaces.ErrImmutable):
		c.JSON(http.StatusConflict, gin.H{"error": "this record cannot be modified"})
	case errors.Is(err, interfaces.ErrQuotaExceeded):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": publicMessage(err, interfaces.ErrQuotaExceeded)})
	case errors.Is(err, interfaces.ErrUpstreamUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "a required upstream service is unavailable"})
	default:
		log.ErrorContext(c.Request.Context(), "unhandled error",
			slog.String("request_id", c.GetString(middleware.RequestIDKey)),
			slog.String("route", c.FullPath()), slog.String("error", err.Error()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// publicMessage returns the wrapped detail for sentinels where the message
// is safe and useful to the caller (validation reasons, "already exists",
// quota wording), falling back to the sentinel's own text.
func publicMessage(err, sentinel error) string {
	if msg := err.Error(); msg != "" && msg != sentinel.Error() {
		return msg
	}
	return sentinel.Error()
}
