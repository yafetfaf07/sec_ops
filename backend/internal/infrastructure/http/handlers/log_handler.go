package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/ingest"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/infrastructure/http/middleware"
)

const ingestKeyHeader = "X-Ingest-Key"

type LogHandler struct {
	svc       *ingest.Service
	log       *slog.Logger
	ingestKey string // optional; empty disables header-based ingest auth
}

func NewLogHandler(svc *ingest.Service, log *slog.Logger, ingestKey string) *LogHandler {
	return &LogHandler{svc: svc, log: log, ingestKey: ingestKey}
}

// RequireIngestAuth allows either an admin JWT (checked by RequireAdmin
// upstream) or a constant-time match on X-Ingest-Key for automated shippers,
// applied before the admin-only chain so a valid key can bypass it.
func (h *LogHandler) RequireIngestAuth(adminChain gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.ingestKey != "" {
			supplied := c.GetHeader(ingestKeyHeader)
			if supplied != "" && constantTimeEqual(supplied, h.ingestKey) {
				c.Next()
				return
			}
		}
		adminChain(c)
	}
}

func (h *LogHandler) List() gin.HandlerFunc {
	return func(c *gin.Context) {
		var q dtos.LogListQuery
		if err := c.ShouldBindQuery(&q); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.List(ctx, q)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *LogHandler) Countries() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Countries(ctx)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *LogHandler) Ingest() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dtos.IngestRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"logs\": [...]}"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		out, err := h.svc.Ingest(ctx, actorFor(c), req.Logs)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusCreated, out)
	}
}

func (h *LogHandler) GenerateMock() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dtos.MockLogsRequest
		// An empty body is fine (defaults apply).
		_ = c.ShouldBindJSON(&req)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		out, err := h.svc.GenerateMock(ctx, actorFor(c), req)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusCreated, out)
	}
}

// actorFor returns the authenticated principal, or the system principal when
// the request was authorised via the ingest API key (RequireIngestAuth sets
// no principal in that case).
func actorFor(c *gin.Context) entities.Principal {
	if p := middleware.GetPrincipal(c); p != nil {
		return *p
	}
	return entities.SystemPrincipal
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
