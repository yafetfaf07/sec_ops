package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/audit"
	"sec_ops/internal/domain/interfaces"
)

type AuditHandler struct {
	svc *audit.Service
	log *slog.Logger
}

func NewAuditHandler(svc *audit.Service, log *slog.Logger) *AuditHandler {
	return &AuditHandler{svc: svc, log: log}
}

func (h *AuditHandler) List() gin.HandlerFunc {
	return func(c *gin.Context) {
		var q dtos.AuditListQuery
		if err := c.ShouldBindQuery(&q); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters"})
			return
		}
		aq := interfaces.AuditQuery{ActionType: q.ActionType, UserID: q.UserID, Limit: q.Limit}
		if q.From != "" {
			t, err := time.Parse(time.RFC3339, q.From)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("from must be RFC3339: %v", err)})
				return
			}
			aq.Since = &t
		}
		if q.To != "" {
			t, err := time.Parse(time.RFC3339, q.To)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("to must be RFC3339: %v", err)})
				return
			}
			aq.Until = &t
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.List(ctx, aq)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *AuditHandler) Verify() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
		defer cancel()
		out, err := h.svc.Verify(ctx)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
