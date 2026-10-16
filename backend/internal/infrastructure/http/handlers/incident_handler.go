package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/incident"
	"sec_ops/internal/infrastructure/http/middleware"
)

type IncidentHandler struct {
	svc *incident.Service
	log *slog.Logger
}

func NewIncidentHandler(svc *incident.Service, log *slog.Logger) *IncidentHandler {
	return &IncidentHandler{svc: svc, log: log}
}

func (h *IncidentHandler) List() gin.HandlerFunc {
	return func(c *gin.Context) {
		var q dtos.IncidentListQuery
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

func (h *IncidentHandler) Get() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Get(ctx, c.Param("id"))
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *IncidentHandler) Acknowledge() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Acknowledge(ctx, *p, c.Param("id"))
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *IncidentHandler) Resolve() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		var req dtos.ResolveRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "a resolution comment is required"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Resolve(ctx, *p, c.Param("id"), req)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
