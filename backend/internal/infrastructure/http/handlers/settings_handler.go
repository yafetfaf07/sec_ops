package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/settings"
	"sec_ops/internal/infrastructure/http/middleware"
)

type SettingsHandler struct {
	svc *settings.Service
	log *slog.Logger
}

func NewSettingsHandler(svc *settings.Service, log *slog.Logger) *SettingsHandler {
	return &SettingsHandler{svc: svc, log: log}
}

func (h *SettingsHandler) Get() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Get(ctx)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *SettingsHandler) Update() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		var req dtos.UpdateSettingsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"patch\": {...}}"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		out, err := h.svc.Update(ctx, *p, req.Patch)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
