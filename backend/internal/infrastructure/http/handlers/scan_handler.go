package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/usecases/scan"
	"sec_ops/internal/domain/entities"
	"sec_ops/internal/infrastructure/http/middleware"
)

type ScanHandler struct {
	svc     *scan.Service
	log     *slog.Logger
	timeout time.Duration
}

func NewScanHandler(svc *scan.Service, log *slog.Logger, timeout time.Duration) *ScanHandler {
	return &ScanHandler{svc: svc, log: log, timeout: timeout}
}

// Daily runs the full scan pipeline synchronously. Authorised by
// RequireAdminOrScheduler (Cloud Scheduler OIDC or an admin JWT).
func (h *ScanHandler) Daily() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		trigger := entities.TriggerScheduler
		if !p.IsSystem() {
			trigger = entities.TriggerManual
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
		defer cancel()
		out, err := h.svc.Run(ctx, trigger, p.Actor())
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *ScanHandler) Manual() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
		defer cancel()
		out, err := h.svc.Run(ctx, entities.TriggerManual, p.Actor())
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
