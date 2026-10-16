package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/usecases/dashboard"
)

type DashboardHandler struct {
	svc *dashboard.Service
	log *slog.Logger
}

func NewDashboardHandler(svc *dashboard.Service, log *slog.Logger) *DashboardHandler {
	return &DashboardHandler{svc: svc, log: log}
}

func (h *DashboardHandler) Summary() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Summary(ctx)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
