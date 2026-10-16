package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/usecases/scan"
)

type ScanRunsHandler struct {
	svc *scan.RunsService
	log *slog.Logger
}

func NewScanRunsHandler(svc *scan.RunsService, log *slog.Logger) *ScanRunsHandler {
	return &ScanRunsHandler{svc: svc, log: log}
}

func (h *ScanRunsHandler) List() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.List(ctx)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
