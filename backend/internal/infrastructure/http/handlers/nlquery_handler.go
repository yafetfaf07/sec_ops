package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/nlquery"
	"sec_ops/internal/infrastructure/http/middleware"
)

type NLQueryHandler struct {
	svc *nlquery.Service
	log *slog.Logger
}

func NewNLQueryHandler(svc *nlquery.Service, log *slog.Logger) *NLQueryHandler {
	return &NLQueryHandler{svc: svc, log: log}
}

func (h *NLQueryHandler) Run() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		var req dtos.NLQueryRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query is required"})
			return
		}
		// Gemini generation can take a few seconds; keep comfortably under
		// the 15s client timeout the frontend's axios instance uses.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		defer cancel()
		out, err := h.svc.Run(ctx, *p, req.Query)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
