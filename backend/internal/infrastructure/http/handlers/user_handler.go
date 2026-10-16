package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/user"
	"sec_ops/internal/infrastructure/http/middleware"
)

type UserHandler struct {
	svc *user.Service
	log *slog.Logger
}

func NewUserHandler(svc *user.Service, log *slog.Logger) *UserHandler {
	return &UserHandler{svc: svc, log: log}
}

func (h *UserHandler) List() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.List(ctx, *p)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}

func (h *UserHandler) Create() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		var req dtos.CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name, email, password and role are required"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Create(ctx, *p, req)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusCreated, out)
	}
}

func (h *UserHandler) UpdateRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		id := c.Param("id")
		var req dtos.UpdateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		out, err := h.svc.Update(ctx, *p, id, req)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, out)
	}
}
