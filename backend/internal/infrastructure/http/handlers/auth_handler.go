package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sec_ops/internal/application/dtos"
	"sec_ops/internal/application/usecases/auth"
	"sec_ops/internal/domain/interfaces"
	"sec_ops/internal/infrastructure/http/middleware"
)

const refreshCookiePath = "/api/v1/auth/refresh"
const refreshCookieName = "refresh_token"

type AuthHandler struct {
	svc          *auth.Service
	log          *slog.Logger
	cookieSecure bool
	sameSiteNone bool
}

func NewAuthHandler(svc *auth.Service, log *slog.Logger, cookieSecure, sameSiteNone bool) *AuthHandler {
	return &AuthHandler{svc: svc, log: log, cookieSecure: cookieSecure, sameSiteNone: sameSiteNone}
}

func (h *AuthHandler) setRefreshCookie(c *gin.Context, token string, maxAge int) {
	if h.sameSiteNone {
		c.SetSameSite(http.SameSiteNoneMode)
	} else {
		c.SetSameSite(http.SameSiteLaxMode)
	}
	c.SetCookie(refreshCookieName, token, maxAge, refreshCookiePath, "", h.cookieSecure, true)
}

func (h *AuthHandler) Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dtos.LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		pair, err := h.svc.Login(ctx, req)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		h.setRefreshCookie(c, pair.RefreshToken, int(time.Until(pair.RefreshExpiresAt).Seconds()))
		c.JSON(http.StatusOK, pair.Response)
	}
}

func (h *AuthHandler) Refresh() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(refreshCookieName)
		if err != nil || token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token missing"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		pair, err := h.svc.Refresh(ctx, token)
		if err != nil {
			Fail(c, h.log, err)
			return
		}
		h.setRefreshCookie(c, pair.RefreshToken, int(time.Until(pair.RefreshExpiresAt).Seconds()))
		c.JSON(http.StatusOK, pair.Response)
	}
}

func (h *AuthHandler) Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := c.Cookie(refreshCookieName); err == nil && token != "" {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()
			_ = h.svc.Logout(ctx, token)
		}
		// Clear on the exact path/attributes the cookie was set with; a
		// mismatched path leaves the cookie in place (the bug this fixes).
		h.setRefreshCookie(c, "", -1)
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
	}
}

func (h *AuthHandler) Me() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := middleware.GetPrincipal(c)
		if p == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		resp, err := h.svc.Me(ctx, *p)
		if err != nil {
			if errors.Is(err, interfaces.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}
			Fail(c, h.log, err)
			return
		}
		c.JSON(http.StatusOK, resp)
	}
}
