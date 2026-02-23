package handler

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) oidcEnabled(c *gin.Context) {
	dataResponse(c, gin.H{"enabled": h.oidcAuth != nil})
}

// oidcRedirectURI derives the OIDC callback URL from the incoming request,
// so the same binary works for both local and production deployments without configuration.
func oidcRedirectURI(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + c.Request.Host + "/api/oidc/callback"
}

func (h *Handler) oidcLogin(c *gin.Context) {
	if h.oidcAuth == nil {
		badRequestError(c, "OIDC is not configured")
		return
	}

	authURL, err := h.oidcAuth.AuthURL(oidcRedirectURI(c))
	if err != nil {
		internalError(c, err, "oidc auth url")
		return
	}

	dataResponse(c, gin.H{"auth_url": authURL})
}

func (h *Handler) oidcCallback(c *gin.Context) {
	if h.oidcAuth == nil {
		badRequestError(c, "OIDC is not configured")
		return
	}

	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=oidc_failed")
		return
	}

	userID, err := h.oidcAuth.Callback(c.Request.Context(), state, code)
	if err != nil {
		slog.Error("OIDC callback failed", "error", err)
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=oidc_failed")
		return
	}

	slog.Info("OIDC login successful", "user", userID)
	h.createSession(c)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}
