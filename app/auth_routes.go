package app

import (
	"net/http"
	"strings"

	"github.com/demkowo/auth/config"
	handler "github.com/demkowo/auth/handlers"
	service "github.com/demkowo/auth/services"
	"github.com/demkowo/utils/resp"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var (
	registered bool
)

func addAccountRoutes(router *gin.Engine, h handler.Account, s service.Account) {
	if registered {
		return
	}

	public := router.Group("/api/v1/auth")
	{
		public.POST("/add", h.Add)
		public.GET("/authenticate", h.AuthenticateByAPIKey)
		public.POST("/login", h.Login)

		public.POST("/logout", h.Logout)
		public.GET("/login/:provider", h.OAuthLogin)
		public.GET("/callback/:provider", h.OAuthCallback)
	}

	protected := router.Group("/api/v1/auth", AuthMiddleware(s))
	{
		protected.POST("/refresh", h.RefreshToken)
		protected.POST("/block", h.Block)
		protected.DELETE("/delete/:account_id", h.Delete)
		protected.PUT("/edit/password", h.UpdatePassword)
		protected.GET("/find", h.Find)
		protected.POST("/get-by-email", h.GetByEmail)
		protected.GET("/get/:account_id", h.GetById)
		protected.POST("/unblock", h.Unblock)

		protected.POST("/api-key/:account_id", h.AddAPIKey)
		protected.DELETE("/delete/api-key", h.DeleteAPIKey)

		protected.POST("/edit-roles", h.UpdateRoles)
		protected.GET("/find/roles/:account_id", h.FindRolesByAccount)
		protected.POST("/roles/add/:account_id", h.AddAccountRole)
		protected.DELETE("/roles/delete/:account_id", h.DeleteAccountRoleById)
		protected.DELETE("/roles/delete", h.DeleteAccountRoleByName)
	}

	registered = true
}

func AuthMiddleware(s service.Account) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(resp.Error(http.StatusUnauthorized, "authorization header missing", nil).JSON())
			return
		}
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			c.AbortWithStatusJSON(resp.Error(http.StatusUnauthorized, "authorization header must start with 'Bearer '", nil).JSON())
			return
		}

		tokenOrKey := strings.TrimSpace(authHeader[len("bearer "):])

		jwtToken, err := jwt.Parse(tokenOrKey, func(token *jwt.Token) (interface{}, error) {
			return config.Values.Get().JWTSecret, nil
		})
		if err == nil && jwtToken.Valid {
			c.Next()
			return
		}

		_, apiErr := s.AuthenticateByAPIKey(tokenOrKey)
		if apiErr != nil {
			c.AbortWithStatusJSON(resp.Error(http.StatusUnauthorized, "invalid token or API key", nil).JSON())
			return
		}
		c.Next()
	}
}
