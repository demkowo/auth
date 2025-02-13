package app

import (
	handler "github.com/demkowo/auth/handlers"
	"github.com/gin-gonic/gin"
)

var (
	registered bool
)

func addAccountRoutes(router *gin.Engine, h handler.Account) {
	if registered {
		return
	}

	public := router.Group("/api/v1/auth")
	{
		public.POST("/add", h.Add)
		public.POST("/login", h.Login)
		public.POST("/refresh", h.RefreshToken)
		public.GET("/authenticate", h.AuthenticateByAPIKey)
	}

	protected := router.Group("/api/v1/auth")
	{
		protected.POST("/block", h.Block)
		protected.DELETE("/delete/:account_id", h.Delete)
		protected.GET("/find", h.Find)
		protected.GET("/get-by-email/:email", h.GetByEmail)
		protected.GET("/get/:account_id", h.GetById)
		protected.POST("/unblock", h.Unblock)
		protected.PUT("/edit/password", h.UpdatePassword)

		protected.POST("/api-key/:account_id", h.AddAPIKey)
		protected.DELETE("/delete/api-key", h.DeleteAPIKey)

		protected.POST("/roles/add/:account_id", h.AddAccountRole)
		protected.POST("/roles/delete/:account_id", h.DeleteAccountRole)
		protected.GET("/find/roles/:account_id", h.FindRolesByAccount)
		protected.POST("/edit-roles", h.UpdateRoles)
	}

	registered = true
}
