package handler

import (
	"log"
	"net/http"
	"strings"
	"time"

	model "github.com/demkowo/auth/models"
	service "github.com/demkowo/auth/services"
	"github.com/demkowo/utils/helper"
	"github.com/demkowo/utils/resp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type Account interface {
	Add(*gin.Context)
	Block(*gin.Context)
	Delete(*gin.Context)
	Find(*gin.Context)
	GetByEmail(*gin.Context)
	GetById(*gin.Context)
	Login(*gin.Context)
	RefreshToken(*gin.Context)
	Unblock(*gin.Context)
	UpdatePassword(*gin.Context)

	AddAPIKey(*gin.Context)
	AuthenticateByAPIKey(*gin.Context)
	DeleteAPIKey(*gin.Context)

	AddAccountRole(*gin.Context)
	DeleteAccountRoleById(*gin.Context)
	DeleteAccountRoleByName(*gin.Context)
	FindRolesByAccount(*gin.Context)
	UpdateRoles(*gin.Context)

	Logout(c *gin.Context)
	OAuthLogin(c *gin.Context)
	OAuthCallback(c *gin.Context)
}

var (
	help = helper.NewHelper()
)

type account struct {
	service service.Account
}

func NewAccount(service service.Account) Account {
	return &account{service: service}
}

func (h *account) Add(c *gin.Context) {
	var acc model.Account

	if !help.BindJSON(c, &acc) {
		return
	}

	if err := acc.Validate(); err != nil {
		c.JSON(err.JSON())
		return
	}

	account, err := h.service.Add(&acc)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}
	c.JSON(resp.New(http.StatusCreated, "account registered successfully", []interface{}{account}).JSON())
}

func (h *account) Block(c *gin.Context) {
	var req struct {
		AccountId string `json:"account_id" binding:"required"`
		Until     string `json:"until" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}
	var until time.Time
	if !help.ParseTime(c, "2006-01-02", req.Until, &until) {
		return
	}
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", req.AccountId, &accountId) {
		return
	}
	account, err := h.service.Block(accountId, until)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}
	c.JSON(resp.New(http.StatusOK, "account blocked successfully", []interface{}{account}).JSON())
}

func (h *account) Delete(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	if err := h.service.Delete(accountId); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "account deleted successfully", nil).JSON())
}

func (h *account) Find(c *gin.Context) {
	accounts, err := h.service.Find()
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "account found successfully", []interface{}{accounts}).JSON())
}

func (h *account) GetByEmail(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	acc, err := h.service.GetByEmail(req.Email)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "account fetched successfully", []interface{}{acc}).JSON())
}

func (h *account) GetById(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	acc, err := h.service.GetById(accountId)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "account fetched successfully", []interface{}{acc}).JSON())
}

func (h *account) Login(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if !help.BindJSON(c, &credentials) {
		return
	}

	token, err := h.service.Login(credentials.Email, credentials.Password)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "login successful", []interface{}{token}).JSON())
}

func (h *account) RefreshToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Println("Authorization header missing")
		c.JSON(resp.Error(http.StatusBadRequest, "invalid authorication header", []interface{}{"authorization header can't be empty"}).JSON())
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		log.Println("Invalid Authorization header format")
		c.JSON(resp.Error(http.StatusBadRequest, "invalid authorication header", []interface{}{"invalid format"}).JSON())
		return
	}

	refreshToken := parts[1]

	token, err := h.service.RefreshToken(refreshToken)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "token refreshed successfully", []interface{}{token}).JSON())
}

func (h *account) Unblock(c *gin.Context) {
	var req struct {
		Id string `json:"account_id" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	var id uuid.UUID
	if !help.ParseUUID(c, "account_id", req.Id, &id) {
		return
	}

	account, err := h.service.Unblock(id)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "Account unblocked successfully", []interface{}{account}).JSON())
}

func (h *account) UpdatePassword(c *gin.Context) {
	var req struct {
		Id      string `json:"id"`
		OldPass string `json:"old_pass" binding:"required"`
		NewPass string `json:"new_pass" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	var id uuid.UUID
	if !help.ParseUUID(c, "id", req.Id, &id) {
		return
	}

	if err := h.service.UpdatePassword(id, req.OldPass, req.NewPass); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "Password changed successfully", nil).JSON())
}

func (h *account) AddAPIKey(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	var req struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	expiresAt := time.Time{}
	if req.ExpiresAt != nil {
		expiresAt = *req.ExpiresAt
	}

	apiKey, err := h.service.AddAPIKey(accountId, expiresAt)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusCreated, "api key created successfully", []interface{}{apiKey}).JSON())
}

func (h *account) AuthenticateByAPIKey(c *gin.Context) {
	apiKey := c.GetHeader("Authorization")
	if apiKey == "" {
		log.Println("empty API Key")
		c.JSON(resp.Error(http.StatusUnauthorized, "empty API Key", []interface{}{"API key required"}).JSON())
		return
	}

	apiKey = strings.TrimPrefix(apiKey, "Bearer ")

	account, err := h.service.AuthenticateByAPIKey(apiKey)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "authenticated successfully", []interface{}{account}).JSON())
}

func (h *account) DeleteAPIKey(c *gin.Context) {
	var req struct {
		Id string `json:"id" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	var id uuid.UUID
	if !help.ParseUUID(c, "id", req.Id, &id) {
		return
	}

	if err := h.service.DeleteAPIKey(id); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "api key deleted successfully", []interface{}{req.Id}).JSON())
}

func (h *account) AddAccountRole(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	roles, err := h.service.AddAccountRole(accountId, req.Role)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusCreated, "role assigned to account successfully", []interface{}{roles}).JSON())
}

func (h *account) DeleteAccountRoleById(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	if err := h.service.DeleteAccountRoleById(accountId); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "role deleted from account successfully", []interface{}{accountId}).JSON())
}

func (h *account) DeleteAccountRoleByName(c *gin.Context) {
	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	if err := h.service.DeleteAccountRoleByName(req.Role); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "role deleted from account successfully", []interface{}{req.Role}).JSON())
}

func (h *account) FindRolesByAccount(c *gin.Context) {
	var accountId uuid.UUID
	if !help.ParseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	roles, err := h.service.FindRolesByAccount(accountId)
	if err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "roles found successfully", []interface{}{roles}).JSON())
}

func (h *account) UpdateRoles(c *gin.Context) {
	var req map[string]interface{}
	if !help.BindJSON(c, &req) {
		return
	}

	if err := h.service.UpdateRoles(req); err != nil {
		log.Println(err)
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "roles updated successfully", []interface{}{}).JSON())
}

func (h *account) Logout(c *gin.Context) {
	var req struct {
		AccountId string `json:"account_id" binding:"required"`
	}

	if !help.BindJSON(c, &req) {
		return
	}

	err := h.service.Logout(req.AccountId)
	if err != nil {
		c.JSON(err.JSON())
		return
	}

	c.JSON(resp.New(http.StatusOK, "logout successful", nil).JSON())
}

func (h *account) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	if code == "" {
		c.JSON(resp.Error(http.StatusBadRequest, "code not provided", nil).JSON())
		return
	}
	token, err := h.service.ExchangeCodeForToken(provider, code)
	if err != nil {
		log.Println("Error exchanging code for token:", err)
		c.JSON(err.JSON())
		return
	}
	account, err := h.service.GetAccountInfo(provider, token)
	if err != nil {
		log.Println("Error getting account info:", err)
		c.JSON(err.JSON())
		return
	}
	if err = h.service.StoreAccount(account); err != nil {
		log.Println("Error storing account:", err)
		c.JSON(err.JSON())
		return
	}
	c.JSON(resp.New(http.StatusOK, "OAuth2 callback successful", []interface{}{account}).JSON())
}

func (h *account) OAuthLogin(c *gin.Context) {
	provider := c.Param("provider")
	config, err := h.service.GetOAuthConfig(provider)
	if err != nil {
		log.Println("Error getting OAuth config:", err)
		c.JSON(err.JSON())
		return
	}

	authURL := config.AuthCodeURL("state", oauth2.AccessTypeOffline)

	c.Redirect(http.StatusTemporaryRedirect, authURL)
	c.Writer.WriteHeaderNow()
}
