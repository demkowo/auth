package handler

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	model "github.com/demkowo/auth/models"
	service "github.com/demkowo/auth/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	DeleteAccountRole(*gin.Context)
	FindRolesByAccount(*gin.Context)
	UpdateRoles(*gin.Context)
}

type account struct {
	service service.Account
}

func NewAccount(service service.Account) Account {
	return &account{service: service}
}

func (h *account) Add(c *gin.Context) {
	var acc model.Account

	if !bindJSON(c, &acc) {
		return
	}

	if err := acc.Validate(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "email, password and nickname can't be empty"})
	}

	if err := h.service.Add(&acc); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "account registered successfully"})
}

func (h *account) Block(c *gin.Context) {
	var req struct {
		AccountId string `json:"account_id" binding:"required"`
		Until     string `json:"until" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	var until time.Time
	if !parseTime(c, "2006-01-02", req.Until, &until) {
		return
	}

	var accountId uuid.UUID
	if !parseUUID(c, "account_id", req.AccountId, &accountId) {
		return
	}

	if err := h.service.Block(accountId, until); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "account blocked successfully",
		"account_id":    accountId,
		"blocked_until": until,
	})
}

func (h *account) Delete(c *gin.Context) {
	var accountId uuid.UUID
	if !parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	if err := h.service.Delete(accountId); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deleted successfully"})
}

func (h *account) Find(c *gin.Context) {
	accounts, err := h.service.Find()
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

func (h *account) GetByEmail(c *gin.Context) {
	acc, err := h.service.GetByEmail(c.Param("email"))
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"account": acc})
}

func (h *account) GetById(c *gin.Context) {
	var accountId uuid.UUID
	if !parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	acc, err := h.service.GetById(accountId)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"account": acc})
}

func (h *account) Login(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if !bindJSON(c, &credentials) {
		return
	}

	token, err := h.service.Login(credentials.Email, credentials.Password)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *account) RefreshToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Println("Authorization header missing")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header required"})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		log.Println("Invalid Authorization header format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Authorization header format"})
		return
	}

	refreshToken := parts[1]

	token, err := h.service.RefreshToken(refreshToken)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *account) Unblock(c *gin.Context) {
	var req struct {
		Id string `json:"account_id" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	var id uuid.UUID
	if !parseUUID(c, "account_id", req.Id, &id) {
		return
	}

	if err := h.service.Unblock(id); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account unblocked successfully", "id": id, "unblock_time": time.Now()})
}

func (h *account) UpdatePassword(c *gin.Context) {
	var req struct {
		Id      string `json:"id"`
		OldPass string `json:"old_pass" binding:"required"`
		NewPass string `json:"new_pass" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	var id uuid.UUID
	if !parseUUID(c, "id", req.Id, &id) {
		return
	}

	if err := h.service.UpdatePassword(id, req.OldPass, req.NewPass); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *account) AddAPIKey(c *gin.Context) {
	var accountId uuid.UUID
	if parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	var req struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if !bindJSON(c, &req) {
		return
	}

	expiresAt := time.Time{}
	if req.ExpiresAt != nil {
		expiresAt = *req.ExpiresAt
	}

	apiKey, errService := h.service.AddAPIKey(accountId, expiresAt)
	if errService != nil {
		log.Println(errService)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errService.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"api_key": apiKey})
}

func (h *account) AuthenticateByAPIKey(c *gin.Context) {
	apiKey := c.GetHeader("Authorization")
	if apiKey == "" {
		log.Println("empty API Key")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
		return
	}

	apiKey = strings.TrimPrefix(apiKey, "Bearer ")

	account, err := h.service.AuthenticateByAPIKey(apiKey)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"account_id": account.Id,
		"email":      account.Email,
		"roles":      account.Roles,
	})
}

func (h *account) DeleteAPIKey(c *gin.Context) {
	var req struct {
		APIKey string `json:"api_key" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	if err := h.service.DeleteAPIKey(req.APIKey); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}

func (h *account) AddAccountRole(c *gin.Context) {
	var accountId uuid.UUID
	if !parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	if err := h.service.AddAccountRole(accountId, req.Role); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role added to account successfully"})
}

func (h *account) DeleteAccountRole(c *gin.Context) {
	var accountId uuid.UUID
	if !parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}

	if !bindJSON(c, &req) {
		return
	}

	if err := h.service.DeleteAccountRole(accountId, req.Role); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "deleting role from account failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role deleted from account successfully"})
}

func (h *account) FindRolesByAccount(c *gin.Context) {
	var accountId uuid.UUID
	if !parseUUID(c, "account_id", c.Param("account_id"), &accountId) {
		return
	}

	roles, errService := h.service.FindRolesByAccount(accountId)
	if errService != nil {
		log.Println(errService)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errService.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

func (h *account) UpdateRoles(c *gin.Context) {
	var req map[string]interface{}
	if !bindJSON(c, &req) {
		return
	}

	if err := h.service.UpdateRoles(req); err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "roles updated"})
}

func bindJSON(c *gin.Context, jsonToBind interface{}) bool {
	if err := c.ShouldBindJSON(&jsonToBind); err != nil {
		log.Printf("invalid JSON data: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid JSON data: %s", err.Error())})
		return false
	}
	return true
}

func parseUUID(c *gin.Context, jsonField string, txtToParse string, dest *uuid.UUID) bool {
	parsedID, err := uuid.Parse(txtToParse)
	if err != nil {
		log.Printf("failed to parse %s: %v", jsonField, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid value: %s", jsonField)})
		return false
	}

	*dest = parsedID
	return true
}

func parseTime(c *gin.Context, timeFormat string, txtToParse string, dest *time.Time) bool {
	res, err := time.Parse(timeFormat, txtToParse)
	if err != nil {
		log.Printf("invalid input: %v", txtToParse)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return false
	}

	*dest = res
	return true
}
