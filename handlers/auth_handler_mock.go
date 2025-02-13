package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type accountMock struct {
}

func NewAccountMock() Account {
	return &accountMock{}
}

func (m *accountMock) Add(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "account added"})
}

func (m *accountMock) Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}
func (m *accountMock) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "token refreshed"})
}
func (m *accountMock) AuthenticateByAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "authenticated"})
}
func (m *accountMock) Block(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account blocked"})
}
func (m *accountMock) Delete(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
}
func (m *accountMock) Find(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account found"})
}
func (m *accountMock) GetByEmail(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account retrieved by email"})
}
func (m *accountMock) GetById(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account retrieved by ID"})
}
func (m *accountMock) Unblock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account unblocked"})
}
func (m *accountMock) UpdatePassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "password updated"})
}
func (m *accountMock) AddAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "API key added"})
}
func (m *accountMock) DeleteAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "API key deleted"})
}
func (m *accountMock) AddAccountRole(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "role added"})
}
func (m *accountMock) DeleteAccountRole(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "role deleted"})
}
func (m *accountMock) FindRolesByAccount(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "roles found"})
}
func (m *accountMock) UpdateRoles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "roles updated"})
}
