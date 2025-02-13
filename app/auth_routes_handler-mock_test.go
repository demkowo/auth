package app

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	hm = &handlerMock{}
)

type handlerMock struct {
}

func NewHandlerMock() *handlerMock {
	return hm
}

func (m *handlerMock) Add(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "account added"})
}

func (m *handlerMock) Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}
func (m *handlerMock) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "token refreshed"})
}
func (m *handlerMock) AuthenticateByAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "authenticated"})
}
func (m *handlerMock) Block(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account blocked"})
}
func (m *handlerMock) Delete(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
}
func (m *handlerMock) Find(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account found"})
}
func (m *handlerMock) GetByEmail(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account retrieved by email"})
}
func (m *handlerMock) GetById(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account retrieved by ID"})
}
func (m *handlerMock) Unblock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "account unblocked"})
}
func (m *handlerMock) UpdatePassword(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "password updated"})
}
func (m *handlerMock) AddAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "API key added"})
}
func (m *handlerMock) DeleteAPIKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "API key deleted"})
}
func (m *handlerMock) AddAccountRole(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "role added"})
}
func (m *handlerMock) DeleteAccountRole(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "role deleted"})
}
func (m *handlerMock) FindRolesByAccount(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "roles found"})
}
func (m *handlerMock) UpdateRoles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "roles updated"})
}
