package handler

import (
	"testing"

	"github.com/demkowo/utils/helper"
	"github.com/stretchr/testify/assert"
)

var (
	mockHandler = NewAccountMock()
)

func Test_Add(t *testing.T) {
	clearMock()
	helper.AddMock(helper.Mock{Test: "Add"})
	mockHandler.Add(c)
	assert.JSONEq(t, `{"message": "account added"}`, w.Body.String())
}

func Test_Login(t *testing.T) {
	clearMock()
	mockHandler.Login(c)
	assert.JSONEq(t, `{"message": "login successful"}`, w.Body.String())
}
func Test_RefreshToken(t *testing.T) {
	clearMock()
	mockHandler.RefreshToken(c)
	assert.JSONEq(t, `{"message": "token refreshed"}`, w.Body.String())
}
func Test_AuthenticateByAPIKey(t *testing.T) {
	clearMock()
	mockHandler.AuthenticateByAPIKey(c)
	assert.JSONEq(t, `{"message": "authenticated"}`, w.Body.String())
}
func Test_Block(t *testing.T) {
	clearMock()
	mockHandler.Block(c)
	assert.JSONEq(t, `{"message": "account blocked"}`, w.Body.String())
}
func Test_Delete(t *testing.T) {
	clearMock()
	mockHandler.Delete(c)
	assert.JSONEq(t, `{"message": "account deleted"}`, w.Body.String())
}
func Test_Find(t *testing.T) {
	clearMock()
	mockHandler.Find(c)
	assert.JSONEq(t, `{"message": "account found"}`, w.Body.String())
}
func Test_GetByEmail(t *testing.T) {
	clearMock()
	mockHandler.GetByEmail(c)
	assert.JSONEq(t, `{"message": "account retrieved by email"}`, w.Body.String())
}
func Test_GetById(t *testing.T) {
	clearMock()
	mockHandler.GetById(c)
	assert.JSONEq(t, `{"message": "account retrieved by ID"}`, w.Body.String())
}
func Test_Unblock(t *testing.T) {
	clearMock()
	mockHandler.Unblock(c)
	assert.JSONEq(t, `{"message": "account unblocked"}`, w.Body.String())
}
func Test_UpdatePassword(t *testing.T) {
	clearMock()
	mockHandler.UpdatePassword(c)
	assert.JSONEq(t, `{"message": "password updated"}`, w.Body.String())
}
func Test_AddAPIKey(t *testing.T) {
	clearMock()
	mockHandler.AddAPIKey(c)
	assert.JSONEq(t, `{"message": "API key added"}`, w.Body.String())
}
func Test_DeleteAPIKey(t *testing.T) {
	clearMock()
	mockHandler.DeleteAPIKey(c)
	assert.JSONEq(t, `{"message": "API key deleted"}`, w.Body.String())
}
func Test_AddAccountRole(t *testing.T) {
	clearMock()
	mockHandler.AddAccountRole(c)
	assert.JSONEq(t, `{"message": "role added"}`, w.Body.String())
}
func Test_DeleteAccountRole(t *testing.T) {
	clearMock()
	mockHandler.DeleteAccountRole(c)
	assert.JSONEq(t, `{"message": "role deleted"}`, w.Body.String())
}
func Test_FindRolesByAccount(t *testing.T) {
	clearMock()
	mockHandler.FindRolesByAccount(c)
	assert.JSONEq(t, `{"message": "roles found"}`, w.Body.String())
}
func Test_UpdateRoles(t *testing.T) {
	clearMock()
	mockHandler.UpdateRoles(c)
	assert.JSONEq(t, `{"message": "roles updated"}`, w.Body.String())
}
