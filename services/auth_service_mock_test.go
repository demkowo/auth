package service

import (
	"errors"
	"net/http"
	"testing"
	"time"

	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/resp"
	"github.com/stretchr/testify/assert"
)

var (
	serviceMock = NewAccountMock()
)

func TestM_Add_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.Add(&acc)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_Add_Error(t *testing.T) {
	clearMock()

	errMap["Add"] = errors.New("Add error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{"Add error"}), err)
}

func TestM_AddJWTToken_Success(t *testing.T) {
	clearMock()

	token, err := serviceMock.AddJWTToken(&acc)

	assert.Nil(t, err)
	assert.Equal(t, "validTokenString", token)
}

func TestM_AddJWTToken_Error(t *testing.T) {
	clearMock()

	errMap["AddJWTToken"] = errors.New("AddJWTToken error")

	serviceMock.SetMock(Mock{Error: errMap})

	token, err := serviceMock.AddJWTToken(&acc)

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"AddJWTToken error"}), err)
}

func TestM_Block_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.Block(acc.Id, time.Now().Add(time.Hour))

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_Block_Error(t *testing.T) {
	clearMock()

	errMap["Block"] = errors.New("Block error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.Block(acc.Id, time.Now().Add(time.Hour))

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to block account", []interface{}{"Block error"}), err)
}

func TestM_CheckAccess_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{})

	err := serviceMock.CheckAccess(acc.Id)

	assert.Nil(t, err)
}

func TestM_CheckAccess_Error(t *testing.T) {
	clearMock()

	errMap["CheckAccess"] = errors.New("CheckAccess error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.CheckAccess(acc.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to check access to account", []interface{}{"CheckAccess error"}), err)
}

func TestM_Delete_Success(t *testing.T) {
	clearMock()

	err := serviceMock.Delete(acc.Id)

	assert.Nil(t, err)
}

func TestM_Delete_Error(t *testing.T) {
	clearMock()

	errMap["Delete"] = errors.New("Delete error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.Delete(acc.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{"Delete error"}), err)
}

func TestM_Find_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Accounts: []*model.Account{&defaultAccount, &acc}})

	accounts, err := serviceMock.Find()

	assert.Nil(t, err)
	assert.Equal(t, []*model.Account{&defaultAccount, &acc}, accounts)
}

func TestM_Find_Error(t *testing.T) {
	clearMock()

	errMap["Find"] = errors.New("Find error")

	serviceMock.SetMock(Mock{Error: errMap})

	accounts, err := serviceMock.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Find error"}), err)
}

func TestM_GetByEmail_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.GetByEmail("email@test.com")

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_GetByEmail_Error(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.GetByEmail("email@test.com")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func TestM_GetById_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_GetById_Error(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.GetById(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func TestM_Login_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Token: "validTokenString"})

	token, err := serviceMock.Login("email@test.com", "password")

	assert.Nil(t, err)
	assert.Equal(t, "validTokenString", token)
}

func TestM_Login_Error(t *testing.T) {
	clearMock()

	errMap["Login"] = errors.New("Login error")

	serviceMock.SetMock(Mock{Error: errMap})

	token, err := serviceMock.Login("email@test.com", "password")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "login failed", []interface{}{"Login error"}), err)
}

func TestM_RefreshToken_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Token: "refreshedValidToken"})

	token, err := serviceMock.RefreshToken("validToken")

	assert.Nil(t, err)
	assert.Equal(t, "refreshedValidToken", token)
}

func TestM_RefreshToken_Error(t *testing.T) {
	clearMock()

	errMap["RefreshToken"] = errors.New("RefreshToken error")

	serviceMock.SetMock(Mock{Error: errMap})

	token, err := serviceMock.RefreshToken("validToken")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "refresh token failed", []interface{}{"RefreshToken error"}), err)
}

func TestM_Unblock_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.Unblock(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_Unblock_Error(t *testing.T) {
	clearMock()

	errMap["Unblock"] = errors.New("Unblock error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.Unblock(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to unblock account", []interface{}{"Unblock error"}), err)
}

func TestM_UpdatePassword_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{})

	err := serviceMock.UpdatePassword(acc.Id, "oldPass", "newPass")

	assert.Nil(t, err)
}

func TestM_UpdatePassword_Error(t *testing.T) {
	clearMock()

	errMap["UpdatePassword"] = errors.New("UpdatePassword error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.UpdatePassword(acc.Id, "oldPass", "newPass")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{"UpdatePassword error"}), err)
}

func TestM_AddAPIKey_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{ApiKey: &apiKey})

	key, err := serviceMock.AddAPIKey(apiKey.AccountId, time.Now().Add(time.Hour))

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func TestM_AddAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	serviceMock.SetMock(Mock{Error: errMap})

	key, err := serviceMock.AddAPIKey(acc.Id, time.Now().Add(time.Hour))

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{"AddAPIKey error"}), err)
}

func TestM_AuthenticateByAPIKey_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Account: &acc})

	account, err := serviceMock.AuthenticateByAPIKey("apiKey")

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_AuthenticateByAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["AuthenticateByAPIKey"] = errors.New("AuthenticateByAPIKey error")

	serviceMock.SetMock(Mock{Error: errMap})

	account, err := serviceMock.AuthenticateByAPIKey("apiKey")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "failed to authenticate with API key", []interface{}{"AuthenticateByAPIKey error"}), err)
}

func TestM_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{})

	err := serviceMock.DeleteAPIKey(apiKey.Key)

	assert.Nil(t, err)
}

func TestM_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.DeleteAPIKey(apiKey.Key)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{"DeleteAPIKey error"}), err)
}

func TestM_AddAccountRole_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{Roles: &accRole})

	roles, err := serviceMock.AddAccountRole(acc.Id, "admin")

	assert.Nil(t, err)
	assert.Equal(t, &accRole, roles)
}

func TestM_AddAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	serviceMock.SetMock(Mock{Error: errMap})

	roles, err := serviceMock.AddAccountRole(acc.Id, "admin")

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{"AddAccountRole error"}), err)
}

func TestM_DeleteAccountRole_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{})

	err := serviceMock.DeleteAccountRole(acc.Id, "admin")

	assert.Nil(t, err)
}

func TestM_DeleteAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRole"] = errors.New("DeleteAccountRole error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.DeleteAccountRole(acc.Id, "admin")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"DeleteAccountRole error"}), err)
}

func TestM_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	serviceMock.SetMock(Mock{AccountRoles: []model.AccountRole{accRole}})

	roles, err := serviceMock.FindRolesByAccount(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, []model.AccountRole{accRole}, roles)
}

func TestM_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")

	serviceMock.SetMock(Mock{Error: errMap})

	roles, err := serviceMock.FindRolesByAccount(acc.Id)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"FindRolesByAccount error"}), err)
}

func TestM_UpdateRoles_Success(t *testing.T) {
	clearMock()

	var req map[string]interface{}

	err := serviceMock.UpdateRoles(req)

	assert.Nil(t, err)
}

func TestM_UpdateRoles_Error(t *testing.T) {
	clearMock()

	var req map[string]interface{}
	errMap["UpdateRoles"] = errors.New("UpdateRoles error")

	serviceMock.SetMock(Mock{Error: errMap})

	err := serviceMock.UpdateRoles(req)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update roles", []interface{}{"UpdateRoles error"}), err)
}
