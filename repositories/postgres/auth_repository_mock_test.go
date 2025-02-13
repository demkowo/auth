package postgres

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
	repo = NewAccountMock()
)

func TestM_NewAccount_Success(t *testing.T) {
	res1 := NewAccountMock()
	res2 := NewAccountMock()

	assert.NotNil(t, res1)
	assert.NotNil(t, res2)
	assert.Equal(t, res1, res2)
}

func TestM_CreateTables_Success(t *testing.T) {
	clearMock()

	err := repo.CreateTables()

	assert.Nil(t, err)
}

func TestM_CreateTables_Error(t *testing.T) {
	clearMock()

	errMap["CreateTables"] = errors.New("CreateTables error")

	repo.SetMock(Mock{Error: errMap})

	err := repo.CreateTables()

	assert.Error(t, errors.New("CreateTables error"), err)
}

func TestM_Add_Success(t *testing.T) {
	clearMock()

	acc := defaultAcc

	account, err := repo.Add(&acc)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_Add_Error(t *testing.T) {
	clearMock()

	errMap["Add"] = errors.New("Add error")

	repo.SetMock(Mock{Error: errMap})

	account, err := repo.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{"Add error"}), err)
}

func TestM_Delete_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{})

	err := repo.Delete(acc.Id)

	assert.Nil(t, err)
}

func TestM_Delete_Error(t *testing.T) {
	clearMock()

	errMap["Delete"] = errors.New("Delete error")

	repo.SetMock(Mock{Error: errMap})

	err := repo.Delete(acc.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{"Delete error"}), err)
}

func TestM_Find_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{Accounts: []*model.Account{&acc}})

	accounts, err := repo.Find()

	assert.Nil(t, err)
	assert.Equal(t, []*model.Account{&acc}, accounts)
}

func TestM_Find_Error(t *testing.T) {
	clearMock()

	errMap["Find"] = errors.New("Find error")

	repo.SetMock(Mock{Error: errMap})

	accounts, err := repo.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Find error"}), err)
}

func TestM_GetByEmail_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{Account: &acc})

	account, err := repo.GetByEmail("test@test.com")

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_GetByEmail_Error(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	repo.SetMock(Mock{Error: errMap})

	account, err := repo.GetByEmail("test@test.com")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func TestM_GetById_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{Account: &acc})

	account, err := repo.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, acc.Id, account.Id)
}

func TestM_GetById_Error(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	repo.SetMock(Mock{Error: errMap})

	account, err := repo.GetById(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func TestM_Update_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{Account: &acc})

	account, err := repo.Update(&acc)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func TestM_Update_Error(t *testing.T) {
	clearMock()

	errMap["Update"] = errors.New("Update error")

	repo.SetMock(Mock{Error: errMap})

	account, err := repo.Update(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{"Update error"}), err)
}

func TestM_UpdatePassword_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{})

	err := repo.UpdatePassword(acc.Id, "newPass")

	assert.Nil(t, err)
}

func TestM_UpdatePassword_Error(t *testing.T) {
	clearMock()

	errMap["UpdatePassword"] = errors.New("UpdatePassword error")

	repo.SetMock(Mock{Error: errMap})

	err := repo.UpdatePassword(acc.Id, "newPass")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{"UpdatePassword error"}), err)
}

func TestM_AddAPIKey_Success(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	key, err := repo.AddAPIKey(&apiKey)

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func TestM_AddAPIKey_validateApiKeyError(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	repo.SetMock(Mock{Error: errMap})

	key, err := repo.AddAPIKey(nil)

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{"AddAPIKey error"}), err)
}

func TestM_AddAPIKey_Error(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	repo.SetMock(Mock{Error: errMap})

	key, err := repo.AddAPIKey(&apiKey)

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{"AddAPIKey error"}), err)
}

func TestM_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	err := repo.DeleteAPIKey("someKeyToRemove")

	assert.Nil(t, err)
}

func TestM_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")

	repo.SetMock(Mock{Error: errMap})

	err := repo.DeleteAPIKey("someKeyToRemove")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{"DeleteAPIKey error"}), err)
}

func TestM_GetAPIKeyById_Success(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	repo.SetMock(Mock{ApiKey: &apiKey})

	key, err := repo.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func TestM_GetAPIKeyById_validateApiKeyError(t *testing.T) {
	clearMock()

	apiKey.CreatedAt = time.Now().Add(-5 * time.Hour)
	apiKey.ExpiresAt = time.Now().Add(time.Hour)
	errMap["GetAPIKeyById"] = errors.New("GetAPIKeyById error")

	repo.SetMock(Mock{Error: errMap, ApiKey: &apiKey})

	key, err := repo.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"GetAPIKeyById error"}), err)
}

func TestM_GetAPIKeyById_Error(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)
	errMap["GetAPIKeyById"] = errors.New("GetAPIKeyById error")

	repo.SetMock(Mock{Error: errMap, ApiKey: &apiKey})

	key, err := repo.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"GetAPIKeyById error"}), err)
}

func TestM_GetAPIKeyByKey_Success(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	repo.SetMock(Mock{ApiKey: &apiKey})

	key, err := repo.GetAPIKeyByKey("someValidKey")

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func TestM_GetAPIKeyByKey_validateApiKeyError(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(5 * time.Hour)

	errMap["GetAPIKeyByKey"] = errors.New("GetAPIKeyByKey error")

	repo.SetMock(Mock{ApiKey: &apiKey, Error: errMap})

	key, err := repo.GetAPIKeyByKey("someValidKey")

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"GetAPIKeyByKey error"}), err)
}

func TestM_GetAPIKeyByKey_Error(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour)

	errMap["GetAPIKeyByKey"] = errors.New("GetAPIKeyByKey error")

	repo.SetMock(Mock{ApiKey: &apiKey, Error: errMap})

	key, err := repo.GetAPIKeyByKey("someValidKey")

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"GetAPIKeyByKey error"}), err)
}

func TestM_AddAccountRole_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{AccountRoles: acc.Roles})

	role, err := repo.AddAccountRole(acc.Id, "admin")

	assert.Nil(t, err)
	assert.Equal(t, &model.AccountRole{Id: acc.Id, Name: "admin"}, role)
}

func TestM_AddAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	repo.SetMock(Mock{AccountRoles: acc.Roles, Error: errMap})

	role, err := repo.AddAccountRole(acc.Id, "admin")

	assert.Nil(t, role)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{"AddAccountRole error"}), err)
}

func TestM_DeleteAccountRole_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{Accounts: []*model.Account{&acc}})

	err := repo.DeleteAccountRole(acc.Id, "admin")

	assert.Nil(t, err)
}

func TestM_DeleteAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRole"] = errors.New("DeleteAccountRole error")

	repo.SetMock(Mock{Error: errMap})

	err := repo.DeleteAccountRole(acc.Id, "admin")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"DeleteAccountRole error"}), err)
}

func TestM_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	repo.SetMock(Mock{AccountRoles: acc.Roles})

	roles, err := repo.FindRolesByAccount(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, acc.Roles, roles)
}

func TestM_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")

	repo.SetMock(Mock{AccountRoles: acc.Roles, Error: errMap})

	roles, err := repo.FindRolesByAccount(acc.Id)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"FindRolesByAccount error"}), err)
}
