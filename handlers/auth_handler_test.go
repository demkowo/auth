package handler

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	model "github.com/demkowo/auth/models"
	service "github.com/demkowo/auth/services"
	"github.com/demkowo/auth/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	c *gin.Context
	w *httptest.ResponseRecorder

	mockService = service.NewAccountMock()
	handler     = NewAccount(mockService)

	acc    model.Account
	expAcc model.Account

	tn, _ = time.Parse("2006-01-02T15:04:05", "2025-02-06T11:35:20")

	defaultAccount = model.Account{
		Id:       uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Nickname: "admin",
		Email:    "admin@admin.com",
		Password: "secretHashedPass",
		Roles:    nil,
		APIKeys:  nil,
		Created:  tn,
		Updated:  tn,
		Blocked:  time.Time{},
		Deleted:  false,
	}

	accountJSON = `{"account":{
		"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
		"email":"admin@admin.com",
		"password":"secretHashedPass",
		"nickname":"admin",
		"roles":null,
		"api_keys":null,
		"created":"2025-02-06T11:35:20Z",
		"updated":"2025-02-06T11:35:20Z",
		"blocked":"0001-01-01T00:00:00Z",
		"deleted":false}}`
)

func TestMain(m *testing.M) {
	utils.StartMock()
	log.SetOutput(os.Stdout)
	os.Exit(m.Run())
}

func clearMock() {
	acc = defaultAccount
	expAcc = defaultAccount
	utils.Var.SetExpectedError(nil)
	utils.Var.SetExpectedPassword("")

	recorder := httptest.NewRecorder()
	w = recorder
	context, _ := gin.CreateTestContext(w)
	c = context
}

func Test_Add_Success(t *testing.T) {
	clearMock()

	body := `{
        "email": "test@test.com",
        "password": "Qwerty!23",
        "nickname": "tester"
    }`

	req := httptest.NewRequest("POST", "/accounts", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Add(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{"message":"account registered successfully"}`, w.Body.String())
}

func Test_Add_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
        "email": 1,
        "password": "wrongPassword",
        "nickname": "tester"
    }`

	req := httptest.NewRequest("POST", "/accounts", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Add(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field Account.email of type string"}`, w.Body.String())
}

func Test_Add_ValidateError(t *testing.T) {
	clearMock()

	body := `{
        "email": "test@test.com",
        "password": "wrongPassword",
        "nickname": "tester"
    }`

	req := httptest.NewRequest("POST", "/accounts", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Add(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit"}`, w.Body.String())
}

func Test_Add_AddError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Add"] = errors.New("Add error")

	body := `{
        "email": "test@test.com",
        "password": "Qwerty!23",
        "nickname": "tester"
    }`

	req := httptest.NewRequest("POST", "/accounts", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Add(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to create account"}`, w.Body.String())
}

func Test_Block_Success(t *testing.T) {
	clearMock()

	body := `{
        "account_id": "3a82ef35-6de8-4eaa-9f53-5a99645772e3",
        "until": "2025-04-01"
    }`

	req := httptest.NewRequest("POST", "/block", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Block(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
		"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3", 
		"blocked_until":"2025-04-01T00:00:00Z", 
		"message":"account blocked successfully"
	}`, w.Body.String())
}

func Test_Block_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
        "account_id": "3a82ef35-6de8-4eaa-9f53-5a99645772e3",
        "until": 1
    }`

	req := httptest.NewRequest("POST", "/block", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .until of type string"}`, w.Body.String())
}

func Test_Block_ParseTimeError(t *testing.T) {
	clearMock()

	body := `{
        "account_id": "3a82ef35-6de8-4eaa-9f53-5a99645772e3",
        "until": "11-11-2025"
    }`

	req := httptest.NewRequest("POST", "/block", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"Invalid time format, expected: 2006-01-02"}`, w.Body.String())
}

func Test_Block_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{
        "account_id": "invalidUUID",
        "until": "2025-02-02"
    }`

	req := httptest.NewRequest("POST", "/block", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_Block_BlockError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Block"] = errors.New("Block error")

	body := `{
        "account_id": "3a82ef35-6de8-4eaa-9f53-5a99645772e3",
        "until": "2025-02-02"
    }`

	req := httptest.NewRequest("POST", "/block", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Block(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to update account"}`, w.Body.String())
}

func Test_Delete_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String(), nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Delete(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"account deleted successfully"}`, w.Body.String())
}

func Test_Delete_ParseUuidError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("DELETE", "/accounts/invalidUUID", nil)

	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Delete(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_Delete_DeleteError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Delete"] = errors.New("Delete error")

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String(), nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Delete(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to delete account"}`, w.Body.String())
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("GET", "/api/v1/auth/find", nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Find(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"accounts"`)
}

func Test_Find_FindError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Find"] = errors.New("Find error")

	req := httptest.NewRequest("GET", "/api/v1/auth/find", nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Find(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to find accounts"}`, w.Body.String())
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "email", Value: "admin@admin.com"}}
	req := httptest.NewRequest("GET", "/accounts/admin@admin.com", nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Account: &acc,
	})

	handler.GetByEmail(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, accountJSON, w.Body.String())
}

func Test_GetByEmail_GetByEmailError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetByEmail"] = errors.New("GetByEmail error")

	c.Params = []gin.Param{{Key: "email", Value: "admin@admin.com"}}
	req := httptest.NewRequest("GET", "/accounts/admin@admin.com", nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.GetByEmail(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to get account"}`, w.Body.String())
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("GET", "/accounts/"+acc.Id.String(), nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Account: &acc,
	})

	handler.GetById(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, accountJSON, w.Body.String())
}

func Test_GetById_ParseUuidError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("GET", "/accounts/invalidUUID", nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.GetById(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_GetById_ServiceError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("GetById error")

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("GET", "/accounts/"+acc.Id.String(), nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.GetById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to get account"}`, w.Body.String())
}

func Test_Login_Success(t *testing.T) {
	clearMock()

	body := `{
		"email":"admin@admin.com",
		"password":"secret"
	}`

	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Token: "someValidToken",
	})

	handler.Login(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"token":"someValidToken"}`, w.Body.String())
}

func Test_Login_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"email":123,
		"password":"secret"
	}`

	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .email of type string"}`, w.Body.String())
}

func Test_Login_LoginError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Login"] = errors.New("Login error")

	body := `{
		"email":"admin@admin.com",
		"password":"wrong"
	}`

	req := httptest.NewRequest("POST", "/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Login(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"error":"invalid credentials"}`, w.Body.String())
}

func Test_RefreshToken_Success(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	c.Request = req

	mockService.SetMock(service.Mock{
		Token: "someValidToken",
	})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"token":"someValidToken"}`, w.Body.String())

}

func Test_RefreshToken_GetHeaderError(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("POST", "/refresh", nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"Authorization header required"}`, w.Body.String())
}

func Test_RefreshToken_HeaderFormatError(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"Invalid Authorization header format"}`, w.Body.String())
}

func Test_RefreshToken_RefreshTokenError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["RefreshToken"] = errors.New("RefreshToken error")

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"error":"invalid credentials"}`, w.Body.String())
}

func Test_Unblock_Success(t *testing.T) {
	clearMock()

	body := `{
		"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"
	}`

	req := httptest.NewRequest("POST", "/unblock", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Unblock(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3", "message":"Account unblocked successfully"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), `"Account unblocked successfully"`)
}

func Test_Unblock_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"account_id":123
	}`

	req := httptest.NewRequest("POST", "/unblock", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Unblock(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .account_id of type string"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_Unblock_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{
		"account_id":"invalidUUID"
	}`

	req := httptest.NewRequest("POST", "/unblock", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.Unblock(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_Unblock_UnblockError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Unblock"] = errors.New("Unblock error")

	body := `{
		"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"
	}`

	req := httptest.NewRequest("POST", "/unblock", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.Unblock(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to unblock account"}`, w.Body.String())
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	body := `{
		"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
		"old_pass":"old123",
		"new_pass":"new123"
	}`

	req := httptest.NewRequest("POST", "/update-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"Password changed successfully"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "Password changed successfully")
}

func Test_UpdatePassword_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"id":123,
		"old_pass":"old123",
		"new_pass":"new123"
	}`

	req := httptest.NewRequest("POST", "/update-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .id of type string"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_UpdatePassword_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{
		"id":"invalidUUID",
		"old_pass":"old123",
		"new_pass":"new123"
	}`

	req := httptest.NewRequest("POST", "/update-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: id"}`, w.Body.String())
}

func Test_UpdatePassword_UpdatePasswordError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["UpdatePassword"] = errors.New("UpdatePassword error")

	body := `{
		"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
		"old_pass":"old",
		"new_pass":"new"
	}`

	req := httptest.NewRequest("POST", "/update-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to change password"}`, w.Body.String())
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	body := `{
		"expires_at":"2026-02-06T00:00:00Z"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/api/v1/auth/api-key/"+acc.Id.String(), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		ApiKey: &model.APIKey{
			Key: "validAPIKey",
		},
	})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{"api_key":"validAPIKey"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), `"api_key"`)
}

func Test_AddAPIKey_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{
		"expires_at":"2026-02-06T00:00:00Z"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("POST", "/api/v1/auth/api-key/"+acc.Id.String(), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		ApiKey: &model.APIKey{
			Key: "validAPIKey",
		},
	})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_AddAPIKey_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"expires_at":"02-26-2026"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/api/v1/auth/api-key/"+acc.Id.String(), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		ApiKey: &model.APIKey{
			Key: "validAPIKey",
		},
	})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: parsing time \"02-26-2026\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"02-26-2026\" as \"2006\""}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_AddAPIKey_AddAPIKeyError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	body := `{
		"expires_at":"2026-02-06T00:00:00Z"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/api/v1/auth/api-key/"+acc.Id.String(), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
		ApiKey: &model.APIKey{
			Key: "validAPIKey",
		},
	})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to create API key"}`, w.Body.String())
}

func Test_AuthenticateByAPIKey_Success(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("GET", "/api-key-auth", nil)
	req.Header.Set("Authorization", "Bearer validAPIKey")
	c.Request = req

	mockService.SetMock(service.Mock{
		Account: &acc,
	})

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, accountJSON, w.Body.String())
}

func Test_AuthenticateByAPIKey_GetHeaderError(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("GET", "/api-key-auth", nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"error":"API key required"}`, w.Body.String())
}

func Test_AuthenticateByAPIKey_AuthenticateByAPIKeyError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AuthenticateByAPIKey"] = errors.New("AuthenticateByAPIKey error")

	req := httptest.NewRequest("GET", "/api-key-auth", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"error":"failed to authenticate with this API key"}`, w.Body.String())
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	body := `{
		"api_key":"someAPIKey"
	}`

	req := httptest.NewRequest("POST", "/api-keys/delete", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"API key revoked successfully"}`, w.Body.String())
}

func Test_DeleteAPIKey_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"api_key":123
	}`

	req := httptest.NewRequest("POST", "/api-keys/delete", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .api_key of type string"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_DeleteAPIKey_DeleteAPIKeyError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")

	body := `{
		"api_key":"someAPIKey"
	}`

	req := httptest.NewRequest("POST", "/api-keys/delete", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to delete API key"}`, w.Body.String())
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	body := `{
		"role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"role added to account successfully"}`, w.Body.String())
}

func Test_AddAccountRole_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{
		"role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("POST", "/accounts/invalidUUID/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_AddAccountRole_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"role":123
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .role of type string"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_AddAccountRole_AddAccountRoleError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	body := `{
		"role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("POST", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to add role to account"}`, w.Body.String())
}

func Test_DeleteAccountRole_Success(t *testing.T) {
	clearMock()

	body := `{
		"role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.DeleteAccountRole(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"role deleted from account successfully"}`, w.Body.String())
}

func Test_DeleteAccountRole_ParseUuidError(t *testing.T) {
	clearMock()

	body := `{"
		role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("DELETE", "/accounts/invalidUUID/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.DeleteAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_DeleteAccountRole_BindJsonError(t *testing.T) {
	clearMock()

	body := `{
		"role":123
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.DeleteAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: json: cannot unmarshal number into Go struct field .role of type string"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_DeleteAccountRole_DeleteAccountRoleError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["DeleteAccountRole"] = errors.New("DeleteAccountRole error")

	body := `{
		"role":"tester"
	}`

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String()+"/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.DeleteAccountRole(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"deleting role from account failed"}`, w.Body.String())
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("GET", "/accounts/"+acc.Id.String()+"/roles", nil)
	c.Request = req

	acc.Roles = []model.AccountRoles{
		{
			Id:   uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
			Name: "admin",
		},
	}

	mockService.SetMock(service.Mock{
		AccountRoles: acc.Roles,
	})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"roles":[{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3", "name":"admin"}]}`, w.Body.String())
}

func Test_FindRolesByAccount_ParseUuidError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	req := httptest.NewRequest("GET", "/accounts/invalidUUID/roles", nil)
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid value: account_id"}`, w.Body.String())
}

func Test_FindRolesByAccount_FindRolesByAccountError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	req := httptest.NewRequest("GET", "/accounts/"+acc.Id.String()+"/roles", nil)
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to find roles"}`, w.Body.String())
}

func Test_UpdateRoles_Success(t *testing.T) {
	clearMock()

	body := `{
		"role_update":"someData"
	}`

	req := httptest.NewRequest("POST", "/roles/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"roles updated"}`, w.Body.String())
}

func Test_UpdateRoles_BindJsonError(t *testing.T) {
	clearMock()

	body := `invalid_json`
	req := httptest.NewRequest("POST", "/roles/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid JSON data: invalid character 'i' looking for beginning of value"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid JSON data")
}

func Test_UpdateRoles_UpdateRolesError(t *testing.T) {
	clearMock()
	errMap := make(map[string]error)
	errMap["UpdateRoles"] = errors.New("UpdateRoles error")

	body := `{"role_update":"someData"}`
	req := httptest.NewRequest("POST", "/roles/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	mockService.SetMock(service.Mock{
		Error: errMap,
	})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to update roles"}`, w.Body.String())
}
