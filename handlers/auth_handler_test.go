package handler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	m "github.com/demkowo/auth/internal/testutil/mocks"
	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/helper"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	c      *gin.Context
	w      *httptest.ResponseRecorder
	tn, _  = time.Parse("2006-01-02T15:04:05", "2025-02-06T11:35:20")
	errMap map[string]error

	mService = m.NewServiceMock()
	handler  = NewAccount(mService)

	acc            model.Account
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
)

func TestMain(m *testing.M) {
	helper.StartMock()
	help = helper.NewHelper()

	os.Exit(m.Run())
}

func setReq(method string, target string, body string, token ...string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	if len(token) > 0 {
		req.Header.Set("Authorization", token[0])
	}

	return req
}

func clearMock() {
	acc = defaultAccount
	recorder := httptest.NewRecorder()
	w = recorder
	context, _ := gin.CreateTestContext(w)
	c = context
	errMap = make(map[string]error)
}

func Test_Add_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/accounts", `{"email":"test@test.com","password":"Qwerty!23","nickname":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_Add_Success"})

	handler.Add(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{
		"code":201,
		"data":[{
			"id":"00000000-0000-0000-0000-000000000000",
			"email":"test@test.com",
			"password":"Qwerty!23",
			"nickname":"tester",
			"roles":null,
			"api_keys":null,
			"created":"0001-01-01T00:00:00Z",
			"updated":"0001-01-01T00:00:00Z",
			"blocked":"0001-01-01T00:00:00Z",
			"deleted":false,"providers":null}],
		"message":"account registered successfully",
		"status":"Created"}`,
		w.Body.String())
}

func Test_Add_BindJSONError(t *testing.T) {
	clearMock()

	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_Add_BindJSONError", Error: errMap})

	handler.Add(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_Add_ValidateError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/accounts", `{"email":"test@test.com","password":"wrongPassword","nickname":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_Add_ValidateError"})

	handler.Add(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{
		"causes":["password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit"],
		"code":500,
		"error":"invalid password",
		"status":"Internal Server Error"
	}`, w.Body.String())
}

func Test_Add_AddError(t *testing.T) {
	clearMock()

	errMap["Add"] = errors.New("Add error")
	c.Request = setReq("POST", "/accounts", `{"email":"test@test.com","password":"Qwerty!23","nickname":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_Add_AddError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Add(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Add error"],"code":500,"error":"failed to create account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_Block_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/block", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","until":"2025-04-01"}`)

	helper.AddMock(helper.Mock{Test: "Test_Block_Success"})

	handler.Block(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":[null],"message":"account blocked successfully","status":"OK"}`, w.Body.String())
}

func Test_Block_BindJSONError(t *testing.T) {
	clearMock()

	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_Block_BindJSONError", Error: errMap})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_Block_ParseTimeError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/block", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","until":"2025-04-01"}`)
	errMap["ParseTime"] = errors.New("ParseTime error")

	helper.AddMock(helper.Mock{Test: "Test_Block_ParseTimeError", Error: errMap})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseTime error"],"code":400,"error":"invalid time format","status":"Bad Request"}`, w.Body.String())
}

func Test_Block_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/block", `{"account_id":"invalidUUID","until":"2025-02-02"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_Block_ParseUUIDError", Error: errMap})

	handler.Block(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_Block_BlockError(t *testing.T) {
	clearMock()

	errMap["Block"] = errors.New("Block error")
	c.Request = setReq("POST", "/block", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","until":"2025-02-02"}`)

	helper.AddMock(helper.Mock{Test: "Test_Block_BlockError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Block(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Block error"],"code":500,"error":"failed to block account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_Delete_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String(), nil)

	helper.AddMock(helper.Mock{Test: "Test_Delete_Success"})

	handler.Delete(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":null,"message":"account deleted successfully","status":"OK"}`, w.Body.String())
}

func Test_Delete_ParseUUIDError(t *testing.T) {
	clearMock()

	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_Delete_ParseUUIDError", Error: errMap})

	handler.Delete(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_Delete_DeleteError(t *testing.T) {
	clearMock()

	errMap["Delete"] = errors.New("Delete error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("DELETE", "/accounts/"+acc.Id.String(), nil)

	helper.AddMock(helper.Mock{Test: "Test_Delete_DeleteError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Delete(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Delete error"],"code":500,"error":"failed to delete account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	c.Request = httptest.NewRequest("GET", "/api/v1/auth/find", nil)

	handler.Find(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":[null],"message":"account found successfully","status":"OK"}`, w.Body.String())
}

func Test_Find_FindError(t *testing.T) {
	clearMock()

	errMap["Find"] = errors.New("Find error")
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/find", nil)

	mService.AddMock(m.Service{Error: errMap})

	handler.Find(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Find error"],"code":500,"error":"failed to find accounts","status":"Internal Server Error"}`, w.Body.String())
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "email", Value: "admin@admin.com"}}
	c.Request = setReq("POST", "/get-by-email", `{"email": "admin@admin.com"}`)

	helper.AddMock(helper.Mock{Test: "Test_GetByEmail_Success"})
	mService.AddMock(m.Service{Account: &acc})

	handler.GetByEmail(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
	"code":200,
	"data":[{
		"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
		"email":"admin@admin.com",
		"password":"secretHashedPass",
		"nickname":"admin",
		"roles":null,"api_keys":null,
		"created":"2025-02-06T11:35:20Z",
		"updated":"2025-02-06T11:35:20Z",
		"blocked":"0001-01-01T00:00:00Z",
		"deleted":false,"providers":null}],
	"message":"account fetched successfully",
	"status":"OK"}`, w.Body.String())
}

func Test_GetByEmail_BindJSONError(t *testing.T) {
	clearMock()

	errMap["BindJSON"] = errors.New("BindJSON error")
	c.Request = setReq("POST", "/get-by-email", `{"email": "admin@admin.com"}`)

	helper.AddMock(helper.Mock{Test: "Test_GetByEmail_BindJSONError", Error: errMap})

	handler.GetByEmail(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_GetByEmail_GetByEmailError(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")
	c.Request = setReq("POST", "/get-by-email", `{"email": "admin@admin.com"}`)

	helper.AddMock(helper.Mock{Test: "Test_GetByEmail_GetByEmailError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.GetByEmail(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["GetByEmail error"],"code":500,"error":"failed to get account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("GET", "/accounts/"+acc.Id.String(), nil)

	helper.AddMock(helper.Mock{Test: "Test_GetById_Success"})
	mService.AddMock(m.Service{Account: &acc})

	handler.GetById(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
		"code":200,
		"data":[{
			"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
			"email":"admin@admin.com",
			"password":"secretHashedPass",
			"nickname":"admin",
			"roles":null,
			"api_keys":null,
			"created":"2025-02-06T11:35:20Z",
			"updated":"2025-02-06T11:35:20Z",
			"blocked":"0001-01-01T00:00:00Z",
			"deleted":false,"providers":null}],
		"message":"account fetched successfully",
		"status":"OK"}`, w.Body.String())
}

func Test_GetById_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	c.Request = httptest.NewRequest("GET", "/accounts/invalidUUID", nil)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_GetById_ParseUUIDError", Error: errMap})

	handler.GetById(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_GetById_ServiceError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("GET", "/accounts/"+acc.Id.String(), nil)

	errMap["GetById"] = errors.New("GetById error")

	helper.AddMock(helper.Mock{Test: "Test_GetById_ServiceError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.GetById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["GetById error"],"code":500,"error":"failed to get account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_Login_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/login", `{"email":"admin@admin.com","password":"secret"}`)

	helper.AddMock(helper.Mock{Test: "Test_Login_Success"})
	mService.AddMock(m.Service{Token: "someValidToken"})

	handler.Login(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":["someValidToken"],"message":"login successful","status":"OK"}`, w.Body.String())
}

func Test_Login_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/login", `{"email":123,"password":"secret"}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_Login_BindJSONError", Error: errMap})

	handler.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_Login_LoginError(t *testing.T) {
	clearMock()

	errMap["Login"] = errors.New("Login error")
	c.Request = setReq("POST", "/login", `{"email":"admin@admin.com","password":"wrong"}`)

	helper.AddMock(helper.Mock{Test: "Test_Login_LoginError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Login(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"causes":["Login error"],"code":401,"error":"login failed","status":"Unauthorized"}`, w.Body.String())
}

func Test_RefreshToken_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/refresh", "", "Bearer sometoken")

	mService.AddMock(m.Service{Token: "someValidToken"})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":["someValidToken"],"message":"token refreshed successfully","status":"OK"}`, w.Body.String())

}

func Test_RefreshToken_GetHeaderError(t *testing.T) {
	clearMock()

	req := httptest.NewRequest("POST", "/refresh", nil)
	c.Request = req

	mService.AddMock(m.Service{})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["authorization header can't be empty"],"code":400,"error":"invalid authorication header","status":"Bad Request"}`, w.Body.String())
}

func Test_RefreshToken_HeaderFormatError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/refresh", "", "invalidToken")

	mService.AddMock(m.Service{})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["invalid format"],"code":400,"error":"invalid authorication header","status":"Bad Request"}`, w.Body.String())
}

func Test_RefreshToken_RefreshTokenError(t *testing.T) {
	clearMock()

	errMap["RefreshToken"] = errors.New("RefreshToken error")
	c.Request = setReq("POST", "/refresh", "", "Bearer invalidToken")

	mService.AddMock(m.Service{Error: errMap})

	handler.RefreshToken(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"causes":["RefreshToken error"],"code":401,"error":"refresh token failed","status":"Unauthorized"}`, w.Body.String())
}

func Test_Unblock_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/unblock", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_Unblock_Success"})

	handler.Unblock(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":[null],"message":"Account unblocked successfully","status":"OK"}`, w.Body.String())
}

func Test_Unblock_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/unblock", `{"account_id":123}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_Unblock_BindJSONError", Error: errMap})

	handler.Unblock(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_Unblock_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/unblock", `{"account_id":"invalidUUID"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_Unblock_ParseUUIDError", Error: errMap})

	mService.AddMock(m.Service{})

	handler.Unblock(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_Unblock_UnblockError(t *testing.T) {
	clearMock()

	errMap["Unblock"] = errors.New("Unblock error")
	c.Request = setReq("POST", "/unblock", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_Unblock_UnblockError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Unblock(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Unblock error"],"code":500,"error":"failed to unblock account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/update-password", `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","old_pass":"old123","new_pass":"new123"}`)

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_Success"})
	mService.AddMock(m.Service{})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":null,"message":"Password changed successfully","status":"OK"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "Password changed successfully")
}

func Test_UpdatePassword_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/update-password", `{"id":123,"old_pass":"old123","new_pass":"new123"}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_BindJSONError", Error: errMap})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_UpdatePassword_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/update-password", `{"id":"invalidUUID","old_pass":"old123","new_pass":"new123"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_ParseUUIDError", Error: errMap})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_UpdatePassword_UpdatePasswordError(t *testing.T) {
	clearMock()

	errMap["UpdatePassword"] = errors.New("UpdatePassword error")
	c.Request = setReq("POST", "/update-password", `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","old_pass":"old","new_pass":"new"}`)

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_UpdatePasswordError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.UpdatePassword(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["UpdatePassword error"],"code":500,"error":"failed to change password","status":"Internal Server Error"}`, w.Body.String())
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/api/v1/auth/api-key/"+acc.Id.String(), `{"expires_at":"2026-02-06T00:00:00Z"}`)

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_Success"})
	mService.AddMock(m.Service{ApiKey: &model.APIKey{Key: "validAPIKey"}})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{
		"code":201,
		"data":[{
			"id":"00000000-0000-0000-0000-000000000000",
			"key":"validAPIKey",
			"account_id":"00000000-0000-0000-0000-000000000000",
			"created_at":"0001-01-01T00:00:00Z",
			"expires_at":"0001-01-01T00:00:00Z"}],
		"message":"api key created successfully",
		"status":"Created"}`, w.Body.String())
}

func Test_AddAPIKey_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	c.Request = setReq("POST", "/api/v1/auth/api-key/"+acc.Id.String(), `{"expires_at":"2026-02-06T00:00:00Z"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_ParseUUIDError", Error: errMap})
	mService.AddMock(m.Service{ApiKey: &model.APIKey{Key: "validAPIKey"}})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_AddAPIKey_BindJSONError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/api/v1/auth/api-key/"+acc.Id.String(), `{"expires_at":"2026-02-06T00:00:00Z"}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_BindJSONError", Error: errMap})
	mService.AddMock(m.Service{ApiKey: &model.APIKey{Key: "validAPIKey"}})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_AddAPIKey_AddAPIKeyError(t *testing.T) {
	clearMock()

	errMap["AddAPIKey"] = errors.New("AddAPIKey error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/api/v1/auth/api-key/"+acc.Id.String(), `{"expires_at":"2026-02-06T00:00:00Z"}`)

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_AddAPIKeyError"})
	mService.AddMock(m.Service{Error: errMap, ApiKey: &model.APIKey{Key: "validAPIKey"}})

	handler.AddAPIKey(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["AddAPIKey error"],"code":500,"error":"failed to create API key","status":"Internal Server Error"}`, w.Body.String())
}

func Test_AuthenticateByAPIKey_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("GET", "/api-key-auth", "", "Bearer someValidKey")

	mService.AddMock(m.Service{Account: &acc})

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
		"code":200,
		"data":[{
			"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3",
			"email":"admin@admin.com",
			"password":"secretHashedPass",
			"nickname":"admin",
			"roles":null,
			"api_keys":null,
			"created":"2025-02-06T11:35:20Z",
			"updated":"2025-02-06T11:35:20Z",
			"blocked":"0001-01-01T00:00:00Z",
			"deleted":false,"providers":null}],
		"message":"authenticated successfully",
		"status":"OK"}`, w.Body.String())
}

func Test_AuthenticateByAPIKey_GetHeaderError(t *testing.T) {
	clearMock()

	c.Request = httptest.NewRequest("GET", "/api-key-auth", nil)

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"causes":["API key required"],"code":401,"error":"empty API Key","status":"Unauthorized"}`, w.Body.String())
}

func Test_AuthenticateByAPIKey_AuthenticateByAPIKeyError(t *testing.T) {
	clearMock()

	errMap["AuthenticateByAPIKey"] = errors.New("AuthenticateByAPIKey error")
	c.Request = setReq("GET", "/api-key-auth", "", "Bearer invalid")

	mService.AddMock(m.Service{Error: errMap})

	handler.AuthenticateByAPIKey(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.JSONEq(t, `{"causes":["AuthenticateByAPIKey error"],"code":401,"error":"failed to authenticate with API key","status":"Unauthorized"}`, w.Body.String())
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/api-keys/delete", `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_DeleteAPIKey_Success"})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":["3a82ef35-6de8-4eaa-9f53-5a99645772e3"],"message":"api key deleted successfully","status":"OK"}`, w.Body.String())
}

func Test_DeleteAPIKey_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/api-keys/delete", `{"id":123}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_DeleteAPIKey_BindJSONError", Error: errMap})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_DeleteAPIKey_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/api-keys/delete", `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_DeleteAPIKey_ParseUUIDError", Error: errMap})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_DeleteAPIKey_DeleteAPIKeyError(t *testing.T) {
	clearMock()

	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")
	c.Request = setReq("POST", "/api-keys/delete", `{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_DeleteAPIKey_DeleteAPIKeyError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.DeleteAPIKey(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["DeleteAPIKey error"],"code":500,"error":"failed to delete API key","status":"Internal Server Error"}`, w.Body.String())
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/accounts/"+acc.Id.String()+"/roles", `{"role":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_AddAccountRole_Success"})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{"code":201,"data":[null],"message":"role assigned to account successfully","status":"Created"}`, w.Body.String())
}

func Test_AddAccountRole_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	c.Request = setReq("POST", "/accounts/invalidUUID/roles", `{"role":"tester"}`)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_AddAccountRole_ParseUUIDError", Error: errMap})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_AddAccountRole_BindJSONError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/accounts/"+acc.Id.String()+"/roles", `{"role":123}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_AddAccountRole_BindJSONError", Error: errMap})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_AddAccountRole_AddAccountRoleError(t *testing.T) {
	clearMock()

	errMap["AddAccountRole"] = errors.New("AddAccountRole error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("POST", "/accounts/"+acc.Id.String()+"/roles", `{"role":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_AddAccountRole_AddAccountRoleError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.AddAccountRole(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["AddAccountRole error"],"code":500,"error":"failed to add role to account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_DeleteAccountRoleById_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "3a82ef35-6de8-4eaa-9f53-5a99645772e3"}}

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRoleById_Success"})

	handler.DeleteAccountRoleById(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":["3a82ef35-6de8-4eaa-9f53-5a99645772e3"],"message":"role deleted from account successfully","status":"OK"}`, w.Body.String())
}

func Test_DeleteAccountRole_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "3a82ef35-6de8-4eaa-9f53-5a99645772e3"}}
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRole_ParseUUIDError", Error: errMap})

	handler.DeleteAccountRoleById(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_DeleteAccountRoleById_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRoleById"] = errors.New("DeleteAccountRoleById error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRoleById_Error"})
	mService.AddMock(m.Service{Error: errMap})

	handler.DeleteAccountRoleById(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["DeleteAccountRoleById error"],"code":500,"error":"failed to delete role from account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_DeleteAccountRoleByName_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("DELETE", "/accounts/"+acc.Id.String()+"/roles", `{"role":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRoleByName_Success"})

	handler.DeleteAccountRoleByName(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":["tester"],"message":"role deleted from account successfully","status":"OK"}`, w.Body.String())
}

func Test_DeleteAccountRoleByName_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("DELETE", "/accounts/"+acc.Id.String()+"/roles", `{"role":123}`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRoleByName_BindJSONError", Error: errMap})

	handler.DeleteAccountRoleByName(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_DeleteAccountRoleByName_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRoleByName"] = errors.New("DeleteAccountRoleByName error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = setReq("DELETE", "/accounts/"+acc.Id.String()+"/roles", `{"role":"tester"}`)

	helper.AddMock(helper.Mock{Test: "Test_DeleteAccountRoleByName_Error"})
	mService.AddMock(m.Service{Error: errMap})

	handler.DeleteAccountRoleByName(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["DeleteAccountRoleByName error"],"code":500,"error":"failed to delete role from account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("GET", "/accounts/"+acc.Id.String()+"/roles", nil)
	acc.Roles = []model.AccountRole{{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "admin"}}

	helper.AddMock(helper.Mock{Test: "Test_FindRolesByAccount_Success"})
	mService.AddMock(m.Service{AccountRoles: acc.Roles})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
		"code":200,
		"data":[[{"id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3","name":"admin"}]],
		"message":"roles found successfully",
		"status":"OK"
	}`, w.Body.String())
}

func Test_FindRolesByAccount_ParseUUIDError(t *testing.T) {
	clearMock()

	c.Params = []gin.Param{{Key: "account_id", Value: "invalidUUID"}}
	c.Request = httptest.NewRequest("GET", "/accounts/invalidUUID/roles", nil)
	errMap["ParseUUID"] = errors.New("ParseUUID error")

	helper.AddMock(helper.Mock{Test: "Test_FindRolesByAccount_ParseUUIDError", Error: errMap})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["ParseUUID error"],"code":400,"error":"invalid UUID format","status":"Bad Request"}`, w.Body.String())
}

func Test_FindRolesByAccount_FindRolesByAccountError(t *testing.T) {
	clearMock()

	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")
	c.Params = []gin.Param{{Key: "account_id", Value: acc.Id.String()}}
	c.Request = httptest.NewRequest("GET", "/accounts/"+acc.Id.String()+"/roles", nil)

	helper.AddMock(helper.Mock{Test: "Test_FindRolesByAccount_FindRolesByAccountError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.FindRolesByAccount(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["FindRolesByAccount error"],"code":500,"error":"failed to find roles","status":"Internal Server Error"}`, w.Body.String())
}

func Test_UpdateRoles_Success(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/roles/update", `{"role_update":"someData"}`)

	helper.AddMock(helper.Mock{Test: "Test_UpdateRoles_Success"})
	mService.AddMock(m.Service{})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":[],"message":"roles updated successfully","status":"OK"}`, w.Body.String())
}

func Test_UpdateRoles_BindJSONError(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/roles/update", `invalid_json`)
	errMap["BindJSON"] = errors.New("BindJSON error")

	helper.AddMock(helper.Mock{Test: "Test_UpdateRoles_BindJSONError", Error: errMap})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_UpdateRoles_UpdateRolesError(t *testing.T) {
	clearMock()

	errMap["UpdateRoles"] = errors.New("UpdateRoles error")
	c.Request = setReq("POST", "/roles/update", `{"role_update":"someData"}`)

	helper.AddMock(helper.Mock{Test: "Test_UpdateRoles_UpdateRolesError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.UpdateRoles(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["UpdateRoles error"],"code":500,"error":"failed to update roles","status":"Internal Server Error"}`, w.Body.String())
}

func Test_Logout_Succesfull(t *testing.T) {
	clearMock()

	c.Request = setReq("POST", "/logout", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_Logout_Succesfull"})

	handler.Logout(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":null,"message":"logout successful","status":"OK"}`, w.Body.String())
}

func Test_Logout_BindJSONError(t *testing.T) {
	clearMock()

	errMap["BindJSON"] = errors.New("BindJSON error")
	c.Request = setReq("POST", "/logout", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_Logout_BindJSONError", Error: errMap})

	handler.Logout(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":["BindJSON error"],"code":400,"error":"invalid JSON","status":"Bad Request"}`, w.Body.String())
}

func Test_Logout_ServiceError(t *testing.T) {
	clearMock()

	errMap["Logout"] = errors.New("Logout error")
	c.Request = setReq("POST", "/logout", `{"account_id":"3a82ef35-6de8-4eaa-9f53-5a99645772e3"}`)

	helper.AddMock(helper.Mock{Test: "Test_Logout_ServiceError"})
	mService.AddMock(m.Service{Error: errMap})

	handler.Logout(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["Logout error"],"code":500,"error":"failed to logout","status":"Internal Server Error"}`, w.Body.String())
}

func Test_OAuthCallback_Succesfull(t *testing.T) {
	clearMock()

	c.Request = httptest.NewRequest("Get", "/callback/google?code=someValidCode", nil)

	handler.OAuthCallback(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"code":200,"data":[null],"message":"OAuth2 callback successful","status":"OK"}`, w.Body.String())
}

func Test_OAuthCallback_CodeError(t *testing.T) {
	clearMock()

	c.Request = httptest.NewRequest("Get", "/callback/google", nil)

	handler.OAuthCallback(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"causes":null,"code":400,"error":"code not provided","status":"Bad Request"}`, w.Body.String())
}

func Test_OAuthCallback_ExchangeCodeForTokenError(t *testing.T) {
	clearMock()

	errMap["ExchangeCodeForToken"] = errors.New("ExchangeCodeForToken error")
	c.Request = httptest.NewRequest("Get", "/callback/google?code=someValidCode", nil)

	mService.AddMock(m.Service{Error: errMap})

	handler.OAuthCallback(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["ExchangeCodeForToken error"],"code":500,"error":"failed to exchange code for token","status":"Internal Server Error"}`, w.Body.String())
}

func Test_OAuthCallback_GetAccountInfoError(t *testing.T) {
	clearMock()

	errMap["GetAccountInfo"] = errors.New("GetAccountInfo error")
	c.Request = httptest.NewRequest("Get", "/callback/google?code=someValidCode", nil)

	mService.AddMock(m.Service{Error: errMap})

	handler.OAuthCallback(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["GetAccountInfo error"],"code":500,"error":"failed to get account info","status":"Internal Server Error"}`, w.Body.String())
}

func Test_OAuthCallback_StoreAccountError(t *testing.T) {
	clearMock()

	errMap["StoreAccount"] = errors.New("StoreAccount error")
	c.Request = httptest.NewRequest("Get", "/callback/google?code=someValidCode", nil)

	mService.AddMock(m.Service{Error: errMap})

	handler.OAuthCallback(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"causes":["StoreAccount error"],"code":500,"error":"failed to store account","status":"Internal Server Error"}`, w.Body.String())
}

func Test_OAuthLogin_Succesfull(t *testing.T) {
	clearMock()

	c.Request = httptest.NewRequest("Get", "/login/google", nil)
	expectedURL := `https://mockprovider.com/auth?access_type=offline&client_id=mock-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&scope=profile+email&state=state`

	handler.OAuthLogin(c)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, expectedURL, w.Header().Get("Location"))
}

func Test_OAuthLogin_GetOAuthConfigError(t *testing.T) {
	clearMock()

	errMap["GetOAuthConfig"] = errors.New("GetOAuthConfig error")
	c.Request = httptest.NewRequest("Get", "/login/google", nil)

	mService.AddMock(m.Service{Error: errMap})

	handler.OAuthLogin(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, `{"causes":["GetOAuthConfig error"],"code":500,"error":"failed to get OAuth2 config","status":"Internal Server Error"}`, w.Body.String())
}
