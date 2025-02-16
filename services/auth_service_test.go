package service

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/demkowo/auth/config"
	m "github.com/demkowo/auth/internal/testutil/mocks"
	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/helper"
	httpm "github.com/demkowo/utils/http_client"
	"github.com/demkowo/utils/resp"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	errMap = make(map[string]error)

	mRepo   = m.NewRepoMock()
	service = NewAccount(mRepo)

	acc            model.Account
	defaultAccount = model.Account{
		Id:       uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Nickname: "admin",
		Email:    "admin@admin.com",
		Password: "secretHashedPass",
		Roles:    nil,
		APIKeys:  nil,
		Created:  time.Now(),
		Updated:  time.Now(),
		Blocked:  time.Time{},
		Deleted:  false,
	}

	apiKey        model.APIKey
	defaultApiKey = model.APIKey{
		Id:        uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Key:       "someValidKey",
		AccountId: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	accRole        model.AccountRole
	defaultAccRole = &model.AccountRole{
		Id:   uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Name: "admin",
	}
)

func TestMain(m *testing.M) {
	helper.StartMock()
	help = helper.NewHelper()

	httpm.StartMock()
	httpcli = httpm.NewClient()

	log.SetOutput(os.Stdout)
	os.Exit(m.Run())
}

func clearMock() {
	acc = defaultAccount
	apiKey = defaultApiKey
	accRole = *defaultAccRole
	errMap = make(map[string]error)
	mRepo.AddMock(m.Repo{})
}

func Test_Add_Success(t *testing.T) {
	clearMock()

	helper.AddMock(helper.Mock{Test: "Test_Add_Success", Password: "secretHashedPass"})

	account, err := service.Add(&acc)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_Add_NoAccountError(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	account, err := service.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusConflict, "account already exists", []interface{}{"admin@admin.com"}), err)
}

func Test_Add_GetByEmailError(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	mRepo.AddMock(m.Repo{Error: errMap, Account: &acc})

	account, err := service.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func Test_Add_HashPasswordError(t *testing.T) {
	clearMock()

	errMap["HashPassword"] = errors.New("HashPassword error")

	helper.AddMock(helper.Mock{Test: "Test_Add_HashPasswordError", Error: errMap})

	account, err := service.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to hash password", []interface{}{"HashPassword error"}), err)
}

func Test_Add_AddError(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = sql.ErrNoRows
	errMap["Add"] = errors.New("Add error")
	acc.Nickname = "testuser"
	acc.Email = "test@example.com"

	helper.AddMock(helper.Mock{Test: "Test_Add_AddError"})
	mRepo.AddMock(m.Repo{Error: errMap, Account: &acc})

	account, err := service.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{"Add error"}), err)
}

func Test_AddJWTToken_Success(t *testing.T) {
	clearMock()

	acc.Roles = []model.AccountRole{
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "admin"},
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "user"},
	}

	expectedClaims := jwt.MapClaims{
		"id":       acc.Id.String(),
		"nickname": acc.Nickname,
		"exp":      time.Now().Add(24 * time.Hour),
		"roles":    []string{"admin", "user"},
	}

	helper.AddMock(helper.Mock{Test: "Test_AddJWTToken_Success"})

	token, err := service.AddJWTToken(&acc)

	assert.Nil(t, err)

	res, e := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return conf.JWTSecret, nil
	})
	assert.Nil(t, e)
	assert.Equal(t, true, res.Valid)

	claims, ok := res.Claims.(jwt.MapClaims)
	assert.Equal(t, true, ok)

	assert.Equal(t, expectedClaims["id"], claims["id"])
	assert.Equal(t, expectedClaims["nickname"], claims["nickname"])
	assert.Equal(t, fmt.Sprint(expectedClaims["roles"]), fmt.Sprint(claims["roles"]))
}

func Test_AddJWTToken_Error(t *testing.T) {
	clearMock()

	token, err := service.AddJWTToken(nil)

	assert.Equal(t, "", token)
	assert.NotNil(t, err)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"missing account"}), err)
}

func Test_AddJWTToken_TokenSignedStringError(t *testing.T) {
	clearMock()

	errMap["TokenSignedString"] = errors.New("TokenSignedString error")

	helper.AddMock(helper.Mock{Test: "Test_AddJWTToken_TokenSignedStringError", Error: errMap})

	token, err := service.AddJWTToken(&acc)

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"TokenSignedString error"}), err)
}

func Test_Block_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	account, err := service.Block(acc.Id, time.Time{})

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_Block_GetByIdError(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	account, err := service.Block(uuid.New(), time.Now().Add(24*time.Hour))

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_Block_UpdateError(t *testing.T) {
	clearMock()

	errMap["Update"] = errors.New("Update error")

	mRepo.AddMock(m.Repo{Error: errMap, Account: &acc})

	account, err := service.Block(uuid.New(), acc.Blocked)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{"Update error"}), err)
}

func Test_CheckAccess_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &model.Account{Id: uuid.New(), Deleted: false, Blocked: time.Time{}}})

	err := service.CheckAccess(uuid.New())

	assert.Nil(t, err)
}

func Test_CheckAccess_GetByIdError(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.CheckAccess(uuid.New())

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_CheckAccess_DeletedError(t *testing.T) {
	clearMock()

	acc.Deleted = true

	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.CheckAccess(uuid.New())

	assert.Equal(t, resp.Error(http.StatusUnauthorized, "account is deleted", nil), err)
}

func Test_CheckAccess_BlockedError(t *testing.T) {
	clearMock()

	acc.Blocked = time.Now().Add(time.Hour)

	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.CheckAccess(uuid.New())

	assert.Equal(t, resp.Error(http.StatusUnauthorized,
		fmt.Sprintf("account is banned until %s", acc.Blocked.Format(time.RFC3339)), nil), err)
}

func Test_Delete_Success(t *testing.T) {
	clearMock()

	err := service.Delete(uuid.New())

	assert.Nil(t, err)
}

func Test_Delete_Error(t *testing.T) {
	clearMock()

	errMap["Delete"] = errors.New("Delete error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.Delete(uuid.New())

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{"Delete error"}), err)
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	acc := []*model.Account{
		{Id: uuid.New(), Email: "test1@example.com", Password: "Paasss!23"},
		{Id: uuid.New(), Email: "test2@example.com", Password: "Paassy!23"},
	}

	mRepo.AddMock(m.Repo{Accounts: acc})

	accounts, err := service.Find()

	assert.Nil(t, err)
	assert.Equal(t, acc[0], accounts[0])
	assert.Equal(t, acc[1], accounts[1])
}

func Test_Find_Error(t *testing.T) {
	clearMock()

	errMap["Find"] = errors.New("Find error")

	mRepo.AddMock(m.Repo{Error: errMap})

	accounts, err := service.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Find error"}), err)
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	account, err := service.GetByEmail("test@example.com")

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_GetByEmail_Error(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	mRepo.AddMock(m.Repo{Error: errMap})

	account, err := service.GetByEmail("test@example.com")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	account, err := service.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_GetById_Error(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById err")

	mRepo.AddMock(m.Repo{Error: errMap})

	account, err := service.GetById(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById err"}), err)
}

func Test_Login_Success(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("validPassword"), bcrypt.DefaultCost)
	acc.Password = string(hashed)

	helper.AddMock(helper.Mock{Test: "Login"})
	mRepo.AddMock(m.Repo{Account: &acc})

	token, err := service.Login("email@example.com", "validPassword")

	parts := strings.Split(token, ".")
	assert.Nil(t, err) // token is being tested with more details in AddJWTToken
	if assert.True(t, len(parts) == 3) {
		assert.Equal(t, 36, len(parts[0]))
		assert.Equal(t, 123, len(parts[1]))
		assert.Equal(t, 43, len(parts[2]))
	}
}

func Test_Login_GetByEmailError(t *testing.T) {
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	mRepo.AddMock(m.Repo{Error: errMap})

	token, err := service.Login("email@example.com", "invalidPassword")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func Test_Login_CheckAccessError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	acc.Password = string(hashed)
	acc.Deleted = true // triggers error in CheckAccess

	mRepo.AddMock(m.Repo{Account: &acc})

	token, err := service.Login("email@example.com", "invalidPassword")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "account is deleted", nil), err)
}

func Test_Login_CompareHashAndPasswordError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("invalidPassword"), bcrypt.DefaultCost)
	acc.Password = string(hashed)

	mRepo.AddMock(m.Repo{Account: &acc})

	token, err := service.Login("email@example.com", "validPassword")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusUnauthorized,
		"invalid credentials", []interface{}{"crypto/bcrypt: hashedPassword is not the hash of the given password"}), err)
}

func Test_Login_AddJwtTokenError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("validPassword"), bcrypt.DefaultCost)
	acc.Password = string(hashed)

	errMap["TokenSignedString"] = errors.New("TokenSignedString error")

	helper.AddMock(helper.Mock{Test: "Login", Error: errMap})
	mRepo.AddMock(m.Repo{Account: &acc})

	token, err := service.Login("email@example.com", "validPassword")

	assert.Equal(t, "", token)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"TokenSignedString error"}), err)
}

func Test_RefreshToken_Success(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	helper.AddMock(helper.Mock{Test: "RefreshToken"})
	mRepo.AddMock(m.Repo{Account: &acc})

	newToken, err := service.RefreshToken(tokenStr)

	parts := strings.Split(newToken, ".")

	assert.Nil(t, err) // token is being tested with more details in AddJWTToken
	if assert.True(t, len(parts) == 3) {
		assert.Equal(t, 36, len(parts[0]))
		assert.Equal(t, 123, len(parts[1]))
		assert.Equal(t, 43, len(parts[2]))
	}
}

func Test_RefreshToken_InvalidTokenError(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	newToken, err := service.RefreshToken("invalid.token.string")

	assert.Equal(t, "", newToken)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "failed to refresh token",
		[]interface{}{"invalid character '\\u008a' looking for beginning of value"}), err)
}

func Test_RefreshToken_UuidParseError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  "invalid_UUID",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	newToken, err := service.RefreshToken(tokenStr)

	assert.Equal(t, "", newToken)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "invalid account Id", []interface{}{"invalid UUID length: 12"}), err)
}

func Test_RefreshToken_GetByIdError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)
	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Equal(t, "", newToken)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_RefreshToken_CheckAccessError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)
	acc.Deleted = true // triggers error in CheckAccess

	mRepo.AddMock(m.Repo{Account: &acc})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Equal(t, "", newToken)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "account is deleted", nil), err)
}

func Test_RefreshToken_AddJwtTokenError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)
	errMap["TokenSignedString"] = errors.New("TokenSignedString error")

	helper.AddMock(helper.Mock{Test: "RefreshToken", Error: errMap})
	mRepo.AddMock(m.Repo{Account: &acc})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Equal(t, "", newToken)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"TokenSignedString error"}), err)
}

func Test_Unblock_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	account, err := service.Unblock(uuid.New())

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_Unblock_GetByIdError(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	account, err := service.Unblock(uuid.New())

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_Unblock_UpdateError(t *testing.T) {
	clearMock()

	errMap["Update"] = errors.New("Update error")

	mRepo.AddMock(m.Repo{Account: &acc, Error: errMap})

	account, err := service.Unblock(uuid.New())

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{"Update error"}), err)
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)
	newPass := "newPass!@#"

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_Success", Password: newPass})
	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.UpdatePassword(uuid.New(), oldPass, newPass)

	assert.Nil(t, err)
}

func Test_UpdatePassword_GetByIdError(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.UpdatePassword(uuid.New(), "oldpass", "newpass")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_UpdatePassword_InvalidOldPasswordError(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.UpdatePassword(uuid.New(), "invalidOldPass", "newPass")

	assert.Equal(t, resp.Error(http.StatusBadRequest, "invalid old password",
		[]interface{}{"crypto/bcrypt: hashedSecret too short to be a bcrypted password"}), err)
}

func Test_UpdatePassword_HashPasswordError(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)
	errMap["HashPassword"] = errors.New("HashPassword error")

	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_HashPasswordError", Error: errMap})
	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.UpdatePassword(uuid.New(), oldPass, "newPass!@#")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to hash password",
		[]interface{}{"HashPassword error"}), err)
}

func Test_UpdatePassword_UpdatePasswordError(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)
	errMap["UpdatePassword"] = errors.New("UpdatePassword error")

	mRepo.AddMock(m.Repo{Account: &acc, Error: errMap})
	helper.AddMock(helper.Mock{Test: "Test_UpdatePassword_UpdatePasswordError"})

	err := service.UpdatePassword(uuid.New(), oldPass, "newPass!@#")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{"UpdatePassword error"}), err)
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_Success"})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func Test_AddAPIKey_GetRandomBytesError(t *testing.T) {
	clearMock()

	errMap["GetRandomBytes"] = errors.New("GetRandomBytes error")

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_GetRandomBytesError", Error: errMap})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API Key", []interface{}{"GetRandomBytes error"}), err)
}

func Test_AddAPIKey_AddAPIKeyError(t *testing.T) {
	clearMock()

	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	helper.AddMock(helper.Mock{Test: "Test_AddAPIKey_AddAPIKeyError"})
	mRepo.AddMock(m.Repo{Error: errMap})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.Nil(t, key)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{"AddAPIKey error"}), err)
}

func Test_AuthenticateByAPIKey_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc, ApiKey: &apiKey})

	account, err := service.AuthenticateByAPIKey("asd")

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_AuthenticateByAPIKey_GetAPIKeyByKeyError(t *testing.T) {
	clearMock()

	errMap["GetAPIKeyByKey"] = errors.New("GetAPIKeyByKey error")

	mRepo.AddMock(m.Repo{Error: errMap, ApiKey: &apiKey})

	account, err := service.AuthenticateByAPIKey("asd")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"GetAPIKeyByKey error"}), err)
}

func Test_AuthenticateByAPIKey_ExpiredKeyError(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Now().Add(time.Hour * -1)

	mRepo.AddMock(m.Repo{Account: &acc, ApiKey: &apiKey})

	account, err := service.AuthenticateByAPIKey("asd")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "API key expired", nil), err)
}

func Test_AuthenticateByAPIKey_GetByIdError(t *testing.T) {
	clearMock()

	errMap["GetById"] = errors.New("GetById error")

	mRepo.AddMock(m.Repo{ApiKey: &apiKey, Account: &acc, Error: errMap})

	account, err := service.AuthenticateByAPIKey("asd")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetById error"}), err)
}

func Test_AuthenticateByAPIKey_CheckAccessError(t *testing.T) {
	clearMock()

	acc.Deleted = true

	mRepo.AddMock(m.Repo{ApiKey: &apiKey, Account: &acc})

	account, err := service.AuthenticateByAPIKey("asd")

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusUnauthorized, "account is deleted", nil), err)
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	err := service.DeleteAPIKey(acc.Id)

	assert.Nil(t, err)
}

func Test_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.DeleteAPIKey(acc.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{"DeleteAPIKey error"}), err)
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	mRepo.AddMock(m.Repo{AccountRoles: []model.AccountRole{accRole}})

	roles, err := service.AddAccountRole(acc.Id, "admin")

	assert.Nil(t, err)
	assert.Equal(t, []*model.AccountRole{&accRole}[0], roles)
}

func Test_AddAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	mRepo.AddMock(m.Repo{AccountRoles: []model.AccountRole{accRole}, Error: errMap})

	roles, err := service.AddAccountRole(uuid.New(), "admin")

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{"AddAccountRole error"}), err)
}

func Test_DeleteAccountRoleById_Success(t *testing.T) {
	clearMock()

	err := service.DeleteAccountRoleById(uuid.New())

	assert.Nil(t, err)
}

func Test_DeleteAccountRoleById_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRoleById"] = errors.New("DeleteAccountRoleById error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.DeleteAccountRoleById(uuid.New())

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"DeleteAccountRoleById error"}), err)
}

func Test_DeleteAccountRoleByName_Success(t *testing.T) {
	clearMock()

	err := service.DeleteAccountRoleByName("admin")

	assert.Nil(t, err)
}

func Test_DeleteAccountRoleByName_Error(t *testing.T) {
	clearMock()

	errMap["DeleteAccountRoleByName"] = errors.New("DeleteAccountRoleByName error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.DeleteAccountRoleByName("admin")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"DeleteAccountRoleByName error"}), err)
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	id1 := uuid.New()
	id2 := uuid.New()

	mRepo.AddMock(m.Repo{AccountRoles: []model.AccountRole{{Id: id1, Name: "admin"}, {Id: id2, Name: "user"}}})

	roles, err := service.FindRolesByAccount(uuid.New())

	assert.Nil(t, err)
	assert.Equal(t, roles, []model.AccountRole{{Id: id1, Name: "admin"}, {Id: id2, Name: "user"}})
}

func Test_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")

	mRepo.AddMock(m.Repo{Error: errMap})

	roles, err := service.FindRolesByAccount(uuid.New())

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"FindRolesByAccount error"}), err)
}

func Test_UpdateRoles_Success(t *testing.T) {
	clearMock()

	rolesMap := map[string]interface{}{"role_" + uuid.NewString() + "_admin": "true", "role_" + uuid.NewString() + "_user": "false"}

	err := service.UpdateRoles(rolesMap)

	assert.Nil(t, err)
}

func Test_UpdateRoles_KeyFormatError(t *testing.T) {
	clearMock()

	rolesMap := map[string]interface{}{"bad_keyFormat": "true"}

	err := service.UpdateRoles(rolesMap)

	assert.NotNil(t, err)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "invalid key format: bad_keyFormat", nil), err)
}

func Test_UpdateRoles_UuidParseError(t *testing.T) {
	clearMock()

	rolesMap := map[string]interface{}{"role_" + "invalidUUID" + "_admin": "true"}

	err := service.UpdateRoles(rolesMap)

	assert.NotNil(t, err)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "errors found while updating roles",
		[]interface{}{[]string{"failed to parse account Id: invalidUUID"}}), err)
}

func Test_UpdateRoles_AddAccountRoleError(t *testing.T) {
	clearMock()

	rolesMap := map[string]interface{}{"role_" + uuid.NewString() + "_admin": "true"}
	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.UpdateRoles(rolesMap)

	assert.NotNil(t, err)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "errors found while updating roles",
		[]interface{}{[]string{"failed to add role admin"}}), err)
}

func Test_UpdateRoles_DeleteAccountRoleByNameError(t *testing.T) {
	clearMock()

	rolesMap := map[string]interface{}{"role_" + uuid.NewString() + "_admin": "false"}
	errMap["DeleteAccountRoleByName"] = errors.New("DeleteAccountRoleByName error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.UpdateRoles(rolesMap)

	assert.NotNil(t, err)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "errors found while updating roles",
		[]interface{}{[]string{"failed to delete role admin"}}), err)
}

func Test_ExchangeCodeForToken_Success(t *testing.T) {
	clearMock()

	provider := "google"
	code := "someValidCode"
	expToken := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}

	helper.AddMock(helper.Mock{Test: "Test_ExchangeCodeForToken_Success", Token: expToken})

	token, err := service.ExchangeCodeForToken(provider, code)

	assert.Nil(t, err)
	assert.Equal(t, &expToken, token)
}

func Test_ExchangeCodeForToken_GetOAuthConfigError(t *testing.T) {
	clearMock()

	provider := "test"
	code := "someValidCode"

	token, err := service.ExchangeCodeForToken(provider, code)

	assert.Nil(t, token)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "unsupported provider", []interface{}{"test"}), err)
}

func Test_ExchangeCodeForToken_ExchangeError(t *testing.T) {
	clearMock()

	provider := "google"
	code := "someValidCode"
	expToken := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	errMap["Exchange"] = errors.New("Exchange error")

	helper.AddMock(helper.Mock{Test: "Test_ExchangeCodeForToken_ExchangeError", Token: expToken, Error: errMap})

	token, err := service.ExchangeCodeForToken(provider, code)

	assert.Nil(t, token)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "failed to exchange code for token", []interface{}{"Exchange error"}), err)
}

func Test_GetAccountInfo_googleSuccess(t *testing.T) {
	clearMock()

	provider := "google"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success", "email": "testuser@google.com", "name":"testuser"}`)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, err)
	assert.Equal(t, "testuser@google.com", account.Email)
	assert.Equal(t, "testuser", account.Nickname)
	assert.Equal(t, []string{"google"}, account.Providers)
}

func Test_GetAccountInfo_githubSuccess(t *testing.T) {
	clearMock()

	provider := "github"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success", "email": "testuser@google.com", "login":"testuser"}`)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, err)
	assert.Equal(t, "testuser@google.com", account.Email)
	assert.Equal(t, "testuser", account.Nickname)
	assert.Equal(t, []string{"github"}, account.Providers)
}

func Test_GetAccountInfo_facebookSuccess(t *testing.T) {
	clearMock()

	provider := "facebook"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success", "email": "testuser@google.com", "name":"testuser"}`)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, err)
	assert.Equal(t, "testuser@google.com", account.Email)
	assert.Equal(t, "testuser", account.Nickname)
	assert.Equal(t, []string{"facebook"}, account.Providers)
}

func Test_GetAccountInfo_unsuportedProviderError(t *testing.T) {
	clearMock()

	provider := "unknown"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success"}`)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "unsupported provider", []interface{}{"unknown"}), err)
}

func Test_GetAccountInfo_GetError(t *testing.T) {
	clearMock()

	provider := "github"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success"}`)),
		Header:     make(http.Header),
	}
	errMap["GET"] = errors.New("GET error")

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp, Error: errMap})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "failed to fetch user info", []interface{}{"GET error"}), err)
}

func Test_GetAccountInfo_HttpResponseError(t *testing.T) {
	clearMock()

	provider := "facebook"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(strings.NewReader(``)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "failed to fetch user info", []interface{}{"Created"}), err)
}

func Test_GetAccountInfo_jsonNewDecoderError(t *testing.T) {
	clearMock()

	provider := "github"
	token := oauth2.Token{AccessToken: "mock-access-token-123", TokenType: "Bearer", RefreshToken: "mock-refresh-token-456", Expiry: time.Now()}
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"message": "success", "email": "testuser@google.com" "name":"testuser"}`)),
		Header:     make(http.Header),
	}

	httpm.AddMock(httpm.Mock{Test: "Get", Response: *mockResp})

	account, err := service.GetAccountInfo(provider, &token)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusBadRequest, "failed to decode user info", []interface{}{"invalid character '\"' after object key:value pair"}), err)
}

func Test_Logout_Success(t *testing.T) {
	clearMock()

	err := service.Logout(acc.Id.String())

	assert.Nil(t, err)
}

func Test_Logout_Error(t *testing.T) {
	clearMock()

	errMap["DeleteOAuth2Token"] = errors.New("DeleteOAuth2Token error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.Logout(acc.Id.String())

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"DeleteOAuth2Token error"}), err)
}

func Test_StoreAccount_Success(t *testing.T) { //0
	clearMock()

	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.StoreAccount(&acc)

	assert.Nil(t, err)
}

func Test_StoreAccount_EmailError(t *testing.T) { //2
	clearMock()

	acc.Email = ""

	mRepo.AddMock(m.Repo{Account: &acc})

	err := service.StoreAccount(&acc)

	assert.Equal(t, resp.Error(http.StatusBadRequest, "invalid account email", []interface{}{"email is empty"}), err)
}

func Test_StoreAccount_GetByEmailError(t *testing.T) { //7,5
	clearMock()

	errMap["GetByEmail"] = errors.New("GetByEmail error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.StoreAccount(&acc)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"GetByEmail error"}), err)
}

func Test_StoreAccount_AddError(t *testing.T) { //7
	clearMock()

	errMap["GetByEmail"] = sql.ErrNoRows
	errMap["Add"] = errors.New("Add error")

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.StoreAccount(&acc)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{"Add error"}), err)
}

func Test_StoreAccount_GetByEmailNotFoundError(t *testing.T) { //7
	clearMock()

	errMap["GetByEmail"] = sql.ErrNoRows

	mRepo.AddMock(m.Repo{Error: errMap})

	err := service.StoreAccount(&acc)

	assert.Nil(t, err)
}

func Test_StoreAccount_UpdateError(t *testing.T) {
	clearMock()

	errMap["Update"] = errors.New("Update error")

	mRepo.AddMock(m.Repo{Error: errMap, Account: &acc})

	err := service.StoreAccount(&acc)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{"Update error"}), err)
}
