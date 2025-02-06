package service

import (
	"errors"
	"log"
	"os"
	"testing"
	"time"

	"github.com/demkowo/auth/config"
	model "github.com/demkowo/auth/models"
	"github.com/demkowo/auth/repositories/postgres"
	"github.com/demkowo/auth/utils"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

var (
	mockRepo = postgres.NewAccountMock()
	service  = NewAccount(mockRepo)

	acc    model.Account
	expAcc model.Account

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
}

func Test_Add_Success(t *testing.T) {
	clearMock()

	utils.Var.SetExpectedPassword("secretHashedPass")
	expAcc.Id = uuid.Nil
	expAcc.Password = "secretHashedPass"

	mockRepo.SetMock(postgres.Mock{
		Account:         &acc,
		ExpectedAccount: &expAcc,
	})

	err := service.Add(&acc)

	assert.NoError(t, err)
}

func Test_Add_GetByEmailError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetByEmail"] = errors.New("GetByEmail error")

	mockRepo.SetMock(postgres.Mock{
		Error:   errMap,
		Account: &acc,
	})

	err := service.Add(&acc)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
}

func Test_Add_HashPasswordError(t *testing.T) {
	clearMock()

	utils.Var.SetExpectedPassword("invalid password")
	mockRepo.SetMock(postgres.Mock{
		Account: nil,
	})

	err := service.Add(&acc)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create an account")
}

func Test_Add_AddError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Add"] = errors.New("Add error")
	utils.Var.SetExpectedPassword("secretHashedPass")
	expAcc.Id = uuid.Nil
	expAcc.Password = "secretHashedPass"

	mockRepo.SetMock(postgres.Mock{
		Error:           errMap,
		Account:         &acc,
		ExpectedAccount: &expAcc,
	})

	err := service.Add(&acc)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create account")
}

func Test_Block_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{Id: uuid.New()},
		Error:   nil,
	})

	svc := NewAccount(mockRepo)
	id := uuid.New()
	until := time.Now().Add(24 * time.Hour)

	err := svc.Block(id, until)
	assert.NoError(t, err)
}

func Test_Block_GetByIdError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("not found")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	err := service.Block(uuid.New(), time.Now().Add(24*time.Hour))

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
}

func Test_Block_UpdateError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Update"] = errors.New("failed to update account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error:   errMap,
		Account: &acc,
	})

	err := service.Block(uuid.New(), time.Now().Add(24*time.Hour))

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to update account")
}

func Test_CheckAccess_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{Id: uuid.New(), Deleted: false, Blocked: time.Time{}},
	})

	svc := NewAccount(mockRepo)
	err := svc.CheckAccess(uuid.New())
	assert.NoError(t, err)
}

func Test_CheckAccess_GetByIdError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("account not found")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	err := service.CheckAccess(uuid.New())

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
}

func Test_CheckAccess_DeletedError(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{Id: uuid.New(), Deleted: true},
	})

	err := service.CheckAccess(uuid.New())
	assert.Error(t, err)
	assert.EqualError(t, err, "account is deleted")
}

func Test_CheckAccess_BlockedError(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{
			Id:      uuid.New(),
			Deleted: false,
			Blocked: time.Now().Add(time.Hour),
		},
	})

	err := service.CheckAccess(uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is banned until")
}

func Test_Delete_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: nil,
	})

	err := service.Delete(uuid.New())

	assert.NoError(t, err)
}

func Test_Delete_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Delete"] = errors.New("failed to delete account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	svc := NewAccount(mockRepo)
	err := svc.Delete(uuid.New())
	assert.Error(t, err)
	assert.EqualError(t, err, "failed to delete account")
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Accounts: []*model.Account{
			{Id: uuid.New(), Email: "test@example.com", Password: "p1"},
			{Id: uuid.New(), Email: "test2@example.com", Password: "p2"},
		},
	})

	accounts, err := service.Find()

	assert.NoError(t, err)
	assert.Len(t, accounts, 2)
	assert.Empty(t, accounts[0].Password, "password should be cleared")
}

func Test_Find_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Find"] = errors.New("failed to find accounts")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	accounts, err := service.Find()

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to find accounts")
	assert.Nil(t, accounts)
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	acc, err := service.GetByEmail("test@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, acc)
	assert.Equal(t, "admin@admin.com", acc.Email)
}

func Test_GetByEmail_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetByEmail"] = errors.New("failed to get account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	acc, err := service.GetByEmail("invalid@email.com")

	assert.Error(t, err)
	assert.Nil(t, acc)
	assert.EqualError(t, err, "failed to get account")
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	acc, err := service.GetById(acc.Id)

	assert.NoError(t, err)
	assert.NotNil(t, acc)
	assert.Equal(t, uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), acc.Id)
}

func Test_GetById_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("failed to get account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	acc, err := service.GetById(uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"))

	assert.Error(t, err)
	assert.Nil(t, acc)
	assert.EqualError(t, err, "failed to get account")
}

func Test_Login_Success(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("validPassword"), bcrypt.DefaultCost)
	acc.Password = string(hashed)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	token, err := service.Login("email@example.com", "validPassword")

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func Test_Login_GetByEmailError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetByEmail"] = errors.New("failed to get account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	token, err := service.Login("invalid@example.com", "password")

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid credentials")
	assert.Empty(t, token)
}

func Test_Login_CheckAccessError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	accID := uuid.New()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{
			Id:       accID,
			Password: string(hashed),
			Deleted:  true, // triggers error in CheckAccess
		},
	})

	token, err := service.Login("email@example.com", "password")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is deleted")
	assert.Empty(t, token)
}

func Test_Login_CompareHashAndPasswordError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("invalidPassword"), bcrypt.DefaultCost)
	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{
			Id:       uuid.New(),
			Password: string(hashed),
		},
	})

	token, err := service.Login("email@example.com", "password")

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid credentials")
	assert.Empty(t, token)
}

func Test_Login_AddJwtTokenError(t *testing.T) {
	clearMock()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("validPassword"), bcrypt.DefaultCost)
	acc.Password = string(hashed)

	errMap := make(map[string]error)
	errMap["AddJWTToken"] = errors.New("failed to create token")
	utils.Var.SetExpectedError(errMap)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	token, err := service.Login("email@example.com", "validPassword")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create token")
	assert.Empty(t, token)
}

func Test_RefreshToken_Success(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.NoError(t, err)
	assert.NotEmpty(t, newToken)
}

func Test_RefreshToken_InvalidTokenError(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{},
	})

	newToken, err := service.RefreshToken("invalid.token.string")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to refresh token")
	assert.Empty(t, newToken)
}

func Test_RefreshToken_InvalidClaimsIdError(t *testing.T) {
	clearMock()

	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   "anything",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(config.Values.Get().JWTSecret)
	assert.NoError(t, err)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to refresh token")
	assert.Empty(t, newToken)
}

func Test_RefreshToken_InvalidAccountIdError(t *testing.T) {
	clearMock()

	claims := jwt.MapClaims{
		"id":       "invalid id",
		"nickname": acc.Nickname,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(config.Values.Get().JWTSecret)
	assert.NoError(t, err)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &model.Account{},
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid account Id")
	assert.Empty(t, newToken)
}

func Test_RefreshToken_GetByIdError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("GetById error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Error(t, err)
	assert.EqualError(t, err, "account not found")
	assert.Empty(t, newToken)
}

func Test_RefreshToken_CheckAccessError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	acc.Deleted = true // triggers error in CheckAccess

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Error(t, err)
	assert.EqualError(t, err, "unauthorized to refresh token")
	assert.Empty(t, newToken)
}

func Test_RefreshToken_AddJWTTokenError(t *testing.T) {
	clearMock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  acc.Id.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(config.Values.Get().JWTSecret)

	errMap := make(map[string]error)
	errMap["AddJWTToken"] = errors.New("GetById error")
	utils.Var.SetExpectedError(errMap)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	newToken, err := service.RefreshToken(tokenStr)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create token")
	assert.Empty(t, newToken)
}

func Test_Unblock_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	err := service.Unblock(uuid.New())

	assert.NoError(t, err)
}

func Test_Unblock_GetByIdError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("account not found")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	err := service.Unblock(uuid.New())

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
}

func Test_Unblock_UpdateError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["Update"] = errors.New("failed to update account")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	err := service.Unblock(uuid.New())

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to update account")
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)

	newPass := "newPass!@#"
	utils.Var.SetExpectedPassword(newPass)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	err := service.UpdatePassword(uuid.New(), oldPass, newPass)

	assert.NoError(t, err)
}

func Test_UpdatePassword_GetByIdError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("account not found")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	err := service.UpdatePassword(uuid.New(), "oldpass", "newpass")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
}

func Test_UpdatePassword_InvalidOldPasswordError(t *testing.T) {
	clearMock()

	oldPass := "invalid oldPass"
	newPass := "newPass!@#"

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	err := service.UpdatePassword(uuid.New(), oldPass, newPass)

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid old password")
}

func Test_UpdatePassword_HashPasswordError(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)

	newPass := "newPass!@#"
	utils.Var.SetExpectedPassword("invalid newPass hash")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
	})

	err := service.UpdatePassword(uuid.New(), oldPass, newPass)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to change password")
}

func Test_UpdatePassword_UpdatePasswordError(t *testing.T) {
	clearMock()

	oldPass := acc.Password
	oldHashed, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	acc.Password = string(oldHashed)

	newPass := "newPass!@#"
	utils.Var.SetExpectedPassword(newPass)

	errMap := make(map[string]error)
	errMap["UpdatePassword"] = errors.New("failed to change password")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Account: &acc,
		Error:   errMap,
	})

	err := service.UpdatePassword(uuid.New(), oldPass, newPass)

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to change password")
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.NoError(t, err)
	assert.NotEmpty(t, key)
}

func Test_AddAPIKey_GetRandomBytesError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetRandomBytes"] = errors.New("GetRandomBytes error")
	utils.Var.SetExpectedError(errMap)

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create API Key")
	assert.Empty(t, key)
}

func Test_AddAPIKey_AddAPIKeyError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AddAPIKey"] = errors.New("AddAPIKey error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	key, err := service.AddAPIKey(uuid.New(), time.Now().Add(time.Hour))

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to create API key")
	assert.Empty(t, key)
}

func Test_AuthenticateByAPIKey_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		ApiKey: &model.APIKey{
			AccountId: acc.Id,
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Account: &acc,
	})

	acc, err := service.AuthenticateByAPIKey("asd")

	assert.NoError(t, err)
	assert.NotNil(t, acc)
}

func Test_AuthenticateByAPIKey_GetAPIKeyByKeyError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetAPIKeyByKey"] = errors.New("GetAPIKeyByKey error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	acc, err := service.AuthenticateByAPIKey("somekey")

	assert.Error(t, err)
	assert.Nil(t, acc)
}

func Test_AuthenticateByAPIKey_ExpiredKeyError(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		ApiKey: &model.APIKey{
			AccountId: acc.Id,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		},
		Account: &model.Account{
			Id: acc.Id,
		},
	})

	acc, err := service.AuthenticateByAPIKey("somekey")

	assert.Error(t, err)
	assert.EqualError(t, err, "API key expired")
	assert.Nil(t, acc)
}

func Test_AuthenticateByAPIKey_GetByIdError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["GetById"] = errors.New("GetById error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		ApiKey: &model.APIKey{
			AccountId: acc.Id,
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Account: &acc,
		Error:   errMap,
	})

	acc, err := service.AuthenticateByAPIKey("somekey")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to get account")
	assert.Nil(t, acc)
}

func Test_AuthenticateByAPIKey_CheckAccessError(t *testing.T) {
	clearMock()

	acc.Deleted = true

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		ApiKey: &model.APIKey{
			AccountId: acc.Id,
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Account: &acc,
	})

	acc, err := service.AuthenticateByAPIKey("somekey")

	assert.Error(t, err)
	assert.EqualError(t, err, "account is deleted")
	assert.Nil(t, acc)
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	err := service.DeleteAPIKey("somekey")

	assert.NoError(t, err)
}

func Test_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["DeleteAPIKey"] = errors.New("DeleteAPIKey error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	err := service.DeleteAPIKey("somekey")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to delete API key")
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	err := service.AddAccountRole(uuid.New(), "admin")

	assert.NoError(t, err)
}

func Test_AddAccountRole_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	err := service.AddAccountRole(uuid.New(), "admin")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to add role to account")
}

func Test_DeleteAccountRole_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	err := service.DeleteAccountRole(uuid.New(), "admin")

	assert.NoError(t, err)
}

func Test_DeleteAccountRole_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["DeleteAccountRole"] = errors.New("DeleteAccountRole error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	err := service.DeleteAccountRole(uuid.New(), "admin")

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to delete role from account")
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	id1 := uuid.New()
	id2 := uuid.New()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		AccountRoles: []model.AccountRoles{
			{Id: id1, Name: "admin"},
			{Id: id2, Name: "user"},
		},
	})

	roles, err := service.FindRolesByAccount(uuid.New())

	assert.NoError(t, err)
	assert.Equal(t, roles, []model.AccountRoles{
		{Id: id1, Name: "admin"},
		{Id: id2, Name: "user"},
	})
}

func Test_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["FindRolesByAccount"] = errors.New("FindRolesByAccount error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		AccountRoles: []model.AccountRoles{
			{Id: uuid.New(), Name: "admin"},
			{Id: uuid.New(), Name: "user"},
		},
		Error: errMap,
	})

	roles, err := service.FindRolesByAccount(uuid.New())

	assert.Error(t, err)
	assert.EqualError(t, err, "failed to find roles")
	assert.Nil(t, roles)
}

func Test_UpdateRoles_Success(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	accountID := uuid.New()
	rolesMap := map[string]interface{}{
		"role_" + accountID.String() + "_admin": "true",
		"role_" + accountID.String() + "_user":  "false",
		"bad_key_format":                        "true",
	}

	err := service.UpdateRoles(rolesMap)

	assert.NoError(t, err)
}

func Test_UpdateRoles_KeyFormatError(t *testing.T) {
	clearMock()

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{})

	accountID := uuid.New()
	rolesMap := map[string]interface{}{
		"role_" + accountID.String() + "_admin": "true",
		"role_" + accountID.String() + "_user":  "false",
		"bad_keyFormat":                         "true",
	}

	err := service.UpdateRoles(rolesMap)

	assert.NoError(t, err)
}

func Test_UpdateRoles_AddAccountRoleError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["AddAccountRole"] = errors.New("AddAccountRole error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	accountID := uuid.New()
	rolesMap := map[string]interface{}{
		"role_" + accountID.String() + "_admin": "true",
		"role_" + accountID.String() + "_user":  "false",
		"bad_keyFormat":                         "true",
	}

	err := service.UpdateRoles(rolesMap)

	assert.NoError(t, err)
}

func Test_UpdateRoles_DeleteAccountRoleError(t *testing.T) {
	clearMock()

	errMap := make(map[string]error)
	errMap["DeleteAccountRole"] = errors.New("DeleteAccountRole error")

	mockRepo := postgres.NewAccountMock()
	mockRepo.SetMock(postgres.Mock{
		Error: errMap,
	})

	accountID := uuid.New()
	rolesMap := map[string]interface{}{
		"role_" + accountID.String() + "_admin": "true",
		"role_" + accountID.String() + "_user":  "false",
		"bad_keyFormat":                         "true",
	}

	err := service.UpdateRoles(rolesMap)

	assert.NoError(t, err)
}
