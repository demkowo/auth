package service

import (
	"errors"
	"log"
	"net/http"
	"time"

	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/resp"
	"github.com/google/uuid"
)

var (
	am = &accountMock{}
)

type accountMock struct {
	mock Mock
}

type Mock struct {
	Error        map[string]error
	Accounts     []*model.Account
	Account      *model.Account
	ApiKey       *model.APIKey
	AccountRoles []model.AccountRole
	Roles        *model.AccountRole
	Token        string
}

func NewAccountMock() *accountMock {
	return am
}

func (r *accountMock) SetMock(mock Mock) {
	r.mock = mock
}

func (s *accountMock) Add(acc *model.Account) (*model.Account, *resp.Err) {
	if s.mock.Error["Add"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{s.mock.Error["Add"].Error()})
	}

	return acc, nil
}

func (s *accountMock) AddJWTToken(acc *model.Account) (string, *resp.Err) {
	if s.mock.Error["AddJWTToken"] != nil {
		return "", resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{s.mock.Error["AddJWTToken"].Error()})
	}

	return "validTokenString", nil
}

func (s *accountMock) Block(accountId uuid.UUID, until time.Time) (*model.Account, *resp.Err) {
	if s.mock.Error["Block"] != nil {
		log.Println(errors.New("Block error"))
		return nil, resp.Error(http.StatusInternalServerError, "failed to block account", []interface{}{s.mock.Error["Block"].Error()})
	}

	return s.mock.Account, nil
}

func (s *accountMock) CheckAccess(accountId uuid.UUID) *resp.Err {
	if s.mock.Error["CheckAccess"] != nil {
		log.Println(errors.New("CheckAccess error"))
		return resp.Error(http.StatusInternalServerError, "failed to check access to account", []interface{}{s.mock.Error["CheckAccess"].Error()})
	}

	return nil
}

func (s *accountMock) Delete(accountId uuid.UUID) *resp.Err {
	if s.mock.Error["Delete"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{s.mock.Error["Delete"].Error()})
	}
	return nil
}

func (s *accountMock) Find() ([]*model.Account, *resp.Err) {
	if s.mock.Error["Find"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{s.mock.Error["Find"].Error()})
	}
	return s.mock.Accounts, nil
}

func (s *accountMock) GetByEmail(email string) (*model.Account, *resp.Err) {
	if s.mock.Error["GetByEmail"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{s.mock.Error["GetByEmail"].Error()})
	}
	return s.mock.Account, nil
}

func (s *accountMock) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
	if s.mock.Error["GetById"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{s.mock.Error["GetById"].Error()})
	}
	return s.mock.Account, nil
}

func (s *accountMock) Login(email, password string) (string, *resp.Err) {
	if s.mock.Error["Login"] != nil {
		return "", resp.Error(http.StatusUnauthorized, "login failed", []interface{}{s.mock.Error["Login"].Error()})
	}
	return s.mock.Token, nil
}

func (s *accountMock) RefreshToken(refreshToken string) (string, *resp.Err) {
	if s.mock.Error["RefreshToken"] != nil {
		return "", resp.Error(http.StatusUnauthorized, "refresh token failed", []interface{}{s.mock.Error["RefreshToken"].Error()})
	}
	return s.mock.Token, nil
}

func (s *accountMock) Unblock(accountId uuid.UUID) (*model.Account, *resp.Err) {
	if s.mock.Error["Unblock"] != nil {
		log.Println(errors.New("Unblock error"))
		return nil, resp.Error(http.StatusInternalServerError, "failed to unblock account", []interface{}{s.mock.Error["Unblock"].Error()})
	}

	return s.mock.Account, nil
}

func (s *accountMock) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) *resp.Err {
	if s.mock.Error["UpdatePassword"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{s.mock.Error["UpdatePassword"].Error()})
	}
	return nil
}

func (s *accountMock) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (*model.APIKey, *resp.Err) {
	if s.mock.Error["AddAPIKey"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{s.mock.Error["AddAPIKey"].Error()})
	}

	return s.mock.ApiKey, nil
}

func (s *accountMock) AuthenticateByAPIKey(apiKey string) (*model.Account, *resp.Err) {
	if s.mock.Error["AuthenticateByAPIKey"] != nil {
		return nil, resp.Error(http.StatusUnauthorized, "failed to authenticate with API key", []interface{}{s.mock.Error["AuthenticateByAPIKey"].Error()})
	}
	return s.mock.Account, nil
}

func (s *accountMock) DeleteAPIKey(apiKey string) *resp.Err {
	if s.mock.Error["DeleteAPIKey"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{s.mock.Error["DeleteAPIKey"].Error()})
	}
	return nil
}

func (s *accountMock) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	if s.mock.Error["AddAccountRole"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{s.mock.Error["AddAccountRole"].Error()})
	}

	return s.mock.Roles, nil
}

func (s *accountMock) DeleteAccountRole(accountId uuid.UUID, role string) *resp.Err {
	if s.mock.Error["DeleteAccountRole"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{s.mock.Error["DeleteAccountRole"].Error()})
	}
	return nil
}

func (s *accountMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	if s.mock.Error["FindRolesByAccount"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{s.mock.Error["FindRolesByAccount"].Error()})
	}

	return s.mock.AccountRoles, nil
}

func (s *accountMock) UpdateRoles(roles map[string]interface{}) *resp.Err {
	if s.mock.Error["UpdateRoles"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to update roles", []interface{}{s.mock.Error["UpdateRoles"].Error()})
	}
	return nil
}
