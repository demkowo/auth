package mocks

import (
	"errors"
	"log"
	"net/http"
	"time"

	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/resp"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

var (
	sm = &serviceMock{}
)

type serviceMock struct {
	mock Service
}

type Service struct {
	Error        map[string]error
	Accounts     []*model.Account
	Account      *model.Account
	ApiKey       *model.APIKey
	AccountRoles []model.AccountRole
	Roles        *model.AccountRole
	Token        string
	OAuth2Token  *oauth2.Token
	OAuth2Config *oauth2.Config
}

func NewServiceMock() *serviceMock {
	return sm
}

func (r *serviceMock) AddMock(mock Service) {
	r.mock = mock
}

func (s *serviceMock) Add(acc *model.Account) (*model.Account, *resp.Err) {
	if s.mock.Error["Add"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{s.mock.Error["Add"].Error()})
	}

	return acc, nil
}

func (s *serviceMock) AddJWTToken(acc *model.Account) (string, *resp.Err) {
	if s.mock.Error["AddJWTToken"] != nil {
		return "", resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{s.mock.Error["AddJWTToken"].Error()})
	}

	return "validTokenString", nil
}

func (s *serviceMock) Block(accountId uuid.UUID, until time.Time) (*model.Account, *resp.Err) {
	if s.mock.Error["Block"] != nil {
		log.Println(errors.New("Block error"))
		return nil, resp.Error(http.StatusInternalServerError, "failed to block account", []interface{}{s.mock.Error["Block"].Error()})
	}

	return s.mock.Account, nil
}

func (s *serviceMock) CheckAccess(accountId uuid.UUID) *resp.Err {
	if s.mock.Error["CheckAccess"] != nil {
		log.Println(errors.New("CheckAccess error"))
		return resp.Error(http.StatusInternalServerError, "failed to check access to account", []interface{}{s.mock.Error["CheckAccess"].Error()})
	}

	return nil
}

func (s *serviceMock) Delete(accountId uuid.UUID) *resp.Err {
	if s.mock.Error["Delete"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{s.mock.Error["Delete"].Error()})
	}
	return nil
}

func (s *serviceMock) Find() ([]*model.Account, *resp.Err) {
	if s.mock.Error["Find"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{s.mock.Error["Find"].Error()})
	}
	return s.mock.Accounts, nil
}

func (s *serviceMock) GetByEmail(email string) (*model.Account, *resp.Err) {
	if s.mock.Error["GetByEmail"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{s.mock.Error["GetByEmail"].Error()})
	}
	return s.mock.Account, nil
}

func (s *serviceMock) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
	if s.mock.Error["GetById"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{s.mock.Error["GetById"].Error()})
	}
	return s.mock.Account, nil
}

func (s *serviceMock) Login(email, password string) (string, *resp.Err) {
	if s.mock.Error["Login"] != nil {
		return "", resp.Error(http.StatusUnauthorized, "login failed", []interface{}{s.mock.Error["Login"].Error()})
	}
	return s.mock.Token, nil
}

func (s *serviceMock) RefreshToken(refreshToken string) (string, *resp.Err) {
	if s.mock.Error["RefreshToken"] != nil {
		return "", resp.Error(http.StatusUnauthorized, "refresh token failed", []interface{}{s.mock.Error["RefreshToken"].Error()})
	}
	return s.mock.Token, nil
}

func (s *serviceMock) Unblock(accountId uuid.UUID) (*model.Account, *resp.Err) {
	if s.mock.Error["Unblock"] != nil {
		log.Println(errors.New("Unblock error"))
		return nil, resp.Error(http.StatusInternalServerError, "failed to unblock account", []interface{}{s.mock.Error["Unblock"].Error()})
	}

	return s.mock.Account, nil
}

func (s *serviceMock) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) *resp.Err {
	if s.mock.Error["UpdatePassword"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{s.mock.Error["UpdatePassword"].Error()})
	}
	return nil
}

func (s *serviceMock) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (*model.APIKey, *resp.Err) {
	if s.mock.Error["AddAPIKey"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{s.mock.Error["AddAPIKey"].Error()})
	}

	return s.mock.ApiKey, nil
}

func (s *serviceMock) AuthenticateByAPIKey(apiKey string) (*model.Account, *resp.Err) {
	if s.mock.Error["AuthenticateByAPIKey"] != nil {
		return nil, resp.Error(http.StatusUnauthorized, "failed to authenticate with API key", []interface{}{s.mock.Error["AuthenticateByAPIKey"].Error()})
	}
	return s.mock.Account, nil
}

func (s *serviceMock) DeleteAPIKey(id uuid.UUID) *resp.Err {
	if s.mock.Error["DeleteAPIKey"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{s.mock.Error["DeleteAPIKey"].Error()})
	}
	return nil
}

func (s *serviceMock) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	if s.mock.Error["AddAccountRole"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{s.mock.Error["AddAccountRole"].Error()})
	}

	return s.mock.Roles, nil
}

func (s *serviceMock) DeleteAccountRoleById(accountId uuid.UUID) *resp.Err {
	if s.mock.Error["DeleteAccountRoleById"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{s.mock.Error["DeleteAccountRoleById"].Error()})
	}
	return nil
}

func (s *serviceMock) DeleteAccountRoleByName(role string) *resp.Err {
	if s.mock.Error["DeleteAccountRoleByName"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{s.mock.Error["DeleteAccountRoleByName"].Error()})
	}
	return nil
}

func (s *serviceMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	if s.mock.Error["FindRolesByAccount"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{s.mock.Error["FindRolesByAccount"].Error()})
	}

	return s.mock.AccountRoles, nil
}

func (s *serviceMock) UpdateRoles(roles map[string]interface{}) *resp.Err {
	if s.mock.Error["UpdateRoles"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to update roles", []interface{}{s.mock.Error["UpdateRoles"].Error()})
	}
	return nil
}

func (s *serviceMock) ExchangeCodeForToken(provider string, code string) (*oauth2.Token, *resp.Err) {
	if s.mock.Error["ExchangeCodeForToken"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to exchange code for token", []interface{}{s.mock.Error["ExchangeCodeForToken"].Error()})
	}
	return s.mock.OAuth2Token, nil
}
func (s *serviceMock) GetAccountByID(id string) (*model.Account, *resp.Err) {
	if s.mock.Error["GetAccountByID"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account by id", []interface{}{s.mock.Error["GetAccountByID"].Error()})
	}
	return s.mock.Account, nil
}
func (s *serviceMock) GetAccountInfo(provider string, token *oauth2.Token) (*model.Account, *resp.Err) {
	if s.mock.Error["GetAccountInfo"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account info", []interface{}{s.mock.Error["GetAccountInfo"].Error()})
	}
	return s.mock.Account, nil
}
func (s *serviceMock) GetOAuthConfig(provider string) (*oauth2.Config, *resp.Err) {
	if s.mock.Error["GetOAuthConfig"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get OAuth2 config", []interface{}{s.mock.Error["GetOAuthConfig"].Error()})
	}

	config := &oauth2.Config{
		ClientID:     "mock-client-id",
		ClientSecret: "mock-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://mockprovider.com/auth",
			TokenURL: "https://mockprovider.com/token",
		},
	}

	return config, nil
}
func (s *serviceMock) Logout(accountId string) *resp.Err {
	if s.mock.Error["Logout"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to logout", []interface{}{s.mock.Error["Logout"].Error()})
	}
	return nil
}
func (s *serviceMock) StoreAccount(account *model.Account) *resp.Err {
	if s.mock.Error["StoreAccount"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to store account", []interface{}{s.mock.Error["StoreAccount"].Error()})
	}
	return nil
}
func (s *serviceMock) UpdateLastLogin(accountId string) {}
