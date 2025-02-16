package mocks

import (
	"database/sql"
	"errors"
	"log"
	"net/http"

	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/resp"
	"github.com/google/uuid"
)

var (
	am = &repoMock{}
)

type repoMock struct {
	mock Repo
}

type Repo struct {
	Error        map[string]error
	Accounts     []*model.Account
	Account      *model.Account
	ApiKey       *model.APIKey
	AccountRoles []model.AccountRole
	OAuth2Token  *model.OAuth2Token
}

func NewRepoMock() *repoMock {
	return am
}

func (r *repoMock) AddMock(mock Repo) {
	r.mock = mock
}

func (r *repoMock) CreateTables() error {
	if r.mock.Error["CreateTables"] != nil {
		return r.mock.Error["CreateTables"]
	}

	return nil
}

func (r *repoMock) Add(acc *model.Account) (*model.Account, *resp.Err) {
	if r.mock.Error["Add"] != nil {
		log.Println(errors.New("Add error"))
		return nil, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{r.mock.Error["Add"].Error()})
	}
	return acc, nil
}

func (r *repoMock) Delete(accountId uuid.UUID) *resp.Err {
	if r.mock.Error["Delete"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{r.mock.Error["Delete"].Error()})
	}
	return nil
}

func (r *repoMock) Find() ([]*model.Account, *resp.Err) {
	if r.mock.Error["Find"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{r.mock.Error["Find"].Error()})
	}
	return r.mock.Accounts, nil
}

func (r *repoMock) GetByEmail(email string) (*model.Account, *resp.Err) {
	if r.mock.Error["GetByEmail"] != nil {
		if r.mock.Error["GetByEmail"] == sql.ErrNoRows {
			return nil, resp.Error(http.StatusInternalServerError, "account not found", []interface{}{sql.ErrNoRows})
		}
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{r.mock.Error["GetByEmail"].Error()})
	}
	return r.mock.Account, nil
}

func (r *repoMock) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
	if r.mock.Error["GetById"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{r.mock.Error["GetById"].Error()})
	}
	return r.mock.Account, nil
}

func (r *repoMock) Update(acc *model.Account) (*model.Account, *resp.Err) {
	if r.mock.Error["Update"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{r.mock.Error["Update"].Error()})
	}
	return acc, nil
}

func (r *repoMock) UpdatePassword(accountId uuid.UUID, newPassword string) *resp.Err {
	if r.mock.Error["UpdatePassword"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{r.mock.Error["UpdatePassword"].Error()})
	}
	return nil
}

func (r *repoMock) AddAPIKey(apiKey *model.APIKey) (*model.APIKey, *resp.Err) {
	if r.mock.Error["AddAPIKey"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{r.mock.Error["AddAPIKey"].Error()})
	}
	return apiKey, nil
}

func (r *repoMock) DeleteAPIKey(id uuid.UUID) *resp.Err {
	if r.mock.Error["DeleteAPIKey"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{r.mock.Error["DeleteAPIKey"].Error()})
	}
	return nil
}

func (r *repoMock) GetAPIKeyById(id uuid.UUID) (*model.APIKey, *resp.Err) {
	if r.mock.Error["GetAPIKeyById"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{r.mock.Error["GetAPIKeyById"].Error()})
	}

	return r.mock.ApiKey, nil
}

func (r *repoMock) GetAPIKeyByKey(key string) (*model.APIKey, *resp.Err) {
	if r.mock.Error["GetAPIKeyByKey"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{r.mock.Error["GetAPIKeyByKey"].Error()})
	}

	return r.mock.ApiKey, nil
}

func (r *repoMock) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	if r.mock.Error["AddAccountRole"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{r.mock.Error["AddAccountRole"].Error()})
	}

	return &model.AccountRole{Id: accountId, Name: role}, nil
}

func (r *repoMock) DeleteAccountRoleById(accountId uuid.UUID) *resp.Err {
	if r.mock.Error["DeleteAccountRoleById"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{r.mock.Error["DeleteAccountRoleById"].Error()})
	}
	return nil
}

func (r *repoMock) DeleteAccountRoleByName(role string) *resp.Err {
	if r.mock.Error["DeleteAccountRoleByName"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{r.mock.Error["DeleteAccountRoleByName"].Error()})
	}
	return nil
}

func (r *repoMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	if r.mock.Error["FindRolesByAccount"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{r.mock.Error["FindRolesByAccount"].Error()})
	}
	return r.mock.AccountRoles, nil
}

func (r *repoMock) AddOAuth2Token(accountId string, token *model.OAuth2Token) *resp.Err {
	if r.mock.Error["AddOAuth2Token"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to add OAuth2 token", []interface{}{r.mock.Error["AddOAuth2Token"].Error()})
	}
	return nil
}

func (r *repoMock) GetOAuth2TokenByaccountId(accountId string) (*model.OAuth2Token, *resp.Err) {
	if r.mock.Error["GetOAuth2TokenByaccountId"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to get OAuth2 token", []interface{}{r.mock.Error["GetOAuth2TokenByaccountId"].Error()})
	}
	return r.mock.OAuth2Token, nil
}

func (r *repoMock) DeleteOAuth2Token(accountId string) *resp.Err {
	if r.mock.Error["DeleteOAuth2Token"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{r.mock.Error["DeleteOAuth2Token"].Error()})
	}
	return nil
}
