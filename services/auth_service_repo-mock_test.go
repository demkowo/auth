package service

import (
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
	mock Mock
}

type Mock struct {
	Error        map[string]error
	Accounts     []*model.Account
	Account      *model.Account
	ApiKey       *model.APIKey
	AccountRoles []model.AccountRole
}

func NewRepoMock() *repoMock {
	return am
}

func (r *repoMock) AddMock(mock Mock) {
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

func (r *repoMock) DeleteAPIKey(key string) *resp.Err {
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

func (r *repoMock) DeleteAccountRole(accountId uuid.UUID, role string) *resp.Err {
	if r.mock.Error["DeleteAccountRole"] != nil {
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{r.mock.Error["DeleteAccountRole"].Error()})
	}
	return nil
}

func (r *repoMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	if r.mock.Error["FindRolesByAccount"] != nil {
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{r.mock.Error["FindRolesByAccount"].Error()})
	}
	return r.mock.AccountRoles, nil
}
