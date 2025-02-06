package service

import (
	"errors"
	"log"
	"time"

	model "github.com/demkowo/auth/models"
	"github.com/google/uuid"
)

var (
	am = &accountMock{}
)

type accountMock struct {
	mock Mock
}

type Mock struct {
	Error           map[string]error
	Accounts        []*model.Account
	Account         *model.Account
	ApiKey          *model.APIKey
	AccountRoles    []model.AccountRoles
	ExpectedAccount *model.Account
	Token           string
}

func NewAccountMock() *accountMock {
	return am
}

func (r *accountMock) SetMock(mock Mock) {
	r.mock = mock
}

func (s *accountMock) Add(acc *model.Account) error {
	if s.mock.Error["Add"] != nil {
		log.Println(errors.New("Add error"))
		return errors.New("failed to create account")
	}

	return nil
}

func (s *accountMock) Block(accountId uuid.UUID, until time.Time) error {
	if s.mock.Error["Block"] != nil {
		log.Println(errors.New("Block error"))
		return errors.New("failed to update account")
	}

	return nil
}

func (s *accountMock) CheckAccess(accountId uuid.UUID) error {
	if s.mock.Error["CheckAccess"] != nil {
		log.Println(errors.New("CheckAccess error"))
		return errors.New("unathorized")
	}

	return nil
}

func (s *accountMock) Delete(accountId uuid.UUID) error {
	if s.mock.Error["Delete"] != nil {
		return errors.New("failed to delete account")
	}
	return nil
}

func (s *accountMock) Find() ([]*model.Account, error) {
	if s.mock.Error["Find"] != nil {
		return nil, errors.New("failed to find accounts")
	}
	return s.mock.Accounts, nil
}

func (s *accountMock) GetByEmail(email string) (*model.Account, error) {
	if s.mock.Error["GetByEmail"] != nil {
		return nil, errors.New("failed to get account")
	}
	return s.mock.Account, nil
}

func (s *accountMock) GetById(id uuid.UUID) (*model.Account, error) {
	if s.mock.Error["GetById"] != nil {
		return nil, errors.New("failed to get account")
	}
	return s.mock.Account, nil
}

func (s *accountMock) Login(email, password string) (string, error) {
	if s.mock.Error["Login"] != nil {
		return "", errors.New("invalid credentials")
	}
	return s.mock.Token, nil
}

func (s *accountMock) RefreshToken(refreshToken string) (string, error) {
	if s.mock.Error["RefreshToken"] != nil {
		return "", errors.New("invalid credentials")
	}
	return s.mock.Token, nil
}

func (s *accountMock) Unblock(accountId uuid.UUID) error {
	if s.mock.Error["Unblock"] != nil {
		log.Println(errors.New("Unblock error"))
		return errors.New("failed to unblock account")
	}

	return nil
}

func (s *accountMock) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) error {
	if s.mock.Error["UpdatePassword"] != nil {
		return errors.New("failed to change password")
	}
	return nil
}

func (s *accountMock) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (string, error) {
	if s.mock.Error["AddAPIKey"] != nil {
		return "", errors.New("failed to create API key")
	}

	return s.mock.ApiKey.Key, nil
}

func (s *accountMock) AuthenticateByAPIKey(apiKey string) (*model.Account, error) {
	if s.mock.Error["AuthenticateByAPIKey"] != nil {
		return nil, errors.New("failed to authenticate with this API key")
	}
	return s.mock.Account, nil
}

func (s *accountMock) DeleteAPIKey(apiKey string) error {
	if s.mock.Error["DeleteAPIKey"] != nil {
		return errors.New("failed to delete API key")
	}
	return nil
}

func (s *accountMock) AddAccountRole(accountId uuid.UUID, role string) error {
	if s.mock.Error["AddAccountRole"] != nil {
		return errors.New("failed to add role to account")
	}
	return nil
}

func (s *accountMock) DeleteAccountRole(accountId uuid.UUID, role string) error {
	if s.mock.Error["DeleteAccountRole"] != nil {
		return errors.New("failed to delete role from account")
	}
	return nil
}

func (s *accountMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRoles, error) {
	if s.mock.Error["FindRolesByAccount"] != nil {
		return nil, errors.New("failed to find roles")
	}

	return s.mock.AccountRoles, nil
}

func (s *accountMock) UpdateRoles(roles map[string]interface{}) error {
	if s.mock.Error["UpdateRoles"] != nil {
		return errors.New("failed to update roles")
	}
	return nil
}
