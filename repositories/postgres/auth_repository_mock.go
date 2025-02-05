package postgres

import (
	"errors"
	"fmt"
	"log"
	"reflect"
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
}

func NewAccountMock() *accountMock {
	return am
}

func (r *accountMock) SetMock(mock Mock) {
	r.mock = mock
}

func (r *accountMock) Add(acc *model.Account) error {
	compareAccounts(r.mock.ExpectedAccount, acc)

	if r.mock.Error["Add"] != nil {
		log.Println(errors.New("Add error"))
		return errors.New("failed to create account")
	}

	return nil
}

func (r *accountMock) Delete(accountId uuid.UUID) error {
	if r.mock.Error["Delete"] != nil {
		return errors.New("failed to delete account")
	}
	return nil
}

func (r *accountMock) Find() ([]*model.Account, error) {
	if r.mock.Error["Find"] != nil {
		return nil, errors.New("failed to find accounts")
	}
	return r.mock.Accounts, nil
}

func (r *accountMock) GetByEmail(email string) (*model.Account, error) {
	if r.mock.Error["GetByEmail"] != nil {
		return nil, errors.New("failed to get account")
	}
	return r.mock.Account, nil
}

func (r *accountMock) GetById(id uuid.UUID) (*model.Account, error) {
	if r.mock.Error["GetById"] != nil {
		return nil, errors.New("failed to get account")
	}
	return r.mock.Account, nil
}

func (r *accountMock) Update(acc *model.Account) error {
	compareAccounts(r.mock.ExpectedAccount, acc)
	if r.mock.Error["Update"] != nil {
		return errors.New("failed to update account")
	}
	return nil
}

func (r *accountMock) UpdatePassword(accountId uuid.UUID, newPassword string) error {
	if r.mock.Error["UpdatePassword"] != nil {
		return errors.New("failed to change password")
	}
	return nil
}

func (r *accountMock) AddAPIKey(apiKey *model.APIKey) error {
	if r.mock.Error["AddAPIKey"] != nil {
		return errors.New("failed to create API key")
	}
	return nil
}

func (r *accountMock) DeleteAPIKey(key string) error {
	if r.mock.Error["DeleteAPIKey"] != nil {
		return errors.New("failed to delete API key")
	}
	return nil
}

func (r *accountMock) GetAPIKeyById(id uuid.UUID) (*model.APIKey, error) {
	if r.mock.Error["GetAPIKeyById"] != nil {
		return nil, errors.New("failed to get API Key")
	}
	return r.mock.ApiKey, nil
}

func (r *accountMock) GetAPIKeyByKey(key string) (*model.APIKey, error) {
	if r.mock.Error["GetAPIKeyByKey"] != nil {
		return nil, errors.New("failed to get API Key")
	}
	return r.mock.ApiKey, nil
}

func (r *accountMock) AddAccountRole(accountId uuid.UUID, role string) error {
	if r.mock.Error["AddAccountRole"] != nil {
		return errors.New("failed to add role to account")
	}
	return nil
}

func (r *accountMock) DeleteAccountRole(accountId uuid.UUID, role string) error {
	if r.mock.Error["DeleteAccountRole"] != nil {
		return errors.New("failed to delete role from account")
	}
	return nil
}

func (r *accountMock) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRoles, error) {
	if r.mock.Error["FindRolesByAccount"] != nil {
		return nil, errors.New("failed to find roles")
	}
	return r.mock.AccountRoles, nil
}

func compareAccounts(expected, received *model.Account) {
	if expected == nil || received == nil {
		return
	}

	differences := make(map[string]string)

	vExpected := reflect.ValueOf(expected).Elem()
	vReceived := reflect.ValueOf(received).Elem()
	tExpected := vExpected.Type()

	for i := 0; i < vExpected.NumField(); i++ {
		fieldName := tExpected.Field(i).Name
		eVal := vExpected.Field(i).Interface()
		rVal := vReceived.Field(i).Interface()

		switch fieldName {
		case "Id":
			if expected.Id == uuid.Nil && received.Id == uuid.Nil {
				differences[fieldName] = "Expected a non-empty UUID, but got empty"
			} else if expected.Id != uuid.Nil && received.Id != uuid.Nil && expected.Id != received.Id {
				differences[fieldName] = fmt.Sprintf("Expected %v, got %v", expected.Id, received.Id)
			}
		case "Created", "Updated", "Blocked":
			eTime := eVal.(time.Time)
			rTime := rVal.(time.Time)
			delta := time.Second
			if rTime.Before(eTime.Add(-delta)) || rTime.After(eTime.Add(delta)) {
				differences[fieldName] = fmt.Sprintf("Expected ~%v, got %v", eTime, rTime)
			}

		case "Roles":
			eRoles := eVal.([]model.AccountRoles)
			rRoles := rVal.([]model.AccountRoles)
			if len(eRoles) != len(rRoles) {
				differences[fieldName] = fmt.Sprintf("Expected %d roles, got %d", len(eRoles), len(rRoles))
			} else {
				for j := range eRoles {
					if eRoles[j].Id != uuid.Nil && rRoles[j].Id != uuid.Nil && eRoles[j].Id != rRoles[j].Id {
						differences[fmt.Sprintf("Roles[%d].Id", j)] = fmt.Sprintf("Expected %v, got %v", eRoles[j].Id, rRoles[j].Id)
					}
					if eRoles[j].Name != rRoles[j].Name {
						differences[fmt.Sprintf("Roles[%d].Name", j)] = fmt.Sprintf("Expected %v, got %v", eRoles[j].Name, rRoles[j].Name)
					}
				}
			}
		case "APIKeys":
			eKeys := eVal.([]model.APIKey)
			rKeys := rVal.([]model.APIKey)
			if len(eKeys) != len(rKeys) {
				differences[fieldName] = fmt.Sprintf("Expected %d API keys, got %d", len(eKeys), len(rKeys))
			} else {
				for j := range eKeys {
					if eKeys[j].Id != uuid.Nil && rKeys[j].Id != uuid.Nil && eKeys[j].Id != rKeys[j].Id {
						differences[fmt.Sprintf("APIKeys[%d].Id", j)] = fmt.Sprintf("Expected %v, got %v", eKeys[j].Id, rKeys[j].Id)
					}
					if eKeys[j].Key != rKeys[j].Key {
						differences[fmt.Sprintf("APIKeys[%d].Key", j)] = fmt.Sprintf("Expected %v, got %v", eKeys[j].Key, rKeys[j].Key)
					}
				}
			}
		case "Password":
			if rVal.(string) != eVal.(string) {
				log.Println("Invalid password")
				differences[fieldName] = fmt.Sprintf("Expected %v, got %v", eVal.(string), rVal.(string))
			}

		default:
			if eVal != rVal {
				differences[fieldName] = fmt.Sprintf("Expected %v, got %v", eVal, rVal)
			}
		}
	}

	if len(differences) > 0 {
		for k, v := range differences {
			fmt.Printf("%s: %s\n", k, v)
		}
		log.Fatalf("Differences found while comparing accounts: %#v\n", differences)
	}
}
