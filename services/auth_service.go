package service

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/demkowo/auth/config"
	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/helper"
	"github.com/demkowo/utils/resp"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	conf = config.Values.Get()
	help helper.Helper
)

type AccountRepo interface {
	Add(*model.Account) (*model.Account, *resp.Err)
	Delete(uuid.UUID) *resp.Err
	Find() ([]*model.Account, *resp.Err)
	GetByEmail(string) (*model.Account, *resp.Err)
	GetById(uuid.UUID) (*model.Account, *resp.Err)
	Update(*model.Account) (*model.Account, *resp.Err)
	UpdatePassword(uuid.UUID, string) *resp.Err

	AddAPIKey(*model.APIKey) (*model.APIKey, *resp.Err)
	DeleteAPIKey(string) *resp.Err
	GetAPIKeyById(uuid.UUID) (*model.APIKey, *resp.Err)
	GetAPIKeyByKey(string) (*model.APIKey, *resp.Err)

	AddAccountRole(uuid.UUID, string) (*model.AccountRole, *resp.Err)
	DeleteAccountRole(uuid.UUID, string) *resp.Err
	FindRolesByAccount(uuid.UUID) ([]model.AccountRole, *resp.Err)
}

type Account interface {
	Add(*model.Account) (*model.Account, *resp.Err)
	AddJWTToken(*model.Account) (string, *resp.Err)
	Block(uuid.UUID, time.Time) (*model.Account, *resp.Err)
	CheckAccess(uuid.UUID) *resp.Err
	Delete(uuid.UUID) *resp.Err
	Find() ([]*model.Account, *resp.Err)
	GetByEmail(string) (*model.Account, *resp.Err)
	GetById(uuid.UUID) (*model.Account, *resp.Err)
	Login(email, password string) (string, *resp.Err)
	RefreshToken(refreshToken string) (string, *resp.Err)
	Unblock(uuid.UUID) (*model.Account, *resp.Err)
	UpdatePassword(uuid.UUID, string, string) *resp.Err

	AddAPIKey(uuid.UUID, time.Time) (*model.APIKey, *resp.Err)
	AuthenticateByAPIKey(string) (*model.Account, *resp.Err)
	DeleteAPIKey(string) *resp.Err

	AddAccountRole(uuid.UUID, string) (*model.AccountRole, *resp.Err)
	DeleteAccountRole(uuid.UUID, string) *resp.Err
	FindRolesByAccount(uuid.UUID) ([]model.AccountRole, *resp.Err)
	UpdateRoles(map[string]interface{}) *resp.Err
}

type account struct {
	repo AccountRepo
}

func NewAccount(repo AccountRepo) Account {
	return &account{repo: repo}
}

func (s *account) Add(acc *model.Account) (*model.Account, *resp.Err) {
	if _, err := s.repo.GetByEmail(acc.Email); err != nil {
		return nil, err
	}

	hashedPassword, err := help.HashPassword(acc.Password)
	if err != nil {
		return nil, err
	}

	acc.Password = hashedPassword
	acc.Id = uuid.New()
	now := time.Now()
	acc.Created = now
	acc.Updated = now
	acc.Blocked = time.Time{}
	acc.Deleted = false

	account, err := s.repo.Add(acc)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (s *account) AddJWTToken(acc *model.Account) (string, *resp.Err) {
	if acc == nil {
		return "", resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"*model.Account can't be nil"})
	}

	roleNames := make([]string, len(acc.Roles))
	for i, role := range acc.Roles {
		roleNames[i] = role.Name
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"id":       acc.Id.String(),
		"nickname": acc.Nickname,
		"exp":      expirationTime.Unix(),
		"roles":    roleNames,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := help.TokenSignedString(token, conf.JWTSecret)
	if err != nil {
		log.Println("failed to sign JWT token:", err)
		return "", resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{err.Error()})
	}
	return tokenString, nil
}

func (s *account) Block(accountId uuid.UUID, until time.Time) (*model.Account, *resp.Err) {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return nil, err
	}
	acc.Blocked = until
	acc.Updated = time.Now()

	account, err := s.repo.Update(acc)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (s *account) CheckAccess(accountId uuid.UUID) *resp.Err {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	if acc.Deleted {
		log.Println("account is deleted")
		return resp.Error(http.StatusInternalServerError, "account is deleted", []interface{}{})
	}

	if !acc.Blocked.IsZero() && acc.Blocked.After(time.Now()) {
		return resp.Error(http.StatusInternalServerError, fmt.Sprintf("account is banned until %s", acc.Blocked.Format(time.RFC3339)), []interface{}{})
	}

	return nil
}

func (s *account) Delete(accountId uuid.UUID) *resp.Err {
	if err := s.repo.Delete(accountId); err != nil {
		return err
	}
	return nil
}

func (s *account) Find() ([]*model.Account, *resp.Err) {
	accounts, err := s.repo.Find()
	if err != nil {
		return nil, err
	}

	for _, acc := range accounts {
		acc.Password = ""
	}
	return accounts, nil
}

func (s *account) GetByEmail(email string) (*model.Account, *resp.Err) {
	acc, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (s *account) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
	acc, err := s.repo.GetById(id)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (s *account) Login(email, password string) (string, *resp.Err) {
	acc, err := s.repo.GetByEmail(email)
	if err != nil {
		return "", err
	}

	if err := s.CheckAccess(acc.Id); err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(password)); err != nil {
		log.Println("invalid credentials due to incorrect password")
		return "", resp.Error(http.StatusUnauthorized, "invalid credentials", []interface{}{err.Error()})
	}

	tokenString, e := s.AddJWTToken(acc)
	if e != nil {
		log.Println("failed to create token:", err)
		return "", e
	}
	return tokenString, nil
}

func (s *account) RefreshToken(refreshToken string) (string, *resp.Err) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return conf.JWTSecret, nil
	})
	if err != nil || !token.Valid {
		log.Println("invalid refresh token:", err)
		return "", resp.Error(http.StatusBadRequest, "failed to refresh token", []interface{}{err.Error()})
	}

	claims := token.Claims.(jwt.MapClaims)
	accountIdStr, ok := claims["id"].(string)
	if !ok {
		log.Println("invalid token 'id' field")
		return "", resp.Error(http.StatusBadRequest, "failed to refresh token", []interface{}{"invalid token id type"})
	}

	accountId, err := uuid.Parse(accountIdStr)
	if err != nil {
		log.Println("invalid account Id in token:", err)
		return "", resp.Error(http.StatusUnauthorized, "invalid account Id", []interface{}{err.Error()})
	}

	acc, e := s.repo.GetById(accountId)
	if e != nil {
		log.Println("failed to get account:", e)
		return "", e
	}

	if err := s.CheckAccess(accountId); err != nil {
		log.Println("access check failed:", err)
		return "", err
	}

	newTokenString, e := s.AddJWTToken(acc)
	if e != nil {
		log.Println("failed to create new token:", e)
		return "", e
	}
	return newTokenString, nil
}

func (s *account) Unblock(accountId uuid.UUID) (*model.Account, *resp.Err) {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return nil, err
	}

	acc.Blocked = time.Time{}
	acc.Updated = time.Now()

	account, err := s.repo.Update(acc)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (s *account) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) *resp.Err {
	acc, err := s.repo.GetById(accountId)

	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(oldPassword)); err != nil {
		return resp.Error(http.StatusInternalServerError, "invalid old password", []interface{}{err.Error()})
	}

	hashedPassword, err := help.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err := s.repo.UpdatePassword(accountId, hashedPassword); err != nil {
		return err
	}

	return nil
}

func (s *account) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (*model.APIKey, *resp.Err) {
	bytes, err := help.GetRandomBytes(32)
	if err != nil {
		return nil, err
	}

	key := hex.EncodeToString(bytes)

	apiKey := &model.APIKey{
		Id:        uuid.New(),
		Key:       key,
		AccountId: accountId,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	res, err := s.repo.AddAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s *account) AuthenticateByAPIKey(apiKey string) (*model.Account, *resp.Err) {
	apiKeyRecord, err := s.repo.GetAPIKeyByKey(apiKey)
	if err != nil {
		return nil, err
	}

	if !apiKeyRecord.ExpiresAt.IsZero() && time.Now().After(apiKeyRecord.ExpiresAt) {
		return nil, resp.Error(http.StatusUnauthorized, "API key expired", []interface{}{})
	}

	acc, err := s.repo.GetById(apiKeyRecord.AccountId)
	if err != nil {
		return nil, err
	}

	if err := s.CheckAccess(acc.Id); err != nil {
		return nil, err
	}
	return acc, nil
}

func (s *account) DeleteAPIKey(apiKey string) *resp.Err {
	if err := s.repo.DeleteAPIKey(apiKey); err != nil {
		return err
	}
	return nil
}

func (s *account) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	roles, err := s.repo.AddAccountRole(accountId, role)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *account) DeleteAccountRole(accountId uuid.UUID, role string) *resp.Err {
	if err := s.repo.DeleteAccountRole(accountId, role); err != nil {
		return err
	}
	return nil
}

func (s *account) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	roles, err := s.repo.FindRolesByAccount(accountId)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *account) UpdateRoles(roles map[string]interface{}) *resp.Err {
	var errs []string

	for key, val := range roles {
		keyParts := strings.Split(key, "_")
		if len(keyParts) != 3 {
			log.Println("invalid key format:", key)
			return resp.Error(http.StatusBadRequest, fmt.Sprintf("invalid key format: %s", keyParts), []interface{}{})
		}

		accountIdStr := keyParts[1]
		roleName := keyParts[2]

		accountId, err := uuid.Parse(accountIdStr)
		if err != nil {
			log.Printf("failed to parse account Id: %s", accountIdStr)
			errs = append(errs, fmt.Errorf("failed to parse account Id :%s", accountIdStr).Error())
		}

		valueStr := fmt.Sprint(val)
		if strings.EqualFold(valueStr, "true") {
			if _, err := s.repo.AddAccountRole(accountId, roleName); err != nil {
				log.Printf("failed to add role %s to account %s", roleName, accountId)
				errs = append(errs, fmt.Errorf("failed to add role %s to account", roleName).Error())
			}
		} else {
			if err := s.repo.DeleteAccountRole(accountId, roleName); err != nil {
				log.Printf("failed to delete role %s from account %s: %v", roleName, accountId, err)
				errs = append(errs, fmt.Errorf("failed to delete role %s from account", roleName).Error())
			}
		}
	}

	if len(errs) > 0 {
		return resp.Error(http.StatusBadRequest, "errors found while updating roles", []interface{}{errs})
	}

	return nil
}
