package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/demkowo/auth/config"
	model "github.com/demkowo/auth/models"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var conf = config.Values.Get()

type AccountRepo interface {
	Add(*model.Account) error
	Delete(uuid.UUID) error
	Find() ([]*model.Account, error)
	GetByEmail(string) (*model.Account, error)
	GetById(uuid.UUID) (*model.Account, error)
	Update(*model.Account) error
	UpdatePassword(uuid.UUID, string) error

	AddAPIKey(*model.APIKey) error
	DeleteAPIKey(string) error
	GetAPIKeyById(uuid.UUID) (*model.APIKey, error)
	GetAPIKeyByKey(string) (*model.APIKey, error)

	AddAccountRole(uuid.UUID, string) error
	DeleteAccountRole(uuid.UUID, string) error
	FindRolesByAccount(uuid.UUID) ([]model.AccountRoles, error)
}

type Account interface {
	Add(*model.Account) error
	Block(uuid.UUID, time.Time) error
	CheckAccess(uuid.UUID) error
	Delete(uuid.UUID) error
	Find() ([]*model.Account, error)
	GetByEmail(string) (*model.Account, error)
	GetById(uuid.UUID) (*model.Account, error)
	Login(email, password string) (string, error)
	RefreshToken(refreshToken string) (string, error)
	Unblock(uuid.UUID) error
	UpdatePassword(uuid.UUID, string, string) error

	AddAPIKey(uuid.UUID, time.Time) (string, error)
	AuthenticateByAPIKey(string) (*model.Account, error)
	DeleteAPIKey(string) error

	AddAccountRole(uuid.UUID, string) error
	DeleteAccountRole(uuid.UUID, string) error
	FindRolesByAccount(uuid.UUID) ([]model.AccountRoles, error)
	UpdateRoles(map[string]interface{}) error
}

type account struct {
	repo AccountRepo
}

func NewAccount(repo AccountRepo) Account {
	return &account{repo: repo}
}

func (s *account) Add(acc *model.Account) error {
	if _, err := s.repo.GetByEmail(acc.Email); err == nil {
		return errors.New("an account with this email already exists")
	}

	hashedPassword, err := hashPassword(acc.Password)
	if err != nil {
		return errors.New("failed to create an account")
	}

	acc.Password = hashedPassword
	acc.Id = uuid.New()
	now := time.Now()
	acc.Created = now
	acc.Updated = now
	acc.Blocked = time.Time{}
	acc.Deleted = false

	if err := s.repo.Add(acc); err != nil {
		return err
	}
	return nil
}

func (s *account) Block(accountId uuid.UUID, until time.Time) error {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	acc.Blocked = until
	acc.Updated = time.Now()

	if err := s.repo.Update(acc); err != nil {
		return err
	}
	return nil
}

func (s *account) CheckAccess(accountId uuid.UUID) error {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	if acc.Deleted {
		log.Println("account is deleted")
		return errors.New("account is deleted")
	}

	if !acc.Blocked.IsZero() && acc.Blocked.After(time.Now()) {
		return fmt.Errorf("account is banned until %s", acc.Blocked.Format(time.RFC3339))
	}

	return nil
}

func (s *account) Delete(accountId uuid.UUID) error {
	if err := s.repo.Delete(accountId); err != nil {
		return err
	}
	return nil
}

func (s *account) Find() ([]*model.Account, error) {
	accounts, err := s.repo.Find()
	if err != nil {
		return nil, err
	}

	for _, acc := range accounts {
		acc.Password = ""
	}
	return accounts, nil
}

func (s *account) GetByEmail(email string) (*model.Account, error) {
	acc, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (s *account) GetById(id uuid.UUID) (*model.Account, error) {
	acc, err := s.repo.GetById(id)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (s *account) Login(email, password string) (string, error) {
	acc, err := s.repo.GetByEmail(email)
	if err != nil {
		return "", errors.New("invalid credentials")
	}

	if err := s.CheckAccess(acc.Id); err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(password)); err != nil {
		log.Println("invalid credentials due to incorrect password")
		return "", errors.New("invalid credentials")
	}

	tokenString, err := s.addJWTToken(acc)
	if err != nil {
		log.Println("failed to create token:", err)
		return "", errors.New("failed to create token")
	}
	return tokenString, nil
}

func (s *account) RefreshToken(refreshToken string) (string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return conf.JWTSecret, nil
	})
	if err != nil || !token.Valid {
		log.Println("invalid refresh token:", err)
		return "", errors.New("failed to refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("invalid token claims type")
		return "", errors.New("failed to refresh token")
	}

	accountIdStr, ok := claims["id"].(string)
	if !ok {
		log.Println("invalid token 'id' field")
		return "", errors.New("failed to refresh token")
	}

	accountId, err := uuid.Parse(accountIdStr)
	if err != nil {
		log.Println("invalid account Id in token:", err)
		return "", errors.New("invalid account Id")
	}

	if err := s.CheckAccess(accountId); err != nil {
		log.Println("access check failed:", err)
		return "", errors.New("unauthorized to refresh token")
	}

	acc, err := s.repo.GetById(accountId)
	if err != nil {
		log.Println("failed to get account:", err)
		return "", errors.New("account not found")
	}

	newTokenString, err := s.addJWTToken(acc)
	if err != nil {
		log.Println("failed to create new token:", err)
		return "", errors.New("failed to create token")
	}
	return newTokenString, nil
}

func (s *account) Unblock(accountId uuid.UUID) error {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	acc.Blocked = time.Time{}
	acc.Updated = time.Now()

	if err := s.repo.Update(acc); err != nil {
		return err
	}
	return nil
}

func (s *account) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) error {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(oldPassword)); err != nil {
		return errors.New("invalid old password")
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return errors.New("failed to change password")
	}

	if err := s.repo.UpdatePassword(accountId, hashedPassword); err != nil {
		return err
	}
	return nil
}

func (s *account) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Println("failed to generate random bytes:", err)
		return "", errors.New("failed to create API Key")
	}

	key := hex.EncodeToString(bytes)

	apiKey := &model.APIKey{
		Id:        uuid.New(),
		Key:       key,
		AccountId: accountId,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := s.repo.AddAPIKey(apiKey); err != nil {
		return "", err
	}
	return key, nil
}

func (s *account) AuthenticateByAPIKey(apiKey string) (*model.Account, error) {
	apiKeyRecord, err := s.repo.GetAPIKeyByKey(apiKey)
	if err != nil {
		return nil, err
	}

	if !apiKeyRecord.ExpiresAt.IsZero() && time.Now().After(apiKeyRecord.ExpiresAt) {
		return nil, errors.New("API key expired")
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

func (s *account) DeleteAPIKey(apiKey string) error {
	if err := s.repo.DeleteAPIKey(apiKey); err != nil {
		return err
	}
	return nil
}

func (s *account) AddAccountRole(accountId uuid.UUID, role string) error {
	if err := s.repo.AddAccountRole(accountId, role); err != nil {
		return err
	}

	return nil
}

func (s *account) DeleteAccountRole(accountId uuid.UUID, role string) error {
	if err := s.repo.DeleteAccountRole(accountId, role); err != nil {
		return err
	}

	return nil
}

func (s *account) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRoles, error) {
	roles, err := s.repo.FindRolesByAccount(accountId)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *account) UpdateRoles(roles map[string]interface{}) error {
	for key, val := range roles {
		keyParts := strings.Split(key, "_")
		if len(keyParts) != 3 {
			log.Println("invalid key format:", key)
			continue
		}

		accountIdStr := keyParts[1]
		roleName := keyParts[2]

		accountId, err := uuid.Parse(accountIdStr)
		if err != nil {
			log.Printf("failed to parse account Id: %s", accountIdStr)
			continue
		}

		valueStr := fmt.Sprint(val)
		if strings.EqualFold(valueStr, "true") {
			if err := s.repo.AddAccountRole(accountId, roleName); err != nil {
				log.Printf("failed to add role %s to account %s: %v", roleName, accountId, err)
				continue
			}
		} else {
			if err := s.repo.DeleteAccountRole(accountId, roleName); err != nil {
				log.Printf("failed to delete role %s from account %s: %v", roleName, accountId, err)
				continue
			}
		}
	}
	return nil
}

func (s *account) addJWTToken(acc *model.Account) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"id":       acc.Id.String(),
		"nickname": acc.Nickname,
		"exp":      expirationTime.Unix(),
		"roles":    extractRoleNames(acc.Roles),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(conf.JWTSecret)
	if err != nil {
		log.Println("failed to sign JWT token:", err)
		return "", errors.New("failed to create token")
	}
	return tokenString, nil
}

func extractRoleNames(roles []model.AccountRoles) []string {
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}
	return roleNames
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("failed to hash password:", err)
		return "", errors.New("failed to hash password")
	}
	return string(bytes), nil
}
