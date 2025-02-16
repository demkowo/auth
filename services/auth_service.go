package service

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/demkowo/auth/config"
	model "github.com/demkowo/auth/models"
	"github.com/demkowo/utils/helper"
	httpclient "github.com/demkowo/utils/http_client"
	"github.com/demkowo/utils/resp"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	conf    = config.Values.Get()
	help    = helper.NewHelper()
	httpcli = httpclient.NewClient()
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
	DeleteAPIKey(uuid.UUID) *resp.Err
	GetAPIKeyById(uuid.UUID) (*model.APIKey, *resp.Err)
	GetAPIKeyByKey(string) (*model.APIKey, *resp.Err)

	AddAccountRole(uuid.UUID, string) (*model.AccountRole, *resp.Err)
	DeleteAccountRoleById(uuid.UUID) *resp.Err
	DeleteAccountRoleByName(string) *resp.Err
	FindRolesByAccount(uuid.UUID) ([]model.AccountRole, *resp.Err)

	AddOAuth2Token(accountId string, token *model.OAuth2Token) *resp.Err
	DeleteOAuth2Token(accountId string) *resp.Err
	GetOAuth2TokenByaccountId(accountId string) (*model.OAuth2Token, *resp.Err)
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
	DeleteAPIKey(uuid.UUID) *resp.Err

	AddAccountRole(uuid.UUID, string) (*model.AccountRole, *resp.Err)
	DeleteAccountRoleById(uuid.UUID) *resp.Err
	DeleteAccountRoleByName(string) *resp.Err
	FindRolesByAccount(uuid.UUID) ([]model.AccountRole, *resp.Err)
	UpdateRoles(map[string]interface{}) *resp.Err

	ExchangeCodeForToken(provider string, code string) (*oauth2.Token, *resp.Err)
	GetAccountInfo(provider string, token *oauth2.Token) (*model.Account, *resp.Err)
	GetOAuthConfig(provider string) (*oauth2.Config, *resp.Err)
	Logout(accountId string) *resp.Err
	StoreAccount(account *model.Account) *resp.Err
}

type account struct {
	repo      AccountRepo
	providers map[string]*oauth2.Config
}

func NewAccount(repo AccountRepo) Account {
	providers := make(map[string]*oauth2.Config)

	providers["google"] = &oauth2.Config{
		ClientID:     "GOOGLE_CLIENT_ID",
		ClientSecret: "GOOGLE_CLIENT_SECRET",
		RedirectURL:  "http://localhost:5000/api/v1/auth/callback/google",
		Scopes:       []string{"email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}

	providers["facebook"] = &oauth2.Config{
		ClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
		ClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:5000/api/v1/auth/callback/facebook",
		Scopes:       []string{"email", "public_profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.facebook.com/v10.0/dialog/oauth",
			TokenURL: "https://graph.facebook.com/v10.0/oauth/access_token",
		},
	}

	providers["github"] = &oauth2.Config{
		ClientID:     "GITHUB_CLIENT_ID",
		ClientSecret: "GITHUB_CLIENT_SECRET",
		RedirectURL:  "http://localhost:5000/api/v1/auth/callback/github",
		Scopes:       []string{"user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}

	return &account{
		repo:      repo,
		providers: providers,
	}
}

func (s *account) Add(acc *model.Account) (*model.Account, *resp.Err) {
	existing, err := s.repo.GetByEmail(acc.Email)
	if err == nil && existing != nil {
		return nil, resp.Error(http.StatusConflict, "account already exists", []interface{}{acc.Email})
	}
	if err != nil && !strings.Contains(strings.ToLower(err.Error), "not found") {
		return nil, err
	}

	hashedPassword, hashErr := help.HashPassword(acc.Password)
	if hashErr != nil {
		return nil, hashErr
	}
	acc.Password = hashedPassword
	acc.Id = uuid.New()
	now := time.Now()
	acc.Created = now
	acc.Updated = now
	acc.Deleted = false

	newAcc, addErr := s.repo.Add(acc)
	if addErr != nil {
		return nil, addErr
	}
	return newAcc, nil
}

func (s *account) AddJWTToken(acc *model.Account) (string, *resp.Err) {
	if acc == nil {
		return "", resp.Error(http.StatusInternalServerError, "failed to create token", []interface{}{"missing account"})
	}

	roleNames := make([]string, len(acc.Roles))
	for i, role := range acc.Roles {
		roleNames[i] = role.Name
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"id":       acc.Id.String(),
		"nickname": acc.Nickname,
		"roles":    roleNames,
		"exp":      expirationTime.Unix(),
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

	updatedAcc, updateErr := s.repo.Update(acc)
	if updateErr != nil {
		return nil, updateErr
	}
	return updatedAcc, nil
}

func (s *account) CheckAccess(accountId uuid.UUID) *resp.Err {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}
	if acc.Deleted {
		return resp.Error(http.StatusUnauthorized, "account is deleted", nil)
	}
	if !acc.Blocked.IsZero() && acc.Blocked.After(time.Now()) {
		msg := fmt.Sprintf("account is banned until %s", acc.Blocked.Format(time.RFC3339))
		return resp.Error(http.StatusUnauthorized, msg, nil)
	}
	return nil
}

func (s *account) Delete(accountId uuid.UUID) *resp.Err {
	return s.repo.Delete(accountId)
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
	return s.repo.GetByEmail(email)
}

func (s *account) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
	return s.repo.GetById(id)
}

func (s *account) Login(email, password string) (string, *resp.Err) {
	acc, err := s.repo.GetByEmail(email)
	if err != nil {
		return "", err
	}
	if accessErr := s.CheckAccess(acc.Id); accessErr != nil {
		return "", accessErr
	}
	if pwdErr := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(password)); pwdErr != nil {
		return "", resp.Error(http.StatusUnauthorized, "invalid credentials", []interface{}{pwdErr.Error()})
	}

	tokenString, tokenErr := s.AddJWTToken(acc)
	if tokenErr != nil {
		return "", tokenErr
	}
	return tokenString, nil
}

func (s *account) RefreshToken(refreshToken string) (string, *resp.Err) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return conf.JWTSecret, nil
	})
	if err != nil || !token.Valid {
		return "", resp.Error(http.StatusBadRequest, "failed to refresh token", []interface{}{err.Error()})
	}

	claims := token.Claims.(jwt.MapClaims)
	accountIdStr := claims["id"].(string)

	accountId, parseErr := uuid.Parse(accountIdStr)
	if parseErr != nil {
		return "", resp.Error(http.StatusUnauthorized, "invalid account Id", []interface{}{parseErr.Error()})
	}

	acc, repoErr := s.repo.GetById(accountId)
	if repoErr != nil {
		return "", repoErr
	}
	if accessErr := s.CheckAccess(accountId); accessErr != nil {
		return "", accessErr
	}

	newToken, newTokenErr := s.AddJWTToken(acc)
	if newTokenErr != nil {
		return "", newTokenErr
	}
	return newToken, nil
}

func (s *account) Unblock(accountId uuid.UUID) (*model.Account, *resp.Err) {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return nil, err
	}
	acc.Blocked = time.Time{}
	acc.Updated = time.Now()

	return s.repo.Update(acc)
}

func (s *account) UpdatePassword(accountId uuid.UUID, oldPassword, newPassword string) *resp.Err {
	acc, err := s.repo.GetById(accountId)
	if err != nil {
		return err
	}

	if compareErr := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(oldPassword)); compareErr != nil {
		return resp.Error(http.StatusBadRequest, "invalid old password", []interface{}{compareErr.Error()})
	}

	hashedPassword, hashErr := help.HashPassword(newPassword)
	if hashErr != nil {
		return hashErr
	}
	return s.repo.UpdatePassword(accountId, hashedPassword)
}

func (s *account) AddAPIKey(accountId uuid.UUID, expiresAt time.Time) (*model.APIKey, *resp.Err) {
	bytes, randErr := help.GetRandomBytes(32)
	if randErr != nil {
		return nil, randErr
	}
	key := hex.EncodeToString(bytes)

	apiKey := &model.APIKey{
		Id:        uuid.New(),
		Key:       key,
		AccountId: accountId,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	return s.repo.AddAPIKey(apiKey)
}

func (s *account) AuthenticateByAPIKey(apiKey string) (*model.Account, *resp.Err) {
	apiKeyRecord, err := s.repo.GetAPIKeyByKey(apiKey)
	if err != nil {
		return nil, err
	}
	if !apiKeyRecord.ExpiresAt.IsZero() && time.Now().After(apiKeyRecord.ExpiresAt) {
		return nil, resp.Error(http.StatusUnauthorized, "API key expired", nil)
	}

	acc, e := s.repo.GetById(apiKeyRecord.AccountId)
	if e != nil {
		return nil, e
	}
	if accessErr := s.CheckAccess(acc.Id); accessErr != nil {
		return nil, accessErr
	}
	return acc, nil
}

func (s *account) DeleteAPIKey(id uuid.UUID) *resp.Err {
	return s.repo.DeleteAPIKey(id)
}

func (s *account) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	return s.repo.AddAccountRole(accountId, role)
}

func (s *account) DeleteAccountRoleById(accountId uuid.UUID) *resp.Err {
	return s.repo.DeleteAccountRoleById(accountId)
}

func (s *account) DeleteAccountRoleByName(role string) *resp.Err {
	return s.repo.DeleteAccountRoleByName(role)
}

func (s *account) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	return s.repo.FindRolesByAccount(accountId)
}

func (s *account) UpdateRoles(roles map[string]interface{}) *resp.Err {
	var errs []string
	for key, val := range roles {
		parts := strings.Split(key, "_")
		if len(parts) != 3 {
			return resp.Error(http.StatusBadRequest, fmt.Sprintf("invalid key format: %s", key), nil)
		}
		accountIdStr := parts[1]
		roleName := parts[2]
		accountId, parseErr := uuid.Parse(accountIdStr)
		if parseErr != nil {
			errs = append(errs, fmt.Sprintf("failed to parse account Id: %s", accountIdStr))
			continue
		}

		valueStr := fmt.Sprint(val)
		if strings.EqualFold(valueStr, "true") {
			if _, addErr := s.repo.AddAccountRole(accountId, roleName); addErr != nil {
				errs = append(errs, fmt.Sprintf("failed to add role %s", roleName))
			}
		} else {
			if delErr := s.repo.DeleteAccountRoleByName(roleName); delErr != nil {
				errs = append(errs, fmt.Sprintf("failed to delete role %s", roleName))
			}
		}
	}

	if len(errs) > 0 {
		return resp.Error(http.StatusBadRequest, "errors found while updating roles", []interface{}{errs})
	}
	return nil
}

func (s *account) ExchangeCodeForToken(provider string, code string) (*oauth2.Token, *resp.Err) {
	cfg, errResp := s.GetOAuthConfig(provider)
	if errResp != nil {
		return nil, errResp
	}
	token, err := help.Exchange(context.Background(), code, cfg)
	if err != nil {
		log.Println("Error exchanging code for token:", err)
		return nil, resp.Error(http.StatusBadRequest, "failed to exchange code for token", []interface{}{err.Error()})
	}
	return token, nil
}

func (s *account) GetAccountInfo(provider string, token *oauth2.Token) (*model.Account, *resp.Err) {
	var userInfoURL string
	switch provider {
	case "google":
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken
	case "facebook":
		userInfoURL = "https://graph.facebook.com/me?fields=id,name,email&access_token=" + token.AccessToken
	case "github":
		userInfoURL = "https://api.github.com/user"
	default:
		return nil, resp.Error(http.StatusBadRequest, "unsupported provider", []interface{}{provider})
	}

	respHTTP, err := httpcli.Get(userInfoURL, nil) //http.Get(userInfoURL)
	if err != nil {
		return nil, resp.Error(http.StatusBadRequest, "failed to fetch user info", []interface{}{err.Error()})
	}
	defer respHTTP.Body.Close()

	if respHTTP.StatusCode != http.StatusOK {
		return nil, resp.Error(http.StatusBadRequest, "failed to fetch user info", []interface{}{http.StatusText(respHTTP.StatusCode)})
	}

	var userInfo map[string]interface{}
	if decodeErr := json.NewDecoder(respHTTP.Body).Decode(&userInfo); decodeErr != nil {
		return nil, resp.Error(http.StatusBadRequest, "failed to decode user info", []interface{}{decodeErr.Error()})
	}

	account := &model.Account{
		Id:        uuid.New(),
		Email:     "",
		Nickname:  "",
		Roles:     []model.AccountRole{},
		Created:   time.Now(),
		Updated:   time.Now(),
		Blocked:   time.Time{},
		Deleted:   false,
		Providers: []string{provider},
	}

	switch provider {
	case "google", "facebook":
		if email, ok := userInfo["email"].(string); ok {
			account.Email = email
		}
		if name, ok := userInfo["name"].(string); ok {
			account.Nickname = name
		}
	case "github":
		if email, ok := userInfo["email"].(string); ok && email != "" {
			account.Email = email
		}
		if login, ok := userInfo["login"].(string); ok {
			account.Nickname = login
		}
	}

	return account, nil
}

func (s *account) GetOAuthConfig(provider string) (*oauth2.Config, *resp.Err) {
	cfg, ok := s.providers[provider]
	if !ok {
		return nil, resp.Error(http.StatusBadRequest, "unsupported provider", []interface{}{provider})
	}
	return cfg, nil
}

func (s *account) Logout(accountId string) *resp.Err {
	return s.repo.DeleteOAuth2Token(accountId)
}

func (s *account) StoreAccount(account *model.Account) *resp.Err {
	if account.Email == "" {
		return resp.Error(http.StatusBadRequest, "invalid account email", []interface{}{"email is empty"})
	}
	existing, err := s.repo.GetByEmail(account.Email)
	if err != nil {
		if len(err.Causes) > 0 {
			if dbErr, ok := err.Causes[0].(error); ok && dbErr == sql.ErrNoRows {
				account.Id = uuid.New()
				if _, addErr := s.repo.Add(account); addErr != nil {
					return addErr
				}
				return nil
			}
		}
		return err
	}
	existing.Nickname = account.Nickname
	existing.Providers = append(existing.Providers, account.Providers...)
	existing.Updated = time.Now()

	if _, updateErr := s.repo.Update(existing); updateErr != nil {
		return updateErr
	}
	return nil
}
