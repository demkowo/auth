package model

import (
	"net/http"
	"regexp"
	"time"

	"github.com/demkowo/utils/resp"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Account struct {
	Id        uuid.UUID     `json:"id"`
	Email     string        `json:"email"`
	Password  string        `json:"password"`
	Nickname  string        `json:"nickname"`
	Roles     []AccountRole `json:"roles"`
	APIKeys   []APIKey      `json:"api_keys"`
	Created   time.Time     `json:"created"`
	Updated   time.Time     `json:"updated"`
	Blocked   time.Time     `json:"blocked"`
	Deleted   bool          `json:"deleted"`
	Providers []string      `json:"providers"`
	jwt.StandardClaims
}

type AccountRole struct {
	Id   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type APIKey struct {
	Id        uuid.UUID `json:"id"`
	Key       string    `json:"key"`
	AccountId uuid.UUID `json:"account_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OAuth2Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

func (a *Account) Validate() *resp.Err {
	if a.Email == "" || a.Password == "" || a.Nickname == "" {
		return resp.Error(http.StatusInternalServerError, "mandatory field is empty", []interface{}{"email, password and nickname can't be empty"})
	}

	emailRegex := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	if !emailRegex.MatchString(a.Email) {
		return resp.Error(http.StatusInternalServerError, "invalid email address", []interface{}{})
	}

	if len(a.Password) < 8 ||
		!containsCapitalLetter(a.Password) ||
		!containsSpecialCharacter(a.Password) ||
		!containsDigit(a.Password) {
		return resp.Error(http.StatusInternalServerError, "invalid password", []interface{}{"password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit"})
	}
	return nil
}

func containsCapitalLetter(password string) bool {
	match, _ := regexp.MatchString("[A-Z]", password)
	return match
}

func containsSpecialCharacter(password string) bool {
	match, _ := regexp.MatchString(`[!@#$%^&*()\-_=+\[\]{}|;:'",.<>/?~]`, password)
	return match
}

func containsDigit(password string) bool {
	match, _ := regexp.MatchString("[0-9]", password)
	return match
}
