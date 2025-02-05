package utils

import (
	"crypto/rand"
	"errors"
	"log"
	"time"

	"github.com/demkowo/auth/config"
	model "github.com/demkowo/auth/models"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var (
	H    HInterface   = &h{}
	Var  VarInterface = &hMock{}
	conf              = config.Values.Get()
)

func StartMock() {
	H = &hMock{
		Error: make(map[string]error),
	}
}

func StopMock() {
	H = &h{}
}

type HInterface interface {
	AddJWTToken(acc *model.Account) (string, error)
	GetRandomBytes(bytesNumber int) ([]byte, error)
	HashPassword(password string) (string, error)
}

type h struct {
}

func (h *h) AddJWTToken(acc *model.Account) (string, error) {
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

	tokenString, err := token.SignedString(conf.JWTSecret)
	if err != nil {
		log.Println("failed to sign JWT token:", err)
		return "", errors.New("failed to create token")
	}
	return tokenString, nil
}

func (h *h) GetRandomBytes(bytesNumber int) ([]byte, error) {
	bytes := make([]byte, bytesNumber)
	if _, err := rand.Read(bytes); err != nil {
		log.Println("failed to generate random bytes:", err)
		return nil, errors.New("failed to create API Key")
	}
	return bytes, nil
}

func (h *h) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("failed to hash password:", err)
		return "", errors.New("failed to hash password")
	}
	return string(bytes), nil
}
