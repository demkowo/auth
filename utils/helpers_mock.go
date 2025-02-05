package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	model "github.com/demkowo/auth/models"
	"golang.org/x/crypto/bcrypt"
)

type hMock struct {
	Password string
	Error    map[string]error
}

type VarInterface interface {
	Get() *hMock
	SetExpectedPassword(string)
	SetExpectedError(map[string]error)
}

func (v *hMock) SetExpectedPassword(password string) {
	v.Password = password
}

func (v *hMock) SetExpectedError(err map[string]error) {
	v.Error = err
}

func (v *hMock) Get() *hMock {
	return v
}

func (h *hMock) AddJWTToken(acc *model.Account) (string, error) {
	err := Var.Get().Error["AddJWTToken"]

	if err != nil {
		return "", err
	}

	return "tokenString", nil
}

func (h *hMock) GetRandomBytes(bytesNumber int) ([]byte, error) {
	if Var.Get().Error["GetRandomBytes"] != nil {
		return nil, errors.New("failed to create API Key")
	}

	bytes := make([]byte, bytesNumber)
	if _, err := rand.Read(bytes); err != nil {
		log.Println("failed to generate random bytes:", err)
		return nil, errors.New("failed to create API Key")
	}
	return bytes, nil
}

func (h *hMock) HashPassword(password string) (string, error) {
	if err := Var.Get().Error["HashPassword"]; err != nil {
		return "", err
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return "", errors.New("failed to hash password")
	}

	if Var.Get().Password != "" {
		if err := bcrypt.CompareHashAndPassword(bytes, []byte(Var.Get().Password)); err != nil {
			return "", fmt.Errorf("password mismatch: %w", err)
		}
	}

	return password, nil
}
