package model

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	acc   Account
	tn, _ = time.Parse("2006-01-02T15:04:05", "2025-02-06T11:35:20")

	defaultAccount = Account{
		Id:       uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Nickname: "admin",
		Email:    "admin@admin.com",
		Password: "ValidPassword!123",
		Roles:    nil,
		APIKeys:  nil,
		Created:  tn,
		Updated:  tn,
		Blocked:  time.Time{},
		Deleted:  false,
	}
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func Test_Validate_Success(t *testing.T) {
	acc = defaultAccount

	err := acc.Validate()

	assert.NoError(t, err)
}

func Test_Validate_EmptyEmail(t *testing.T) {
	acc = defaultAccount
	acc.Email = ""

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "email, password and nickname can't be empty")
}

func Test_Validate_EmptyPassword(t *testing.T) {
	acc = defaultAccount
	acc.Password = ""

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "email, password and nickname can't be empty")
}

func Test_Validate_EmptyNickname(t *testing.T) {
	acc = defaultAccount
	acc.Nickname = ""

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "email, password and nickname can't be empty")
}

func Test_Validate_InvalidEmail(t *testing.T) {
	acc = defaultAccount
	acc.Email = "invalidEmail"

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid email address")
}

func Test_Validate_InvalidPasswordTooShort(t *testing.T) {
	acc = defaultAccount
	acc.Password = "Short1!"

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit")
}

func Test_Validate_InvalidPasswordNoCapitalLetter(t *testing.T) {
	acc = defaultAccount
	acc.Password = "0_capital_letters"

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit")
}

func Test_Validate_InvalidPasswordNoSpecialChar(t *testing.T) {
	acc = defaultAccount
	acc.Password = "0SpecialCharacters"

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit")
}

func Test_Validate_InvalidPasswordNoDigits(t *testing.T) {
	acc = defaultAccount
	acc.Password = "ZeroDigits!"

	err := acc.Validate()

	assert.Error(t, err)
	assert.EqualError(t, err, "password must contain at least 8 characters, 1 capital letter, 1 special character, and 1 digit")
}
