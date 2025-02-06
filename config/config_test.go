package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func Test_Get_Success(t *testing.T) {
	res := Values.Get()

	assert.NotNil(t, res)
	assert.NotNil(t, res.JWTSecret)
}
