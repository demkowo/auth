package config

import (
	"os"
)

var (
	Values config = &conf{}
)

type config interface {
	Get() *conf
}

type conf struct {
	JWTSecret []byte
}

func (m *conf) Get() *conf {
	m.JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	return m
}
