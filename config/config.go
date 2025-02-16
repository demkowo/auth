package config

import (
	"os"
)

const (
	portNumber = ":5000"
)

var (
	Values config = &conf{}
)

type config interface {
	Get() *conf
}

type conf struct {
	JWTSecret []byte
	Port      string
}

func (m *conf) Get() *conf {
	m.JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	m.Port = portNumber

	return m
}
