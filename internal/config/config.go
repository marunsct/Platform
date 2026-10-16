// Package config reads maturad's settings from the environment (technical specification §10).
package config

import (
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Env                string // development, staging, production
	DatabaseURL        string // runtime role, subject to row-level security
	MigrateDatabaseURL string // owner role, runs migrations at start-up
	RuntimeRole        string // role that receives table privileges after migrations
	HTTPAddr           string
	Issuer             string // Keycloak realm URL
	Audience           string
	OperatorRole       string // realm role that grants operator scope
	Auth               string // oidc or dev
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func FromEnv() (Config, error) {
	c := Config{
		Env:                getenv("MATURA_ENV", "production"),
		DatabaseURL:        os.Getenv("MATURA_DATABASE_URL"),
		MigrateDatabaseURL: os.Getenv("MATURA_MIGRATE_DATABASE_URL"),
		RuntimeRole:        getenv("MATURA_RUNTIME_ROLE", "matura_app"),
		HTTPAddr:           getenv("MATURA_HTTP_ADDR", ":8080"),
		Issuer:             os.Getenv("MATURA_ISSUER"),
		Audience:           getenv("MATURA_AUDIENCE", "matura-api"),
		OperatorRole:       getenv("MATURA_OPERATOR_ROLE", "matura-operator"),
		Auth:               getenv("MATURA_AUTH", "oidc"),
	}
	return c, c.Validate()
}

// Validate fails closed: a production server never starts with development authentication or without an issuer.
func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("MATURA_DATABASE_URL is required")
	}
	switch c.Auth {
	case "dev":
		if c.Env != "development" {
			return fmt.Errorf("MATURA_AUTH=dev trusts request headers; it needs MATURA_ENV=development (got %q)", c.Env)
		}
	case "oidc":
		if c.Issuer == "" {
			return errors.New("MATURA_AUTH=oidc needs MATURA_ISSUER (the Keycloak realm URL)")
		}
	default:
		return fmt.Errorf("MATURA_AUTH must be oidc or dev, got %q", c.Auth)
	}
	return nil
}
