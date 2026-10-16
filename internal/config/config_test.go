package config

import "testing"

func TestValidateFailsClosed(t *testing.T) {
	base := Config{DatabaseURL: "postgres://x", Issuer: "https://id", Auth: "oidc", Env: "production", KEK: "k"}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	cases := map[string]func(*Config){
		"no database":         func(c *Config) { c.DatabaseURL = "" },
		"dev auth in prod":    func(c *Config) { c.Auth = "dev" },
		"oidc without issuer": func(c *Config) { c.Issuer = "" },
		"unknown auth":        func(c *Config) { c.Auth = "none" },
		"no KEK in prod":      func(c *Config) { c.KEK = "" },
	}
	for name, mod := range cases {
		c := base
		mod(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dev := base
	dev.Auth, dev.Env = "dev", "development"
	if err := dev.Validate(); err != nil {
		t.Fatalf("dev auth in development: %v", err)
	}
}
