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

func TestTrustedProxies(t *testing.T) {
	t.Setenv("MATURA_DATABASE_URL", "postgres://x")
	t.Setenv("MATURA_ENV", "development")
	t.Setenv("MATURA_AUTH", "dev")
	t.Setenv("MATURA_TRUSTED_PROXIES", "10.0.0.1, 172.16.5.0/12")
	c, err := FromEnv()
	if err != nil || len(c.TrustedProxies) != 2 || c.TrustedProxies[0].String() != "10.0.0.1/32" ||
		c.TrustedProxies[1].String() != "172.16.0.0/12" {
		t.Fatalf("trusted proxies: %v %v", c.TrustedProxies, err)
	}
	t.Setenv("MATURA_TRUSTED_PROXIES", "proxy.local")
	if _, err := FromEnv(); err == nil {
		t.Fatal("a host name was accepted as a trusted proxy")
	}
}
