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

func TestTrustPageDefaultsOff(t *testing.T) {
	t.Setenv("MATURA_DATABASE_URL", "postgres://x")
	t.Setenv("MATURA_ENV", "development")
	t.Setenv("MATURA_AUTH", "dev")
	c, err := FromEnv()
	if err != nil || c.TrustPage || c.ProductName != "Matura" {
		t.Fatalf("defaults: trust page %v, product %q, %v", c.TrustPage, c.ProductName, err)
	}
	t.Setenv("MATURA_TRUST_PAGE", "on")
	t.Setenv("MATURA_PRODUCT_NAME", "Acme Cloud")
	if c, err = FromEnv(); err != nil || !c.TrustPage || c.ProductName != "Acme Cloud" {
		t.Fatalf("on: %v %q %v", c.TrustPage, c.ProductName, err)
	}
	t.Setenv("MATURA_TRUST_PAGE", "maybe")
	if _, err = FromEnv(); err == nil {
		t.Fatal("MATURA_TRUST_PAGE=maybe accepted")
	}
}

func TestMetricsAddrCanBeTurnedOff(t *testing.T) {
	t.Setenv("MATURA_METRICS_ADDR", "")
	if got := metricsAddr(); got != "" {
		t.Fatalf("empty MATURA_METRICS_ADDR gave %q, want off", got)
	}
}

func TestOpenFGAIsOptional(t *testing.T) {
	t.Setenv("MATURA_DATABASE_URL", "postgres://x")
	t.Setenv("MATURA_ENV", "development")
	t.Setenv("MATURA_AUTH", "dev")
	if c, err := FromEnv(); err != nil || c.OpenFGAURL != "" || c.OpenFGAStore != "matura" {
		t.Fatalf("default: %+v %v", c, err)
	}
	t.Setenv("MATURA_OPENFGA_URL", "http://openfga:8080")
	if c, err := FromEnv(); err != nil || c.OpenFGAURL != "http://openfga:8080" {
		t.Fatalf("set: %v", err)
	}
	t.Setenv("MATURA_OPENFGA_URL", "openfga:8080")
	if _, err := FromEnv(); err == nil {
		t.Fatal("a URL without scheme was accepted")
	}
}
