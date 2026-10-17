// Package config reads maturad's settings from the environment (technical specification §10).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

type Config struct {
	Env                string // development, staging, production
	DatabaseURL        string // runtime role, subject to row-level security
	MigrateDatabaseURL string // owner role, runs migrations at start-up
	RuntimeRole        string // role that receives table privileges after migrations
	HTTPAddr           string
	MetricsAddr        string // separate listener for /metrics; empty turns it off
	Issuer             string // Keycloak realm URL
	Audience           string
	OperatorRole       string // realm role that grants operator scope
	Auth               string // oidc or dev
	KEK                string // base64 key-encryption key for stored secrets
	InternalToken      string // shared with Keycloak's Matura extension for /internal/v1
	EventSource        string // CloudEvents source of this installation
	PublicURL          string // where people reach maturad, for links in emails
	InviteAcceptURL    string // page invitation links open; default <PublicURL>/invitations/accept
	PortalClientID     string // public Keycloak client the portal and the accept page sign in with (PKCE)
	SMTPAddr           string // host:port of the mail relay; empty: emails are queued but not sent
	SMTPFrom           string
	SMTPUser           string
	SMTPPassword       string
	DeleteGrace        time.Duration  // how long a deleted tenant can be restored; default 30 days
	TrustedProxies     []netip.Prefix // reverse proxies whose X-Forwarded-For is believed (IP allow-lists, audit)
	ProductName        string         // name shown on the trust page and in readiness reports
	TrustPage          bool           // serve the public trust page at /trust (MATURA_TRUST_PAGE=on)
	SecurityContact    string         // optional address the trust page gives for security reports
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
		MetricsAddr:        metricsAddr(),
		Issuer:             os.Getenv("MATURA_ISSUER"),
		Audience:           getenv("MATURA_AUDIENCE", "matura-api"),
		OperatorRole:       getenv("MATURA_OPERATOR_ROLE", "matura-operator"),
		Auth:               getenv("MATURA_AUTH", "oidc"),
		KEK:                os.Getenv("MATURA_KEK"),
		InternalToken:      os.Getenv("MATURA_INTERNAL_TOKEN"),
		EventSource:        getenv("MATURA_EVENT_SOURCE", "matura://installation/main"),
		PublicURL:          getenv("MATURA_PUBLIC_URL", "http://localhost:8080"),
		InviteAcceptURL:    os.Getenv("MATURA_INVITE_ACCEPT_URL"),
		PortalClientID:     getenv("MATURA_PORTAL_CLIENT_ID", "matura-console"),
		SMTPAddr:           os.Getenv("MATURA_SMTP_ADDR"),
		SMTPFrom:           getenv("MATURA_SMTP_FROM", "no-reply@matura.local"),
		SMTPUser:           os.Getenv("MATURA_SMTP_USER"),
		SMTPPassword:       os.Getenv("MATURA_SMTP_PASSWORD"),
		ProductName:        getenv("MATURA_PRODUCT_NAME", "Matura"),
		SecurityContact:    os.Getenv("MATURA_SECURITY_CONTACT"),
	}
	switch v := strings.ToLower(getenv("MATURA_TRUST_PAGE", "off")); v {
	case "on", "true", "1":
		c.TrustPage = true
	case "off", "false", "0":
	default:
		return c, fmt.Errorf("MATURA_TRUST_PAGE must be on or off, got %q", v)
	}
	grace := getenv("MATURA_TENANT_DELETE_GRACE", "720h")
	d, err := time.ParseDuration(grace)
	if err != nil || d < 0 {
		return c, fmt.Errorf("MATURA_TENANT_DELETE_GRACE must be a duration such as 720h (30 days), got %q", grace)
	}
	c.DeleteGrace = d
	for _, raw := range strings.Split(os.Getenv("MATURA_TRUSTED_PROXIES"), ",") {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return c, fmt.Errorf("MATURA_TRUSTED_PROXIES: %q is not an address or CIDR range", raw)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}
	return c, c.Validate()
}

// Validate fails closed: a production server never starts with development authentication or without an issuer.
func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("MATURA_DATABASE_URL is required")
	}
	if c.KEK == "" && c.Env != "development" {
		return errors.New("MATURA_KEK is required outside development: 32 random bytes, base64 (openssl rand -base64 32)")
	}
	if c.InternalToken != "" && len(c.InternalToken) < 32 {
		return errors.New("MATURA_INTERNAL_TOKEN must be at least 32 characters (openssl rand -hex 32)")
	}
	if c.SMTPAddr != "" && !strings.Contains(c.SMTPFrom, "@") {
		return errors.New("MATURA_SMTP_FROM must be an email address")
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

// metricsAddr is MATURA_METRICS_ADDR, default :9090; set but empty turns the metrics listener off.
func metricsAddr() string {
	if v, ok := os.LookupEnv("MATURA_METRICS_ADDR"); ok {
		return v
	}
	return ":9090"
}
