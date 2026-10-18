// Package config reads maturad's settings from the environment (technical specification §10).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
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
	KEKProvider        string // where the key-encryption key lives: local (MATURA_KEK), transit, awskms, gcpkms, azurekv
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
	KeycloakURL        string         // Keycloak base URL maturad calls (default: from Issuer)
	KeycloakClientID   string         // confidential client whose service account manages the realm
	KeycloakSecret     string         // empty: session, MFA and SSO endpoints answer 503
	ProductName        string         // name shown on the trust page and in readiness reports
	TrustPage          bool           // serve the public trust page at /trust (MATURA_TRUST_PAGE=on)
	SecurityContact    string         // optional address the trust page gives for security reports
	OpenFGAURL         string         // OpenFGA HTTP API; empty turns fine-grained permissions off (TS11)
	OpenFGAToken       string         // OpenFGA preshared key, if it requires one
	OpenFGAStore       string         // name of the installation's OpenFGA store
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
		KEKProvider:        strings.ToLower(getenv("MATURA_KEK_PROVIDER", "local")),
		InternalToken:      os.Getenv("MATURA_INTERNAL_TOKEN"),
		EventSource:        getenv("MATURA_EVENT_SOURCE", "matura://installation/main"),
		PublicURL:          getenv("MATURA_PUBLIC_URL", "http://localhost:8080"),
		InviteAcceptURL:    os.Getenv("MATURA_INVITE_ACCEPT_URL"),
		PortalClientID:     getenv("MATURA_PORTAL_CLIENT_ID", "matura-console"),
		SMTPAddr:           os.Getenv("MATURA_SMTP_ADDR"),
		SMTPFrom:           getenv("MATURA_SMTP_FROM", "no-reply@matura.local"),
		SMTPUser:           os.Getenv("MATURA_SMTP_USER"),
		SMTPPassword:       os.Getenv("MATURA_SMTP_PASSWORD"),
		KeycloakURL:        os.Getenv("MATURA_KEYCLOAK_URL"),
		KeycloakClientID:   getenv("MATURA_KEYCLOAK_CLIENT_ID", "matura-admin"),
		KeycloakSecret:     os.Getenv("MATURA_KEYCLOAK_CLIENT_SECRET"),
		ProductName:        getenv("MATURA_PRODUCT_NAME", "Matura"),
		SecurityContact:    os.Getenv("MATURA_SECURITY_CONTACT"),
		OpenFGAURL:         os.Getenv("MATURA_OPENFGA_URL"),
		OpenFGAToken:       os.Getenv("MATURA_OPENFGA_TOKEN"),
		OpenFGAStore:       getenv("MATURA_OPENFGA_STORE", "matura"),
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
	switch c.KEKProvider {
	case "", "local":
		if c.KEK == "" && c.Env != "development" {
			return errors.New("MATURA_KEK is required outside development: 32 random bytes, base64 (openssl rand -base64 32)")
		}
	case "transit", "awskms", "gcpkms", "azurekv":
	default:
		return fmt.Errorf("MATURA_KEK_PROVIDER must be local, transit, awskms, gcpkms or azurekv, got %q", c.KEKProvider)
	}
	if c.InternalToken != "" && len(c.InternalToken) < 32 {
		return errors.New("MATURA_INTERNAL_TOKEN must be at least 32 characters (openssl rand -hex 32)")
	}
	if c.SMTPAddr != "" && !strings.Contains(c.SMTPFrom, "@") {
		return errors.New("MATURA_SMTP_FROM must be an email address")
	}
	if c.OpenFGAURL != "" {
		u, err := url.Parse(c.OpenFGAURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("MATURA_OPENFGA_URL must be an http(s) URL such as http://openfga:8080, got %q", c.OpenFGAURL)
		}
	}
	if c.KeycloakSecret != "" && c.Issuer == "" {
		return errors.New("MATURA_KEYCLOAK_CLIENT_SECRET needs MATURA_ISSUER (the realm comes from it)")
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
