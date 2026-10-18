// Command maturad is Matura's control plane.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/access"
	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/audit"
	"github.com/marunsct/Platform/internal/billing"
	"github.com/marunsct/Platform/internal/config"
	"github.com/marunsct/Platform/internal/events"
	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/lifecycle"
	"github.com/marunsct/Platform/internal/mail"
	"github.com/marunsct/Platform/internal/metrics"
	"github.com/marunsct/Platform/internal/placement"
	"github.com/marunsct/Platform/internal/portal"
	"github.com/marunsct/Platform/internal/privacy"
	"github.com/marunsct/Platform/internal/readiness"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("maturad stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.MigrateDatabaseURL != "" {
		conn, err := pgx.Connect(ctx, cfg.MigrateDatabaseURL)
		if err != nil {
			return err
		}
		err = store.Migrate(ctx, conn, cfg.RuntimeRole)
		conn.Close(ctx)
		if err != nil {
			return err
		}
		log.Info("migrations applied")
	}

	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	kek := cfg.KEK
	if kek == "" && (cfg.KEKProvider == "" || cfg.KEKProvider == "local") { // only in development (config.Validate)
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		kek = base64.StdEncoding.EncodeToString(b)
		log.Warn("MATURA_KEK is not set: using a random key for this run; stored secrets will not open after a restart")
	}
	var previous []string
	for _, k := range strings.Split(os.Getenv("MATURA_KEK_PREVIOUS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			previous = append(previous, k)
		}
	}
	keys, err := secrets.RingFromConfig(secrets.RingConfig{Provider: cfg.KEKProvider, LocalKEK: kek, Previous: previous})
	if err != nil {
		return err
	}
	log.Info("key-encryption key", "provider", cfg.KEKProvider, "key", keys.Primary().ID())

	var auth api.Authenticator
	switch cfg.Auth {
	case "dev":
		log.Warn("MATURA_AUTH=dev: requests are trusted from X-Matura-Dev-* headers; never use this outside development")
		auth = api.DevAuthenticator{}
	default:
		jwks := strings.TrimRight(cfg.Issuer, "/") + "/protocol/openid-connect/certs"
		if v := os.Getenv("MATURA_JWKS_URL"); v != "" {
			jwks = v
		}
		kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwks})
		if err != nil {
			return err
		}
		auth = api.JWTAuthenticator{Keyfunc: kf.Keyfunc, Issuer: cfg.Issuer, Audience: cfg.Audience,
			OperatorRole: cfg.OperatorRole}
	}

	st := store.New(pool)
	store.AllowHTTPWebhooks = cfg.Env == "development"
	relay := &events.Relay{Store: st, Keys: keys, Log: log, Source: cfg.EventSource}
	go relay.Run(ctx)
	provisioner := &placement.Provisioner{Store: st, Keys: keys, Log: log}
	go provisioner.Run(ctx)
	purger := &lifecycle.Purger{Store: st, Log: log}
	go purger.Run(ctx)
	streamer := &audit.Streamer{Store: st, Keys: keys, Log: log}
	go streamer.Run(ctx)
	privacyWorker := &privacy.Worker{Store: st, Log: log}
	go privacyWorker.Run(ctx)
	if adapter, err := billingAdapter(); err != nil {
		return err
	} else if adapter != nil {
		go (&billing.Exporter{Store: st, Adapter: adapter, Log: log}).Run(ctx)
		log.Info("billing export on", "provider", adapter.Name())
	}

	server := api.New(st, auth, keys, log)
	tenantKeysOn := false
	if v := strings.ToLower(os.Getenv("MATURA_TENANT_KEYS")); v != "off" && v != "false" {
		tenantKeysOn = true
		var byok []string
		for _, p := range strings.Split(os.Getenv("MATURA_BYOK_PROVIDERS"), ",") {
			if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
				byok = append(byok, p)
			}
		}
		server.EnableTenantKeys(keys, &secrets.CustomerKeys{Providers: byok, AllowHTTP: cfg.Env == "development"})
		log.Info("tenant keys on", "customer_managed_providers", byok)
	}
	if cfg.OpenFGAURL != "" {
		svc := &access.Service{Client: &fga.Client{URL: cfg.OpenFGAURL, Token: cfg.OpenFGAToken}, Store: st,
			StoreName: cfg.OpenFGAStore, Log: log}
		server.SetAccess(svc)
		go (&access.Syncer{Service: svc}).Run(ctx)
	} else {
		log.Info("MATURA_OPENFGA_URL is not set: fine-grained permission endpoints answer 501")
	}
	server.SetSource(cfg.EventSource)
	server.SetTrustedProxies(cfg.TrustedProxies)
	server.EnableInternal(cfg.InternalToken)
	server.SetProtectedResource(cfg.PublicURL, cfg.Audience, cfg.Issuer)
	if cfg.KeycloakSecret != "" {
		base, realm, err := keycloak.SplitIssuer(cfg.Issuer)
		if err != nil {
			return err
		}
		if cfg.KeycloakURL != "" {
			base = cfg.KeycloakURL
		}
		kc, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, ClientID: cfg.KeycloakClientID,
			ClientSecret: cfg.KeycloakSecret})
		if err != nil {
			return err
		}
		server.SetKeycloak(kc, cfg.Issuer)
		server.SetUserDirectory(kc) // erasure deletes the Keycloak account too
	} else {
		log.Warn("MATURA_KEYCLOAK_CLIENT_SECRET is not set: session, MFA and SSO endpoints answer 503")
	}
	api.AllowHTTPIdentityProviders = cfg.Env == "development"
	server.SetDeletionGrace(cfg.DeleteGrace)
	server.SetInvitations(api.Invitations{AcceptURL: cfg.InviteAcceptURL, PublicURL: cfg.PublicURL,
		Issuer: cfg.Issuer, ClientID: cfg.PortalClientID})
	server.SetPortal(portal.Config{Auth: cfg.Auth, Issuer: cfg.Issuer, ClientID: cfg.PortalClientID})
	server.SetReadiness(readiness.Install{Product: cfg.ProductName, Env: cfg.Env, Auth: cfg.Auth,
		KEKConfigured: cfg.KEK != "" || (cfg.KEKProvider != "" && cfg.KEKProvider != "local"), KEKProvider: cfg.KEKProvider,
		TenantKeys: tenantKeysOn, SMTPConfigured: cfg.SMTPAddr != "", MetricsEnabled: cfg.MetricsAddr != "",
		PublicURL: cfg.PublicURL, TrustPage: cfg.TrustPage, SecurityContact: cfg.SecurityContact})
	if cfg.SMTPAddr != "" {
		mailer := &mail.Mailer{Store: st, Log: log, Sender: mail.SMTP{Addr: cfg.SMTPAddr, From: cfg.SMTPFrom,
			User: cfg.SMTPUser, Password: cfg.SMTPPassword}}
		go mailer.Run(ctx)
	} else {
		log.Warn("MATURA_SMTP_ADDR is not set: invitation emails are queued but not sent; " +
			"the API returns each invitation's link so an admin can pass it on")
	}
	reg := metrics.New()
	reg.Backlog = st.Backlog
	if cfg.MetricsAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("GET /metrics", reg)
			msrv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			log.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := msrv.ListenAndServe(); err != nil {
				log.Error("metrics listener stopped", "err", err)
			}
		}()
	}
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           reg.Wrap(server.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("maturad listening", "addr", cfg.HTTPAddr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// billingAdapter reads MATURA_BILLING_PROVIDER (stripe, lago or openmeter; unset: no export), MATURA_BILLING_API_KEY,
// MATURA_BILLING_URL and MATURA_BILLING_METERS ("devflow.runs=runs,…": Matura meter to the provider's name).
func billingAdapter() (billing.Adapter, error) {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("MATURA_BILLING_PROVIDER")))
	key, base := os.Getenv("MATURA_BILLING_API_KEY"), os.Getenv("MATURA_BILLING_URL")
	names := map[string]string{}
	for _, pair := range strings.Split(os.Getenv("MATURA_BILLING_METERS"), ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && k != "" && v != "" {
			names[k] = v
		}
	}
	switch provider {
	case "":
		return nil, nil
	case "stripe":
		if key == "" {
			return nil, errors.New("MATURA_BILLING_API_KEY is required for Stripe")
		}
		return &billing.Stripe{APIKey: key, BaseURL: base, Events: names}, nil
	case "lago":
		if key == "" {
			return nil, errors.New("MATURA_BILLING_API_KEY is required for Lago")
		}
		return &billing.Lago{APIKey: key, BaseURL: base, Codes: names}, nil
	case "openmeter":
		return &billing.OpenMeter{APIKey: key, BaseURL: base, Types: names}, nil
	}
	return nil, fmt.Errorf("MATURA_BILLING_PROVIDER must be stripe, lago or openmeter, got %q", provider)
}
