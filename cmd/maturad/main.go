// Command maturad is Matura's control plane.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/audit"
	"github.com/marunsct/Platform/internal/config"
	"github.com/marunsct/Platform/internal/events"
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

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	kek := cfg.KEK
	if kek == "" { // only reachable in development (config.Validate)
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		kek = base64.StdEncoding.EncodeToString(b)
		log.Warn("MATURA_KEK is not set: using a random key for this run; stored secrets will not open after a restart")
	}
	keys, err := secrets.NewLocal(kek)
	if err != nil {
		return err
	}

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

	server := api.New(st, auth, keys, log)
	server.SetSource(cfg.EventSource)
	server.SetTrustedProxies(cfg.TrustedProxies)
	server.EnableInternal(cfg.InternalToken)
	server.SetDeletionGrace(cfg.DeleteGrace)
	server.SetInvitations(api.Invitations{AcceptURL: cfg.InviteAcceptURL, PublicURL: cfg.PublicURL,
		Issuer: cfg.Issuer, ClientID: cfg.PortalClientID})
	server.SetPortal(portal.Config{Auth: cfg.Auth, Issuer: cfg.Issuer, ClientID: cfg.PortalClientID})
	server.SetReadiness(readiness.Install{Product: cfg.ProductName, Env: cfg.Env, Auth: cfg.Auth,
		KEKConfigured: cfg.KEK != "", SMTPConfigured: cfg.SMTPAddr != "", MetricsEnabled: cfg.MetricsAddr != "",
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
