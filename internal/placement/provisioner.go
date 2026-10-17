// Package placement creates and drops the storage of platform-managed data placements (technical specification
// §7, TS7b) on the database servers operators registered.
//
//	shared:   database <app>_shared once per server, owned by <app>_owner; runtime role <app>_app without BYPASSRLS
//	          (the app's row-level security separates tenants)
//	schema:   database <app>_bridge once per server; schema t_<tenant> owned by role <app>_t_<id>, whose
//	          search_path is that schema; the role can connect to the bridge database and use nothing else
//	database: database <app>_t_<tenant> owned by role <app>_t_<id>; CONNECT revoked from PUBLIC
//
// Every step checks before it creates, so a step that failed halfway is safe to run again.
package placement

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

const provisionerLock = 7351004

// Provisioner works through placements that need storage created or dropped. Every maturad replica runs one; an
// advisory lock makes exactly one of them active.
type Provisioner struct {
	Store    *store.Store
	Keys     secrets.KeyManager
	Log      *slog.Logger
	Interval time.Duration // between rounds; default 2 s
}

func (p *Provisioner) defaults() {
	if p.Interval == 0 {
		p.Interval = 2 * time.Second
	}
	if p.Log == nil {
		p.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (p *Provisioner) Run(ctx context.Context) {
	p.defaults()
	for ctx.Err() == nil {
		release, ok, err := p.Store.TryLeader(ctx, provisionerLock)
		if err != nil && ctx.Err() == nil {
			p.Log.Warn("provisioner: leader check failed", "err", err)
		}
		if ok {
			for ctx.Err() == nil {
				if _, err := p.Round(ctx); err != nil && ctx.Err() == nil {
					p.Log.Warn("provisioner round failed", "err", err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(p.Interval):
				}
			}
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// Round handles every placement that is due and returns how many it handled (tests call it directly).
func (p *Provisioner) Round(ctx context.Context) (int, error) {
	p.defaults()
	done := 0
	for done < 100 {
		j, err := p.Store.NextPlacementJob(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return done, nil
		}
		if err != nil {
			return done, err
		}
		if j.Retire {
			err = p.drop(ctx, j)
		} else {
			err = p.provision(ctx, j)
		}
		if err != nil {
			p.Log.Warn("placement step failed", "placement", j.ID, "mode", j.Mode, "retire", j.Retire, "err", err)
			if ferr := p.Store.PlacementFailed(ctx, j, err); ferr != nil {
				return done, ferr
			}
		}
		done++
	}
	return done, nil
}

var nonName = regexp.MustCompile(`[^a-z0-9_]+`)

// ident turns slugs into a Postgres identifier: lower case, [a-z0-9_], at most 63 bytes.
func ident(parts ...string) string {
	s := nonName.ReplaceAllString(strings.ToLower(strings.Join(parts, "_")), "_")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func shortID(j store.PlacementJob) string {
	h := strings.ReplaceAll(j.TenantID.String(), "-", "")
	return h[len(h)-12:] // the random end of a UUIDv7
}

func password() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func q(name string) string { return pgx.Identifier{name}.Sanitize() }

// lit quotes a string literal for statements that take no parameters (CREATE ROLE … PASSWORD).
func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (p *Provisioner) connect(ctx context.Context, server uuid.UUID, db string) (*pgx.Conn, error) {
	dsn, err := p.Store.DBServerAdminURL(ctx, store.Scope{Operator: true}, p.Keys, server)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	u.Path = "/" + db
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("connect to database server as admin (%s): %w", db, err)
	}
	return conn, nil
}

func exists(ctx context.Context, c *pgx.Conn, sql string, args ...any) (bool, error) {
	var ok bool
	err := c.QueryRow(ctx, `SELECT EXISTS (`+sql+`)`, args...).Scan(&ok)
	return ok, err
}

// ensureRole creates a login role or, when it exists, sets a new password (the stored one is then replaced).
func ensureRole(ctx context.Context, c *pgx.Conn, role, pw string, login bool) error {
	ok, err := exists(ctx, c, `SELECT 1 FROM pg_roles WHERE rolname = $1`, role)
	if err != nil {
		return err
	}
	opts := "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD " + lit(pw)
	if !login {
		opts = "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
	}
	verb := "CREATE"
	if ok {
		verb = "ALTER"
	}
	_, err = c.Exec(ctx, verb+" ROLE "+q(role)+" "+opts)
	return err
}

func ensureDatabase(ctx context.Context, c *pgx.Conn, db, owner string) error {
	ok, err := exists(ctx, c, `SELECT 1 FROM pg_database WHERE datname = $1`, db)
	if err != nil || ok {
		return err
	}
	stmt := "CREATE DATABASE " + q(db)
	if owner != "" {
		// the admin must be a member of the owner role to give it a database (Postgres 16 rule)
		if _, err := c.Exec(ctx, "GRANT "+q(owner)+" TO CURRENT_USER"); err != nil {
			return err
		}
		stmt += " OWNER " + q(owner)
	}
	if _, err := c.Exec(ctx, stmt); err != nil {
		return err
	}
	_, err = c.Exec(ctx, "REVOKE ALL ON DATABASE "+q(db)+" FROM PUBLIC")
	return err
}

func (p *Provisioner) provision(ctx context.Context, j store.PlacementJob) error {
	server, err := p.Store.PickDBServer(ctx, j.AppID, j.Mode)
	if err != nil {
		return err
	}
	c, err := p.connect(ctx, server, "postgres")
	if err != nil {
		return err
	}
	defer c.Close(context.WithoutCancel(ctx))
	out := store.Provisioned{DBServerID: server, RolePassword: password()}
	switch j.Mode {
	case "shared":
		out.Database, out.Owner, out.Role = ident(j.AppSlug, "shared"), ident(j.AppSlug, "owner"), ident(j.AppSlug, "app")
		out.OwnerPassword = password()
		if err := ensureRole(ctx, c, out.Owner, out.OwnerPassword, true); err != nil {
			return err
		}
		if err := ensureRole(ctx, c, out.Role, out.RolePassword, true); err != nil {
			return err
		}
		if err := ensureDatabase(ctx, c, out.Database, out.Owner); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "GRANT CONNECT ON DATABASE "+q(out.Database)+" TO "+q(out.Role)); err != nil {
			return err
		}
		db, err := p.connect(ctx, server, out.Database)
		if err != nil {
			return err
		}
		defer db.Close(context.WithoutCancel(ctx))
		// the runtime role reads and writes what the owner creates, never owns or alters it
		for _, stmt := range []string{
			"GRANT USAGE ON SCHEMA public TO " + q(out.Role),
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + q(out.Owner) + " IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO " + q(out.Role),
			"ALTER DEFAULT PRIVILEGES FOR ROLE " + q(out.Owner) + " IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO " + q(out.Role),
			"ALTER SCHEMA public OWNER TO " + q(out.Owner),
		} {
			if _, err := db.Exec(ctx, stmt); err != nil {
				return err
			}
		}
	case "schema":
		out.Database, out.Role = ident(j.AppSlug, "bridge"), ident(j.AppSlug, "t", shortID(j))
		out.Schema = ident("t", j.TenantSlug)
		if err := ensureRole(ctx, c, out.Role, out.RolePassword, true); err != nil {
			return err
		}
		if err := ensureDatabase(ctx, c, out.Database, ""); err != nil {
			return err
		}
		// the admin must be a member of the role to give it a schema (Postgres 16 rule)
		for _, stmt := range []string{
			"GRANT CONNECT ON DATABASE " + q(out.Database) + " TO " + q(out.Role),
			"GRANT " + q(out.Role) + " TO CURRENT_USER",
		} {
			if _, err := c.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		db, err := p.connect(ctx, server, out.Database)
		if err != nil {
			return err
		}
		defer db.Close(context.WithoutCancel(ctx))
		for _, stmt := range []string{
			"REVOKE ALL ON SCHEMA public FROM PUBLIC",
			"CREATE SCHEMA IF NOT EXISTS " + q(out.Schema) + " AUTHORIZATION " + q(out.Role),
			"ALTER ROLE " + q(out.Role) + " IN DATABASE " + q(out.Database) + " SET search_path = " + q(out.Schema),
		} {
			if _, err := db.Exec(ctx, stmt); err != nil {
				return err
			}
		}
	case "database":
		out.Database, out.Role = ident(j.AppSlug, "t", j.TenantSlug), ident(j.AppSlug, "t", shortID(j))
		if err := ensureRole(ctx, c, out.Role, out.RolePassword, true); err != nil {
			return err
		}
		if err := ensureDatabase(ctx, c, out.Database, out.Role); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown placement mode %q", j.Mode)
	}
	out.Label = out.Database
	if out.Schema != "" {
		out.Label += "/" + out.Schema
	}
	return p.Store.PlacementProvisioned(ctx, p.Keys, j, out)
}

// drop removes a retired tenant's schema or database and role. Shared mode keeps the shared database: the app
// already deleted the tenant's rows.
func (p *Provisioner) drop(ctx context.Context, j store.PlacementJob) error {
	if j.DBServerID == nil || j.DatabaseName == nil || j.Mode == "shared" {
		return p.Store.PlacementDropped(ctx, j)
	}
	c, err := p.connect(ctx, *j.DBServerID, "postgres")
	if err != nil {
		return err
	}
	defer c.Close(context.WithoutCancel(ctx))
	switch j.Mode {
	case "schema":
		ok, err := exists(ctx, c, `SELECT 1 FROM pg_database WHERE datname = $1`, *j.DatabaseName)
		if err != nil {
			return err
		}
		if ok {
			db, err := p.connect(ctx, *j.DBServerID, *j.DatabaseName)
			if err != nil {
				return err
			}
			defer db.Close(context.WithoutCancel(ctx))
			if j.SchemaName != nil {
				if _, err := db.Exec(ctx, "DROP SCHEMA IF EXISTS "+q(*j.SchemaName)+" CASCADE"); err != nil {
					return err
				}
			}
			if j.RoleName != nil {
				if ok, err := exists(ctx, db, `SELECT 1 FROM pg_roles WHERE rolname = $1`, *j.RoleName); err != nil {
					return err
				} else if ok {
					if _, err := db.Exec(ctx, "DROP OWNED BY "+q(*j.RoleName)); err != nil {
						return err
					}
				}
			}
		}
	case "database":
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+q(*j.DatabaseName)+" WITH (FORCE)"); err != nil {
			return err
		}
	}
	if j.RoleName != nil {
		if _, err := c.Exec(ctx, "DROP ROLE IF EXISTS "+q(*j.RoleName)); err != nil {
			return err
		}
	}
	return p.Store.PlacementDropped(ctx, j)
}
