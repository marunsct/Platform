package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/secrets"
)

// --- plans --------------------------------------------------------------------------------------------------------

type Plan struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	DataModeRequired *string         `json:"data_mode_required"`
	DataModeDefault  string          `json:"data_mode_default"`
	Limits           json.RawMessage `json:"limits"`
}

var planIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// PutPlan creates or replaces a plan (operators). The mode decides where tenants on the plan keep their data (DP-3).
func (s *Store) PutPlan(ctx context.Context, sc Scope, p Plan) (Plan, error) {
	if !planIDRE.MatchString(p.ID) {
		return Plan{}, invalid("plan id %q must be lower-case letters, digits, '_' or '-'", p.ID)
	}
	if p.Name == "" {
		p.Name = p.ID
	}
	if p.DataModeDefault == "" {
		p.DataModeDefault = "shared"
	}
	if len(p.Limits) == 0 {
		p.Limits = json.RawMessage(`{}`)
	}
	var out Plan
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `INSERT INTO plan (id, name, data_mode_required, data_mode_default, limits)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, data_mode_required = EXCLUDED.data_mode_required,
				data_mode_default = EXCLUDED.data_mode_default, limits = EXCLUDED.limits
			RETURNING id, name, data_mode_required, data_mode_default, limits`,
			p.ID, p.Name, p.DataModeRequired, p.DataModeDefault, []byte(p.Limits)).
			Scan(&out.ID, &out.Name, &out.DataModeRequired, &out.DataModeDefault, &out.Limits))
	})
	return out, err
}

func (s *Store) ListPlans(ctx context.Context) ([]Plan, error) {
	var out []Plan
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, data_mode_required, data_mode_default, limits FROM plan ORDER BY id`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Plan, error) {
			var p Plan
			err := r.Scan(&p.ID, &p.Name, &p.DataModeRequired, &p.DataModeDefault, &p.Limits)
			return p, err
		})
		return err
	})
	return out, err
}

// --- database servers (DP-2) ---------------------------------------------------------------------------------------

type DBServer struct {
	ID                uuid.UUID       `json:"id"`
	Name              string          `json:"name"`
	Host              string          `json:"host"`
	Port              int             `json:"port"`
	AdminUser         string          `json:"admin_user"`
	SecretFingerprint string          `json:"admin_secret_fingerprint"` // the password itself is never returned
	SSLMode           string          `json:"sslmode"`
	Region            *string         `json:"region"`
	Dedicated         bool            `json:"dedicated"`
	Labels            json.RawMessage `json:"labels"`
	Status            string          `json:"status"`
	Version           int64           `json:"version"`
}

const dbServerCols = `id, name, host, port, admin_user, admin_secret_fingerprint, sslmode, region, dedicated, labels,
	status, version`

func scanDBServer(row pgx.Row) (DBServer, error) {
	var d DBServer
	err := row.Scan(&d.ID, &d.Name, &d.Host, &d.Port, &d.AdminUser, &d.SecretFingerprint, &d.SSLMode, &d.Region,
		&d.Dedicated, &d.Labels, &d.Status, &d.Version)
	return d, mapErr(err)
}

var (
	serverNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostRE       = regexp.MustCompile(`^[A-Za-z0-9.:\-\[\]]{1,253}$`)
	pgUserRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
)

type NewDBServer struct {
	Name          string
	Host          string
	Port          int
	AdminUser     string
	AdminPassword string
	SSLMode       string
	Region        string
	Dedicated     bool
	Labels        json.RawMessage
}

func (in *NewDBServer) validate() error {
	if !serverNameRE.MatchString(in.Name) {
		return invalid("name must be lower-case letters, digits and hyphens")
	}
	if !hostRE.MatchString(in.Host) {
		return invalid("host must be a host name or IP address")
	}
	if in.Port == 0 {
		in.Port = 5432
	}
	if in.Port < 1 || in.Port > 65535 {
		return invalid("port must be between 1 and 65535")
	}
	if !pgUserRE.MatchString(in.AdminUser) {
		return invalid("admin_user must be a plain Postgres role name")
	}
	if in.AdminPassword == "" {
		return invalid("admin_password is required")
	}
	if in.SSLMode == "" {
		in.SSLMode = "require"
	}
	if len(in.Labels) == 0 {
		in.Labels = json.RawMessage(`{}`)
	}
	return nil
}

func dbServerAAD(id uuid.UUID) string { return "db_server:" + id.String() }

// CreateDBServer registers a Postgres server Matura may create databases and schemas on. The admin password is
// sealed with the KeyManager and only its fingerprint is ever shown.
func (s *Store) CreateDBServer(ctx context.Context, sc Scope, km secrets.KeyManager, in NewDBServer) (DBServer, error) {
	if err := in.validate(); err != nil {
		return DBServer{}, err
	}
	id := ids.New()
	sealed, err := km.Seal([]byte(in.AdminPassword), dbServerAAD(id))
	if err != nil {
		return DBServer{}, err
	}
	var out DBServer
	err = s.tx(ctx, sc, func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanDBServer(tx.QueryRow(ctx, `INSERT INTO db_server (id, name, host, port, admin_user, admin_secret,
			admin_secret_fingerprint, sslmode, region, dedicated, labels, status, version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', $12) RETURNING `+dbServerCols,
			id, in.Name, in.Host, in.Port, in.AdminUser, sealed, km.Fingerprint([]byte(in.AdminPassword)), in.SSLMode,
			nullable(in.Region), in.Dedicated, []byte(in.Labels), v))
		return err
	})
	return out, err
}

func (s *Store) ListDBServers(ctx context.Context, sc Scope) ([]DBServer, error) {
	var out []DBServer
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+dbServerCols+` FROM db_server ORDER BY name`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (DBServer, error) { return scanDBServer(r) })
		return err
	})
	return out, err
}

type DBServerPatch struct {
	Status        *string // active, draining (no new placements) or disabled
	Region        *string
	Dedicated     *bool
	Labels        json.RawMessage
	AdminPassword *string // rotation
}

func (s *Store) UpdateDBServer(ctx context.Context, sc Scope, km secrets.KeyManager, id uuid.UUID, p DBServerPatch) (DBServer, error) {
	if p.Status != nil && *p.Status != "active" && *p.Status != "draining" && *p.Status != "disabled" {
		return DBServer{}, invalid("status can be active, draining or disabled")
	}
	var sealed []byte
	var fp *string
	if p.AdminPassword != nil {
		if *p.AdminPassword == "" {
			return DBServer{}, invalid("admin_password cannot be empty")
		}
		var err error
		if sealed, err = km.Seal([]byte(*p.AdminPassword), dbServerAAD(id)); err != nil {
			return DBServer{}, err
		}
		f := km.Fingerprint([]byte(*p.AdminPassword))
		fp = &f
	}
	var out DBServer
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		var labels any
		if len(p.Labels) > 0 {
			labels = []byte(p.Labels)
		}
		out, err = scanDBServer(tx.QueryRow(ctx, `UPDATE db_server SET status = coalesce($2, status),
			region = coalesce($3, region), dedicated = coalesce($4, dedicated), labels = coalesce($5::jsonb, labels),
			admin_secret = coalesce($6, admin_secret), admin_secret_fingerprint = coalesce($7, admin_secret_fingerprint),
			version = $8, updated_at = now() WHERE id = $1 RETURNING `+dbServerCols,
			id, p.Status, p.Region, p.Dedicated, labels, sealed, fp, v))
		return err
	})
	return out, err
}

// DeleteDBServer removes a server no placement uses.
func (s *Store) DeleteDBServer(ctx context.Context, sc Scope, id uuid.UUID) error {
	return s.tx(ctx, sc, func(tx pgx.Tx) error {
		var used int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM placement WHERE db_server_id = $1 AND state <> 'deleted'`, id).
			Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			return invalid("%d tenant placements still use this server; drain it and move them first", used)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM db_server WHERE id = $1`, id)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DBServerAdminURL opens the server's sealed password and returns a connection URL for its admin role. Only the
// provisioner and the connection test use it; it is never sent to a client.
func (s *Store) DBServerAdminURL(ctx context.Context, sc Scope, km secrets.KeyManager, id uuid.UUID) (string, error) {
	var host, user, sslmode string
	var port int
	var sealed []byte
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT host, port, admin_user, admin_secret, sslmode FROM db_server WHERE id = $1`, id).
			Scan(&host, &port, &user, &sealed, &sslmode))
	})
	if err != nil {
		return "", err
	}
	pw, err := km.Open(sealed, dbServerAAD(id))
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(user, string(pw)), Host: host + ":" + strconv.Itoa(port),
		Path: "/postgres", RawQuery: "sslmode=" + url.QueryEscape(sslmode) + "&connect_timeout=5"}
	return u.String(), nil
}

// ServerCheck is what the connection test found.
type ServerCheck struct {
	OK            bool   `json:"ok"`
	ServerVersion string `json:"server_version,omitempty"`
	CanCreateDB   bool   `json:"can_create_databases"`
	CanCreateRole bool   `json:"can_create_roles"`
	Error         string `json:"error,omitempty"`
}

// CheckDBServer connects with the admin role and reports whether it can do what provisioning needs.
func (s *Store) CheckDBServer(ctx context.Context, sc Scope, km secrets.KeyManager, id uuid.UUID) (ServerCheck, error) {
	dsn, err := s.DBServerAdminURL(ctx, sc, km, id)
	if err != nil {
		return ServerCheck{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		var ce *pgconn.ConnectError
		msg := "cannot connect"
		if errors.As(err, &ce) {
			msg = fmt.Sprintf("cannot connect: %v", ce.Unwrap())
		}
		return ServerCheck{Error: msg}, nil
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var c ServerCheck
	err = conn.QueryRow(ctx, `SELECT current_setting('server_version'),
			rolsuper OR rolcreatedb, rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user`).
		Scan(&c.ServerVersion, &c.CanCreateDB, &c.CanCreateRole)
	if err != nil {
		return ServerCheck{Error: "connected, but could not read the role's privileges"}, nil
	}
	c.OK = c.CanCreateDB && c.CanCreateRole
	if !c.OK {
		c.Error = "the admin role needs CREATEDB and CREATEROLE"
	}
	return c, nil
}
