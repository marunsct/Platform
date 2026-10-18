package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/secrets"
)

// Data placement (technical specification §7, TS7b): where each tenant's data for each app lives, and its lifecycle
// requested → provisioned → ready → retiring → deleted. Platform-managed placements are provisioned by
// internal/placement; app-managed ones are registered by the app.

func placementSubject(p Placement, appSlug string) string {
	return "tenants/" + p.TenantID.String() + "/apps/" + appSlug + "/placement"
}

func placementAAD(id uuid.UUID, purpose string) string {
	return "placement:" + id.String() + ":" + purpose
}

// ListPlacements returns where a tenant's data lives for each app it enabled.
func (s *Store) ListPlacements(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Placement, error) {
	var out []Placement
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+placementCols+` FROM placement WHERE tenant_id = $1 ORDER BY created_at`,
			tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Placement, error) { return scanPlacement(r) })
		return err
	})
	return out, err
}

// AppPlacement is the calling app's placement for a tenant.
func (s *Store) AppPlacement(ctx context.Context, app App, tenantID uuid.UUID) (Placement, error) {
	var out Placement
	err := s.tx(ctx, Scope{TenantID: tenantID, Operator: true}, func(tx pgx.Tx) error {
		var err error
		out, err = scanPlacement(tx.QueryRow(ctx, `SELECT `+placementCols+` FROM placement
			WHERE tenant_id = $1 AND app_id = $2`, tenantID, app.ID))
		return err
	})
	return out, err
}

// changePlacement locks the app's placement for a tenant, lets fn decide the new state (or none), and records it.
func (s *Store) changePlacement(ctx context.Context, app App, tenantID uuid.UUID,
	fn func(tx pgx.Tx, p Placement) (state, event string, err error)) (Placement, error) {
	var out Placement
	err := s.tx(ctx, Scope{TenantID: tenantID, Operator: true}, func(tx pgx.Tx) error {
		p, err := scanPlacement(tx.QueryRow(ctx, `SELECT `+placementCols+` FROM placement
			WHERE tenant_id = $1 AND app_id = $2 FOR UPDATE`, tenantID, app.ID))
		if err != nil {
			return err
		}
		state, event, err := fn(tx, p)
		if err != nil || state == "" {
			out = p
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanPlacement(tx.QueryRow(ctx, `UPDATE placement SET state = $2, error = NULL, version = $3,
			updated_at = now() WHERE id = $1 RETURNING `+placementCols, p.ID, state, v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, tenantID, event, placementSubject(out, app.Slug), out)
	})
	return out, err
}

func stateErr(p Placement, want string) error {
	return fmt.Errorf("%w: the placement is %s; this needs it to be %s", ErrConflict, p.State, want)
}

// AppStorage is what an app-managed placement says about where it keeps the tenant's data.
type AppStorage struct {
	LocationLabel string `json:"location_label"`
	DatabaseName  string `json:"database_name,omitempty"`
	SchemaName    string `json:"schema_name,omitempty"`
}

// RegisterPlacement records storage an app created itself (manager: app) and marks it provisioned.
func (s *Store) RegisterPlacement(ctx context.Context, app App, tenantID uuid.UUID, in AppStorage) (Placement, error) {
	if in.LocationLabel == "" || len(in.LocationLabel) > 200 {
		return Placement{}, invalid("location_label is required (at most 200 characters), e.g. \"eu-west-1 / prod-db\"")
	}
	return s.changePlacement(ctx, app, tenantID, func(tx pgx.Tx, p Placement) (string, string, error) {
		if p.Manager != "app" {
			return "", "", fmt.Errorf("%w: Matura manages this tenant's storage; ask for credentials instead", ErrConflict)
		}
		switch p.State {
		case "requested", "provisioned", "failed", "ready":
		default:
			return "", "", stateErr(p, "requested, provisioned or ready")
		}
		if _, err := tx.Exec(ctx, `UPDATE placement SET location_label = $2, database_name = $3, schema_name = $4
			WHERE id = $1`, p.ID, in.LocationLabel, nullable(in.DatabaseName), nullable(in.SchemaName)); err != nil {
			return "", "", err
		}
		if p.State == "ready" { // moved within the app's own storage: stays ready, the change is still an event
			return "ready", "placement.ready", nil
		}
		return "provisioned", "placement.provisioned", nil
	})
}

// PlacementReady records that the app migrated the tenant's storage and serves it.
func (s *Store) PlacementReady(ctx context.Context, app App, tenantID uuid.UUID) (Placement, error) {
	return s.changePlacement(ctx, app, tenantID, func(_ pgx.Tx, p Placement) (string, string, error) {
		switch p.State {
		case "ready":
			return "", "", nil
		case "provisioned", "migrating":
			return "ready", "placement.ready", nil
		}
		return "", "", stateErr(p, "provisioned")
	})
}

// PlacementDataDeleted records that the app deleted a retiring tenant's data. App-managed storage is then gone;
// platform-managed storage is dropped by the provisioner, which marks it deleted.
func (s *Store) PlacementDataDeleted(ctx context.Context, app App, tenantID uuid.UUID) (Placement, error) {
	return s.changePlacement(ctx, app, tenantID, func(tx pgx.Tx, p Placement) (string, string, error) {
		switch {
		case p.State == "deleted":
			return "", "", nil
		case p.State != "retiring":
			return "", "", stateErr(p, "retiring (the tenant is being deleted)")
		case p.Manager == "app":
			return "deleted", "placement.deleted", nil
		}
		_, err := tx.Exec(ctx, `UPDATE placement SET data_deleted_at = coalesce(data_deleted_at, now()),
			next_attempt_at = now() WHERE id = $1`, p.ID)
		return "", "", err
	})
}

// retirePlacements starts deleting a tenant's storage for every app (tenant.deleting).
func retirePlacements(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT `+placementCols+` FROM placement
		WHERE tenant_id = $1 AND state NOT IN ('retiring', 'deleted') FOR UPDATE`, tenantID)
	if err != nil {
		return err
	}
	ps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Placement, error) { return scanPlacement(r) })
	if err != nil {
		return err
	}
	for _, p := range ps {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		var slug string
		if err := tx.QueryRow(ctx, `SELECT slug FROM app WHERE id = $1`, p.AppID).Scan(&slug); err != nil {
			return err
		}
		out, err := scanPlacement(tx.QueryRow(ctx, `UPDATE placement SET state = 'retiring', version = $2,
			updated_at = now() WHERE id = $1 RETURNING `+placementCols, p.ID, v))
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, v, tenantID, "placement.retiring", placementSubject(out, slug), out); err != nil {
			return err
		}
	}
	return nil
}

// Credentials connect an app to a platform-managed placement (technical specification §7.4).
type Credentials struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SSLMode    string    `json:"sslmode"`
	Database   string    `json:"database"`
	User       string    `json:"user"`
	Password   string    `json:"password"`
	SearchPath string    `json:"search_path,omitempty"`
	Mode       string    `json:"mode"`
	ExpiresAt  time.Time `json:"expires_at"` // ask again after this
}

// PlacementCredentials returns the runtime credentials of a platform-managed placement, or with migrate the role
// that owns the tables (the same role except in shared mode).
func (s *Store) PlacementCredentials(ctx context.Context, km secrets.KeyManager, app App, tenantID uuid.UUID,
	migrate bool) (Credentials, error) {
	var c Credentials
	var p Placement
	var role, owner *string
	var sealed, ownerSealed []byte
	err := s.tx(ctx, Scope{TenantID: tenantID, Operator: true}, func(tx pgx.Tx) error {
		var err error
		p, err = scanPlacement(tx.QueryRow(ctx, `SELECT `+placementCols+` FROM placement
			WHERE tenant_id = $1 AND app_id = $2`, tenantID, app.ID))
		if err != nil {
			return err
		}
		if p.Manager != "platform" {
			return fmt.Errorf("%w: the app manages this tenant's storage itself", ErrConflict)
		}
		switch p.State {
		case "provisioned", "migrating", "ready":
		default:
			return stateErr(p, "provisioned or ready")
		}
		return tx.QueryRow(ctx, `SELECT s.host, s.port, s.sslmode, p.role_name, p.role_secret, p.owner_role_name,
				p.owner_role_secret
			FROM placement p JOIN db_server s ON s.id = p.db_server_id WHERE p.id = $1`, p.ID).
			Scan(&c.Host, &c.Port, &c.SSLMode, &role, &sealed, &owner, &ownerSealed)
	})
	if err != nil {
		return Credentials{}, err
	}
	purpose := "runtime"
	if migrate && owner != nil {
		role, sealed, purpose = owner, ownerSealed, "owner"
	}
	if role == nil || sealed == nil || p.DatabaseName == nil {
		return Credentials{}, fmt.Errorf("placement %s has no stored credentials", p.ID)
	}
	pw, err := km.Open(sealed, placementAAD(p.ID, purpose))
	if err != nil {
		return Credentials{}, err
	}
	c.Database, c.User, c.Password, c.Mode = *p.DatabaseName, *role, string(pw), p.Mode
	if p.SchemaName != nil {
		c.SearchPath = *p.SchemaName
	}
	c.ExpiresAt = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	return c, nil
}

// --- the provisioner's side ------------------------------------------------------------------------------------------

// PlacementJob is a platform-managed placement that needs work: provisioning (Retire false) or dropping (Retire true).
type PlacementJob struct {
	Placement
	AppSlug    string
	TenantSlug string
	Attempts   int
	Retire     bool
	// for Retire: what was created
	RoleName      *string
	OwnerRoleName *string
}

// NextPlacementJob returns the next platform-managed placement due for provisioning or dropping, or ErrNotFound.
func (s *Store) NextPlacementJob(ctx context.Context) (PlacementJob, error) {
	var j PlacementJob
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT p.id, p.tenant_id, p.app_id, p.mode, p.manager, p.db_server_id,
				p.database_name, p.schema_name, p.location_label, p.state, p.error, p.version,
				a.slug, t.slug, p.attempts, p.state = 'retiring', p.role_name, p.owner_role_name
			FROM placement p JOIN app a ON a.id = p.app_id JOIN tenant t ON t.id = p.tenant_id
			WHERE p.manager = 'platform' AND p.next_attempt_at <= now()
			  AND (p.state IN ('requested', 'failed') OR (p.state = 'retiring' AND p.data_deleted_at IS NOT NULL))
			ORDER BY p.next_attempt_at LIMIT 1`)
		return mapErr(row.Scan(&j.ID, &j.TenantID, &j.AppID, &j.Mode, &j.Manager, &j.DBServerID, &j.DatabaseName,
			&j.SchemaName, &j.LocationLabel, &j.State, &j.Error, &j.Version, &j.AppSlug, &j.TenantSlug, &j.Attempts,
			&j.Retire, &j.RoleName, &j.OwnerRoleName))
	})
	return j, err
}

// PickDBServer chooses where a new placement goes: for shared mode the server already holding the app's shared
// database, else the active, non-dedicated server with the fewest placements.
func (s *Store) PickDBServer(ctx context.Context, appID uuid.UUID, mode string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		if mode == "shared" {
			err := tx.QueryRow(ctx, `SELECT p.db_server_id FROM placement p JOIN db_server s ON s.id = p.db_server_id
				WHERE p.app_id = $1 AND p.mode = 'shared' AND p.manager = 'platform' AND s.status = 'active'
				ORDER BY p.created_at LIMIT 1`, appID).Scan(&id)
			if err == nil {
				return nil
			}
			if err != pgx.ErrNoRows {
				return err
			}
		}
		err := tx.QueryRow(ctx, `SELECT s.id FROM db_server s
			WHERE s.status = 'active' AND NOT s.dedicated
			ORDER BY (SELECT count(*) FROM placement p WHERE p.db_server_id = s.id AND p.state <> 'deleted'), s.name
			LIMIT 1`).Scan(&id)
		if err == pgx.ErrNoRows {
			return invalid("no active database server is registered; an operator adds one at /admin/v1/db-servers")
		}
		return err
	})
	return id, err
}

// Provisioned is what the provisioner created for a placement.
type Provisioned struct {
	DBServerID              uuid.UUID
	Database, Schema, Label string
	Role, Owner             string
	RolePassword            string
	OwnerPassword           string
}

// PlacementProvisioned stores what was created (passwords sealed) and marks the placement provisioned.
func (s *Store) PlacementProvisioned(ctx context.Context, km secrets.KeyManager, j PlacementJob, in Provisioned) error {
	km = s.forTenant(km, j.TenantID)
	sealed, err := km.Seal([]byte(in.RolePassword), placementAAD(j.ID, "runtime"))
	if err != nil {
		return err
	}
	var owner any
	var ownerSealed []byte
	if in.Owner != "" {
		owner = in.Owner
		if ownerSealed, err = km.Seal([]byte(in.OwnerPassword), placementAAD(j.ID, "owner")); err != nil {
			return err
		}
	}
	return s.tx(ctx, Scope{TenantID: j.TenantID, Operator: true}, func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err := scanPlacement(tx.QueryRow(ctx, `UPDATE placement SET state = 'provisioned', error = NULL,
				db_server_id = $2, database_name = $3, schema_name = $4, role_name = $5, role_secret = $6,
				owner_role_name = $7, owner_role_secret = $8, location_label = $9, attempts = 0, version = $10,
				updated_at = now()
			WHERE id = $1 AND state IN ('requested', 'failed') RETURNING `+placementCols,
			j.ID, in.DBServerID, in.Database, nullable(in.Schema), in.Role, sealed, owner, ownerSealed, in.Label, v))
		if err != nil {
			return err // ErrNotFound: the tenant started deleting meanwhile; the next round drops it
		}
		return emit(ctx, tx, v, j.TenantID, "placement.provisioned", placementSubject(out, j.AppSlug), out)
	})
}

// PlacementDropped marks a retired placement's storage as gone.
func (s *Store) PlacementDropped(ctx context.Context, j PlacementJob) error {
	return s.tx(ctx, Scope{TenantID: j.TenantID, Operator: true}, func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err := scanPlacement(tx.QueryRow(ctx, `UPDATE placement SET state = 'deleted', error = NULL,
				role_secret = NULL, owner_role_secret = NULL, attempts = 0, version = $2, updated_at = now()
			WHERE id = $1 AND state = 'retiring' RETURNING `+placementCols, j.ID, v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, j.TenantID, "placement.deleted", placementSubject(out, j.AppSlug), out)
	})
}

// PlacementFailed records a failed step and when to try again (1 min doubling to 1 h). Provisioning failures show
// as state failed; a failed drop stays retiring with the error.
func (s *Store) PlacementFailed(ctx context.Context, j PlacementJob, cause error) error {
	wait := time.Minute << min(j.Attempts, 6)
	msg := cause.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return s.tx(ctx, Scope{TenantID: j.TenantID, Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE placement SET error = $2, attempts = attempts + 1,
				next_attempt_at = now() + $3::interval,
				state = CASE WHEN state = 'requested' THEN 'failed' ELSE state END
			WHERE id = $1`, j.ID, msg, fmt.Sprintf("%d seconds", int(min(wait, time.Hour).Seconds())))
		return err
	})
}
