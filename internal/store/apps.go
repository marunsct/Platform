package store

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

const appCols = `id, slug, name, client_id, manifest, status, version`

func scanApp(row pgx.Row) (App, error) {
	var a App
	var raw []byte
	if err := row.Scan(&a.ID, &a.Slug, &a.Name, &a.ClientID, &raw, &a.Status, &a.Version); err != nil {
		return a, mapErr(err)
	}
	return a, json.Unmarshal(raw, &a.Manifest)
}

// ApplyApp registers an app or updates it from its manifest (RL-1). Applying the same manifest twice changes
// nothing; roles created or edited in Matura are never overwritten (RL-10, see syncManifestRoles).
func (s *Store) ApplyApp(ctx context.Context, sc Scope, m Manifest) (App, bool, error) {
	if err := m.Normalize(); err != nil {
		return App{}, false, err
	}
	var out App
	changed := false
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		cur, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE slug = $1 FOR UPDATE`, m.Slug))
		if err != nil && err != ErrNotFound {
			return err
		}
		if err == nil {
			a, _ := json.Marshal(cur.Manifest)
			b, _ := json.Marshal(m)
			if string(a) == string(b) {
				out = cur
				return nil
			}
		}
		changed = true
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(m)
		id := cur.ID
		if id == uuid.Nil {
			id = ids.New()
		}
		out, err = scanApp(tx.QueryRow(ctx, `INSERT INTO app (id, slug, name, client_id, manifest, status, version)
			VALUES ($1, $2, $3, $4, $5, 'active', $6)
			ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, client_id = EXCLUDED.client_id,
				manifest = EXCLUDED.manifest, version = EXCLUDED.version, updated_at = now()
			RETURNING `+appCols, id, m.Slug, m.Name, m.ClientID, body, v))
		if err != nil {
			return err
		}
		if err := syncManifestRoles(ctx, tx, out, m, v); err != nil {
			return err
		}
		return emit(ctx, tx, v, uuid.Nil, "app.manifest.updated", "apps/"+m.Slug, out)
	})
	return out, changed, err
}

func (s *Store) ListApps(ctx context.Context) ([]App, error) {
	var out []App
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+appCols+` FROM app WHERE status = 'active' ORDER BY slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (App, error) { return scanApp(r) })
		return err
	})
	return out, err
}

func getAppBySlug(ctx context.Context, tx pgx.Tx, slug string) (App, error) {
	return scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE slug = $1 AND status = 'active'`, slug))
}

func (s *Store) GetApp(ctx context.Context, slug string) (App, error) {
	var out App
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		var err error
		out, err = getAppBySlug(ctx, tx, slug)
		return err
	})
	return out, err
}

const placementCols = `id, tenant_id, app_id, mode, manager, location_label, state, version`

func scanPlacement(row pgx.Row) (Placement, error) {
	var p Placement
	err := row.Scan(&p.ID, &p.TenantID, &p.AppID, &p.Mode, &p.Manager, &p.LocationLabel, &p.State, &p.Version)
	return p, mapErr(err)
}

// choosePlacement picks the data mode for a tenant enabling an app (DP-3): the plan's required mode, else the
// tenant's default if the app supports it, else the app's default.
func choosePlacement(ctx context.Context, tx pgx.Tx, t Tenant, m Manifest) (mode, manager string, err error) {
	manager = m.Tenancy.Default.Manager
	if t.Plan != nil {
		var required *string
		err := tx.QueryRow(ctx, `SELECT data_mode_required FROM plan WHERE id = $1`, *t.Plan).Scan(&required)
		if err != nil && mapErr(err) != ErrNotFound {
			return "", "", err
		}
		if required != nil {
			if !slices.Contains(m.Tenancy.Modes, *required) {
				return "", "", invalid("the tenant's plan requires %s data placement, which %s does not support",
					*required, m.Slug)
			}
			return *required, manager, nil
		}
	}
	if slices.Contains(m.Tenancy.Modes, t.DataModeDefault) {
		return t.DataModeDefault, manager, nil
	}
	return m.Tenancy.Default.Mode, manager, nil
}

// EnableApp turns an app on for a tenant and records where the tenant's data will live (placement "requested";
// provisioning is TS7b).
func (s *Store) EnableApp(ctx context.Context, sc Scope, tenantID uuid.UUID, appSlug string) (TenantApp, error) {
	var out TenantApp
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		t, err := scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1`, tenantID))
		if err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO tenant_app (tenant_id, app_id, status, version)
			VALUES ($1, $2, 'enabled', $3)
			ON CONFLICT (tenant_id, app_id) DO UPDATE SET status = 'enabled', version = EXCLUDED.version,
				updated_at = now()
			RETURNING tenant_id, app_id, status, version`, tenantID, app.ID, v).
			Scan(&out.TenantID, &out.AppID, &out.Status, &out.Version); err != nil {
			return mapErr(err)
		}
		out.AppSlug = app.Slug
		subject := "tenants/" + tenantID.String() + "/apps/" + app.Slug
		if err := emit(ctx, tx, v, tenantID, "tenant_app.enabled", subject, out); err != nil {
			return err
		}
		p, err := scanPlacement(tx.QueryRow(ctx, `SELECT `+placementCols+` FROM placement
			WHERE tenant_id = $1 AND app_id = $2`, tenantID, app.ID))
		switch {
		case err == nil && p.State != "deleted":
			out.Placement = &p
			return nil
		case err != nil && err != ErrNotFound:
			return err
		}
		mode, manager, err := choosePlacement(ctx, tx, t, app.Manifest)
		if err != nil {
			return err
		}
		pv, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		p, err = scanPlacement(tx.QueryRow(ctx, `INSERT INTO placement (id, tenant_id, app_id, mode, manager, state, version)
			VALUES ($1, $2, $3, $4, $5, 'requested', $6)
			ON CONFLICT (tenant_id, app_id) DO UPDATE SET mode = EXCLUDED.mode, manager = EXCLUDED.manager,
				state = 'requested', db_server_id = NULL, database_name = NULL, schema_name = NULL, role_name = NULL,
				role_secret = NULL, location_label = NULL, error = NULL, version = EXCLUDED.version, updated_at = now()
			RETURNING `+placementCols, ids.New(), tenantID, app.ID, mode, manager, pv))
		if err != nil {
			return err
		}
		out.Placement = &p
		return emit(ctx, tx, pv, tenantID, "placement.requested", subject+"/placement", p)
	})
	return out, err
}

func (s *Store) DisableApp(ctx context.Context, sc Scope, tenantID uuid.UUID, appSlug string) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE tenant_app SET status = 'disabled', version = $3, updated_at = now()
			WHERE tenant_id = $1 AND app_id = $2 AND status = 'enabled'`, tenantID, app.ID, v)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		// the placement and its data stay: disabling is reversible, deleting the tenant removes data (TN-5)
		return emit(ctx, tx, v, tenantID, "tenant_app.disabled", "tenants/"+tenantID.String()+"/apps/"+app.Slug,
			map[string]any{"tenant_id": tenantID, "app_id": app.ID, "app": app.Slug, "version": v})
	})
}

func (s *Store) ListTenantApps(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]TenantApp, error) {
	var out []TenantApp
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT ta.tenant_id, ta.app_id, a.slug, ta.status, ta.version,
				p.id, p.tenant_id, p.app_id, p.mode, p.manager, p.location_label, p.state, p.version
			FROM tenant_app ta JOIN app a ON a.id = ta.app_id
			LEFT JOIN placement p ON p.tenant_id = ta.tenant_id AND p.app_id = ta.app_id
			WHERE ta.tenant_id = $1 ORDER BY a.slug`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TenantApp, error) {
			var ta TenantApp
			var p struct {
				ID, TenantID, AppID  *uuid.UUID
				Mode, Manager, State *string
				Label                *string
				Version              *int64
			}
			if err := r.Scan(&ta.TenantID, &ta.AppID, &ta.AppSlug, &ta.Status, &ta.Version,
				&p.ID, &p.TenantID, &p.AppID, &p.Mode, &p.Manager, &p.Label, &p.State, &p.Version); err != nil {
				return ta, err
			}
			if p.ID != nil {
				ta.Placement = &Placement{ID: *p.ID, TenantID: *p.TenantID, AppID: *p.AppID, Mode: *p.Mode,
					Manager: *p.Manager, LocationLabel: p.Label, State: *p.State, Version: *p.Version}
			}
			return ta, nil
		})
		return err
	})
	return out, err
}

// rawManifest scans a jsonb manifest column into a Manifest.
type rawManifest struct{ m *Manifest }

func (r rawManifest) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, r.m)
	case string:
		return json.Unmarshal([]byte(v), r.m)
	}
	return invalid("manifest column has an unexpected type")
}
