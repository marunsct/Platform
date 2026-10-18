package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

const grantCols = `g.id, g.tenant_id, g.app_id, a.slug, g.workspace_id, g.subject_type, g.subject_id, g.role, g.status,
	g.version`

func scanGrant(row pgx.Row) (Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.TenantID, &g.AppID, &g.AppSlug, &g.WorkspaceID, &g.SubjectType, &g.SubjectID, &g.Role,
		&g.Status, &g.Version)
	return g, mapErr(err)
}

func grantSubject(g Grant) string {
	return "tenants/" + g.TenantID.String() + "/grants/" + g.ID.String()
}

type NewGrant struct {
	App         string
	UserID      uuid.UUID
	Role        string
	WorkspaceID *uuid.UUID // nil: the whole tenant
}

// CreateGrant gives an active member an app role (RL-3). The app must be enabled for the tenant, the role must be
// one of the app's, and a workspace must belong to the tenant (composite foreign key).
func (s *Store) CreateGrant(ctx context.Context, sc Scope, tenantID uuid.UUID, in NewGrant) (Grant, error) {
	var out Grant
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		out, err = createGrant(ctx, tx, tenantID, in)
		return err
	})
	return out, err
}

func createGrant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in NewGrant) (Grant, error) {
	var out Grant
	err := func() error {
		app, err := getAppBySlug(ctx, tx, in.App)
		if err != nil {
			if err == ErrNotFound {
				return invalid("app %q does not exist", in.App)
			}
			return err
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_app WHERE tenant_id = $1 AND app_id = $2
			AND status = 'enabled')`, tenantID, app.ID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return invalid("enable %s for this tenant before granting its roles", app.Slug)
		}
		m, err := getMember(ctx, tx, tenantID, in.UserID, false)
		if err != nil || m.Status != "active" {
			return invalid("the user is not an active member of this tenant")
		}
		var known bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_role WHERE app_id = $1 AND name = $2)`,
			app.ID, in.Role).Scan(&known); err != nil {
			return err
		}
		if !known {
			return invalid("%s has no role %q", app.Slug, in.Role)
		}
		if in.WorkspaceID != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace WHERE tenant_id = $1 AND id = $2
				AND status = 'active')`, tenantID, *in.WorkspaceID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return invalid("workspace does not exist in this tenant")
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO role_grant (id, tenant_id, app_id, workspace_id, subject_type, subject_id,
			role, status, version) VALUES ($1, $2, $3, $4, 'user', $5, $6, 'active', $7)`,
			id, tenantID, app.ID, in.WorkspaceID, in.UserID, in.Role, v); err != nil {
			return mapErr(err)
		}
		if out, err = getGrant(ctx, tx, tenantID, id); err != nil {
			return err
		}
		return emit(ctx, tx, v, tenantID, "grant.added", grantSubject(out), out)
	}()
	return out, err
}

// grantDefaults gives a new member each enabled app's default role for the whole tenant (RL-4), except apps in
// skip (an invitation that named roles for them) and apps where the member already has an active grant.
func grantDefaults(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, skip map[string]bool) error {
	rows, err := tx.Query(ctx, `SELECT a.slug, r.name FROM tenant_app ta
		JOIN app a ON a.id = ta.app_id AND a.status = 'active'
		JOIN app_role r ON r.app_id = a.id AND r.is_default
		WHERE ta.tenant_id = $1 AND ta.status = 'enabled'
		  AND NOT EXISTS (SELECT 1 FROM role_grant g WHERE g.tenant_id = $1 AND g.app_id = a.id
		                  AND g.subject_type = 'user' AND g.subject_id = $2 AND g.status = 'active')
		ORDER BY a.slug`, tenantID, userID)
	if err != nil {
		return err
	}
	type def struct{ app, role string }
	defs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (def, error) {
		var d def
		return d, r.Scan(&d.app, &d.role)
	})
	if err != nil {
		return err
	}
	for _, d := range defs {
		if skip[d.app] {
			continue
		}
		if _, err := createGrant(ctx, tx, tenantID, NewGrant{App: d.app, UserID: userID, Role: d.role}); err != nil {
			return err
		}
	}
	return nil
}

func getGrant(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (Grant, error) {
	return scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
		WHERE g.tenant_id = $1 AND g.id = $2`, tenantID, id))
}

type GrantFilter struct {
	App    string
	UserID uuid.UUID
}

func (s *Store) ListGrants(ctx context.Context, sc Scope, tenantID uuid.UUID, f GrantFilter) ([]Grant, error) {
	var out []Grant
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var user any
		if f.UserID != uuid.Nil {
			user = f.UserID
		}
		rows, err := tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
			WHERE g.tenant_id = $1 AND g.status = 'active' AND ($2 = '' OR a.slug = $2)
			  AND ($3::uuid IS NULL OR g.subject_id = $3) ORDER BY a.slug, g.role, g.id`, tenantID, f.App, user)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
		return err
	})
	return out, err
}

func revokeGrant(ctx context.Context, tx pgx.Tx, g Grant) error {
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE role_grant SET status = 'revoked', version = $3, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, g.TenantID, g.ID, v); err != nil {
		return err
	}
	g.Status, g.Version = "revoked", v
	return emit(ctx, tx, v, g.TenantID, "grant.revoked", grantSubject(g), g)
}

func (s *Store) RevokeGrant(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		g, err := getGrant(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		if g.Status != "active" {
			return ErrNotFound
		}
		return revokeGrant(ctx, tx, g)
	})
}

func revokeGrantsOf(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
		WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.subject_id = $2 AND g.status = 'active'`,
		tenantID, userID)
	if err != nil {
		return err
	}
	grants, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
	if err != nil {
		return err
	}
	for _, g := range grants {
		if err := revokeGrant(ctx, tx, g); err != nil {
			return err
		}
	}
	return nil
}
