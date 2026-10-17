package store

import (
	"context"
	"slices"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxPermsInToken is where the token switches from `perms` to `perms_ref` (contract §2).
const MaxPermsInToken = 40

// TokenRequest is what Keycloak's mapper sends when it issues a token for a user and an app's client.
type TokenRequest struct {
	User      UserProfile
	ClientID  string
	Tenant    string // slug or id; empty means the tenant used last, else the first one
	Workspace string // id; empty means the tenant's default workspace
}

// TokenContext is the Matura part of an access token (contract §2).
type TokenContext struct {
	TenantID    *uuid.UUID       `json:"tid,omitempty"`
	TenantSlug  string           `json:"tenant,omitempty"`
	WorkspaceID *uuid.UUID       `json:"wid,omitempty"`
	TenantRoles []string         `json:"troles"`
	Roles       []string         `json:"roles"`
	Perms       []string         `json:"perms,omitempty"`
	PermsRef    string           `json:"perms_ref,omitempty"`
	Versions    map[string]int64 `json:"ver"`
	PlaceMode   string           `json:"pmode,omitempty"`
}

// TokenRefusal says why no token may be issued; Code becomes the OAuth error description.
type TokenRefusal struct{ Code, Msg string }

func (e *TokenRefusal) Error() string { return e.Msg }

func refuse(code, msg string) error { return &TokenRefusal{Code: code, Msg: msg} }

// TokenContextFor works out the claims for a token, recording the user on first sight and remembering the tenant
// they chose. It refuses inactive users, tenants the user does not belong to, inactive tenants and tenants that
// have not enabled the app (RL-2).
func (s *Store) TokenContextFor(ctx context.Context, req TokenRequest) (TokenContext, error) {
	u, err := s.UpsertUser(ctx, req.User)
	if err != nil {
		return TokenContext{}, err
	}
	if u.Status != "active" {
		return TokenContext{}, refuse("user_inactive", "this account is deactivated")
	}
	out := TokenContext{TenantRoles: []string{}, Roles: []string{}, Versions: map[string]int64{"u": u.Version}}
	err = s.tx(ctx, Scope{UserID: u.ID}, func(tx pgx.Tx) error {
		app, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE client_id = $1`, req.ClientID))
		if err == ErrNotFound || (err == nil && app.Status != "active") {
			return refuse("unknown_client", "no active app uses this client id")
		}
		if err != nil {
			return err
		}
		t, m, err := chooseTenant(ctx, tx, u.ID, req.Tenant)
		if err != nil || t == nil {
			return err // no tenant yet: a token without tid, for onboarding
		}
		if err := setTenant(ctx, tx, t.ID); err != nil {
			return err
		}
		switch t.Status {
		case "active":
		case "suspended":
			return refuse("tenant_suspended", "this organisation is suspended")
		default:
			return refuse("tenant_inactive", "this organisation is not available")
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_app WHERE tenant_id = $1 AND app_id = $2
			AND status = 'enabled')`, t.ID, app.ID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return refuse("app_not_enabled", "this organisation has not enabled "+app.Name)
		}
		wid, err := chooseWorkspace(ctx, tx, t.ID, req.Workspace)
		if err != nil {
			return err
		}
		roles, err := rolesFor(ctx, tx, app, t.ID, u.ID, m.TenantRole, wid)
		if err != nil {
			return err
		}
		perms, err := permsOf(ctx, tx, app.ID, roles)
		if err != nil {
			return err
		}
		var mode *string
		if err := tx.QueryRow(ctx, `SELECT mode FROM placement WHERE tenant_id = $1 AND app_id = $2`, t.ID, app.ID).
			Scan(&mode); err != nil && mapErr(err) != ErrNotFound {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app_user SET last_tenant_id = $2 WHERE id = $1
			AND last_tenant_id IS DISTINCT FROM $2`, u.ID, t.ID); err != nil {
			return err
		}
		out.TenantID, out.TenantSlug, out.TenantRoles, out.Roles = &t.ID, t.Slug, []string{m.TenantRole}, roles
		if wid != uuid.Nil {
			out.WorkspaceID = &wid
		}
		if len(perms) > MaxPermsInToken {
			out.PermsRef = "matura_app_role"
		} else {
			out.Perms = perms
		}
		out.Versions["m"], out.Versions["t"] = m.Version, t.Version
		if mode != nil {
			out.PlaceMode = *mode
		}
		return nil
	})
	return out, err
}

// chooseTenant picks the tenant named in the request, else the last used, else the first by name. A tenant the
// user is not an active member of is refused when named, and skipped otherwise.
func chooseTenant(ctx context.Context, tx pgx.Tx, userID uuid.UUID, want string) (*Tenant, Membership, error) {
	q := `SELECT t.id, t.slug, t.name, t.kind, t.status, t.plan, t.data_mode_default, t.version, t.created_at,
			t.updated_at, m.tenant_role, m.version
		FROM membership m JOIN tenant t ON t.id = m.tenant_id
		WHERE m.user_id = $1 AND m.status = 'active' AND t.status <> 'deleted'`
	var args = []any{userID}
	switch {
	case want != "":
		if id, err := uuid.Parse(want); err == nil {
			q += ` AND t.id = $2`
			args = append(args, id)
		} else {
			q += ` AND t.slug = $2`
			args = append(args, want)
		}
	default:
		q += ` ORDER BY (t.id = (SELECT last_tenant_id FROM app_user WHERE id = $1)) DESC NULLS LAST,
			(t.status = 'active') DESC, t.name`
	}
	q += ` LIMIT 1`
	var t Tenant
	var m Membership
	err := tx.QueryRow(ctx, q, args...).Scan(&t.ID, &t.Slug, &t.Name, &t.Kind, &t.Status, &t.Plan, &t.DataModeDefault,
		&t.Version, &t.CreatedAt, &t.UpdatedAt, &m.TenantRole, &m.Version)
	if err == pgx.ErrNoRows {
		if want != "" {
			return nil, m, refuse("not_a_member", "you are not a member of this organisation")
		}
		return nil, m, nil
	}
	if err != nil {
		return nil, m, err
	}
	return &t, m, nil
}

func chooseWorkspace(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, want string) (uuid.UUID, error) {
	var id uuid.UUID
	if want != "" {
		wid, err := uuid.Parse(want)
		if err != nil {
			return uuid.Nil, refuse("unknown_workspace", "no such workspace in this organisation")
		}
		err = tx.QueryRow(ctx, `SELECT id FROM workspace WHERE tenant_id = $1 AND id = $2 AND status = 'active'`,
			tenantID, wid).Scan(&id)
		if err == pgx.ErrNoRows {
			return uuid.Nil, refuse("unknown_workspace", "no such workspace in this organisation")
		}
		return id, err
	}
	err := tx.QueryRow(ctx, `SELECT id FROM workspace WHERE tenant_id = $1 AND is_default`, tenantID).Scan(&id)
	if err == pgx.ErrNoRows {
		return uuid.Nil, nil
	}
	return id, err
}

// rolesFor returns the user's roles for the app in the tenant: active grants for the whole tenant or the chosen
// workspace, plus the manifest's owner role for tenant owners and admins (RL-5).
func rolesFor(ctx context.Context, tx pgx.Tx, app App, tenantID, userID uuid.UUID, tenantRole string, wid uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT role FROM role_grant WHERE tenant_id = $1 AND app_id = $2
		AND subject_type = 'user' AND subject_id = $3 AND status = 'active'
		AND (workspace_id IS NULL OR workspace_id = $4)`, tenantID, app.ID, userID, wid)
	if err != nil {
		return nil, err
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if app.Manifest.OwnerRole != "" && (tenantRole == "owner" || tenantRole == "admin") &&
		!slices.Contains(roles, app.Manifest.OwnerRole) {
		roles = append(roles, app.Manifest.OwnerRole)
	}
	sort.Strings(roles)
	return roles, nil
}

// permsOf expands roles into the sorted union of their permissions; any "*" makes it ["*"] (technical spec §6).
func permsOf(ctx context.Context, tx pgx.Tx, appID uuid.UUID, roles []string) ([]string, error) {
	if len(roles) == 0 {
		return []string{}, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT unnest(permissions) FROM app_role WHERE app_id = $1 AND name = ANY($2)`,
		appID, roles)
	if err != nil {
		return nil, err
	}
	perms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if slices.Contains(perms, "*") {
		return []string{"*"}, nil
	}
	sort.Strings(perms)
	return perms, nil
}
