package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

const tenantCols = `id, slug, name, kind, status, plan, data_mode_default, status_reason, purge_after, support_access, version, created_at, updated_at`

// tenantColsOf is tenantCols qualified with a table alias, for joins.
func tenantColsOf(alias string) string {
	cols := strings.Split(tenantCols, ", ")
	for i, c := range cols {
		cols[i] = alias + "." + c
	}
	return strings.Join(cols, ", ")
}

func tenantDest(t *Tenant) []any {
	return []any{&t.ID, &t.Slug, &t.Name, &t.Kind, &t.Status, &t.Plan, &t.DataModeDefault, &t.StatusReason,
		&t.PurgeAfter, &t.SupportAccess, &t.Version, &t.CreatedAt, &t.UpdatedAt}
}

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(tenantDest(&t)...)
	return t, mapErr(err)
}

const workspaceCols = `id, tenant_id, name, status, is_default, version, updated_at`

func scanWorkspace(row pgx.Row) (Workspace, error) {
	var w Workspace
	err := row.Scan(&w.ID, &w.TenantID, &w.Name, &w.Status, &w.IsDefault, &w.Version, &w.UpdatedAt)
	return w, mapErr(err)
}

type NewTenant struct {
	Slug string
	Name string
	Kind string // company (default), shared or personal
	Plan string
}

// CreateTenant creates the tenant, its default workspace and the owner's membership in one transaction.
func (s *Store) CreateTenant(ctx context.Context, sc Scope, in NewTenant, ownerID uuid.UUID) (Tenant, error) {
	if !ids.ValidSlug(in.Slug) {
		return Tenant{}, invalid("slug %q must be 3-40 lower-case letters, digits or inner hyphens, and not reserved", in.Slug)
	}
	if in.Name == "" {
		return Tenant{}, invalid("name is required")
	}
	if in.Kind == "" {
		in.Kind = "company"
	}
	var out Tenant
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		id := ids.New()
		if err := setTenant(ctx, tx, id); err != nil {
			return err
		}
		mode := "shared"
		if in.Plan != "" {
			if err := tx.QueryRow(ctx, `SELECT coalesce(data_mode_required, data_mode_default) FROM plan WHERE id = $1`,
				in.Plan).Scan(&mode); err != nil {
				if mapErr(err) == ErrNotFound {
					return invalid("plan %q does not exist", in.Plan)
				}
				return err
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanTenant(tx.QueryRow(ctx, `INSERT INTO tenant (id, slug, name, kind, status, plan,
			data_mode_default, version) VALUES ($1, $2, $3, $4, 'active', $5, $6, $7) RETURNING `+tenantCols,
			id, in.Slug, in.Name, in.Kind, nullable(in.Plan), mode, v))
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, v, id, "tenant.created", "tenants/"+id.String(), out.Contract()); err != nil {
			return err
		}
		if _, err := createWorkspace(ctx, tx, id, "Default", true); err != nil {
			return err
		}
		_, err = addMember(ctx, tx, id, ownerID, "owner", false)
		return err
	})
	return out, err
}

// ListTenants returns what row-level security lets the scope see: the user's tenants, or all for operators.
func (s *Store) ListTenants(ctx context.Context, sc Scope) ([]Tenant, error) {
	var out []Tenant
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tenantCols+` FROM tenant WHERE status <> 'deleted' ORDER BY slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Tenant, error) { return scanTenant(r) })
		return err
	})
	return out, err
}

func (s *Store) GetTenant(ctx context.Context, sc Scope, id uuid.UUID) (Tenant, error) {
	var out Tenant
	err := s.tx(ctx, sc.InTenant(id), func(tx pgx.Tx) error {
		var err error
		out, err = scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1`, id))
		return err
	})
	return out, err
}

type TenantPatch struct {
	Name          *string
	Plan          *string // operators only; the API layer checks
	SupportAccess *string // approval, allowed or off; owners and operators
}

// UpdateTenant applies a patch. ifVersion, when non-zero, must equal the stored version (If-Match). Status changes
// go through ChangeTenantStatus.
func (s *Store) UpdateTenant(ctx context.Context, sc Scope, id uuid.UUID, p TenantPatch, ifVersion int64) (Tenant, error) {
	var out Tenant
	err := s.tx(ctx, sc.InTenant(id), func(tx pgx.Tx) error {
		cur, err := scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if ifVersion != 0 && ifVersion != cur.Version {
			return ErrVersion
		}
		if p.Name != nil && *p.Name == "" {
			return invalid("name cannot be empty")
		}
		if p.SupportAccess != nil && !supportPolicies[*p.SupportAccess] {
			return invalid("support_access can be approval, allowed or off")
		}
		if p.Plan != nil && *p.Plan != "" {
			if err := planExists(ctx, tx, *p.Plan); err != nil {
				return err
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanTenant(tx.QueryRow(ctx, `UPDATE tenant SET name = coalesce($2, name),
			plan = CASE WHEN $3::boolean THEN nullif($4, '') ELSE plan END,
			support_access = coalesce($5, support_access), version = $6, updated_at = now()
			WHERE id = $1 RETURNING `+tenantCols,
			id, p.Name, p.Plan != nil, p.Plan, p.SupportAccess, v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, id, "tenant.updated", "tenants/"+id.String(), out.Contract())
	})
	return out, err
}

func createWorkspace(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, name string, isDefault bool) (Workspace, error) {
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return Workspace{}, err
	}
	id := ids.New()
	w, err := scanWorkspace(tx.QueryRow(ctx, `INSERT INTO workspace (id, tenant_id, name, status, is_default, version)
		VALUES ($1, $2, $3, 'active', $4, $5) RETURNING `+workspaceCols, id, tenantID, name, isDefault, v))
	if err != nil {
		return w, err
	}
	return w, emit(ctx, tx, v, tenantID, "workspace.created", "tenants/"+tenantID.String()+"/workspaces/"+id.String(), w)
}

func (s *Store) CreateWorkspace(ctx context.Context, sc Scope, tenantID uuid.UUID, name string) (Workspace, error) {
	if name == "" {
		return Workspace{}, invalid("name is required")
	}
	var out Workspace
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := checkWorkspaceLimit(ctx, tx, tenantID); err != nil {
			return err
		}
		var err error
		out, err = createWorkspace(ctx, tx, tenantID, name, false)
		return err
	})
	return out, err
}

func (s *Store) ListWorkspaces(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Workspace, error) {
	var out []Workspace
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+workspaceCols+` FROM workspace WHERE tenant_id = $1 AND status <> 'deleted'
			ORDER BY is_default DESC, name`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Workspace, error) { return scanWorkspace(r) })
		return err
	})
	return out, err
}

type WorkspacePatch struct {
	Name   *string
	Status *string // active or archived
}

func (s *Store) UpdateWorkspace(ctx context.Context, sc Scope, tenantID, id uuid.UUID, p WorkspacePatch) (Workspace, error) {
	var out Workspace
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := scanWorkspace(tx.QueryRow(ctx, `SELECT `+workspaceCols+` FROM workspace
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
		if err != nil {
			return err
		}
		typ := "workspace.updated"
		if p.Status != nil {
			switch {
			case *p.Status != "active" && *p.Status != "archived":
				return invalid("status can be active or archived")
			case *p.Status == "archived" && cur.IsDefault:
				return invalid("the default workspace cannot be archived")
			case *p.Status == "archived":
				typ = "workspace.archived"
			}
		}
		if p.Name != nil && *p.Name == "" {
			return invalid("name cannot be empty")
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanWorkspace(tx.QueryRow(ctx, `UPDATE workspace SET name = coalesce($3, name),
			status = coalesce($4, status), version = $5, updated_at = now() WHERE tenant_id = $1 AND id = $2
			RETURNING `+workspaceCols, tenantID, id, p.Name, p.Status, v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, tenantID, typ, "tenants/"+tenantID.String()+"/workspaces/"+id.String(), out)
	})
	return out, err
}

// TenantBySlug finds a tenant that is not deleted by its slug (operator scope).
func (s *Store) TenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	var out Tenant
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var err error
		out, err = scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE slug = $1 AND status <> 'deleted'`, slug))
		return mapErr(err)
	})
	return out, err
}
