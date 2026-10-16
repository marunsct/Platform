package store

import (
	"context"
	"slices"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Role is an app role as Matura holds it (ADR 0008).
type Role struct {
	App         string   `json:"app"`
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	Permissions []string `json:"permissions"`
	IsDefault   bool     `json:"is_default"`
	Origin      string   `json:"origin"` // manifest or platform
	Edited      bool     `json:"edited"` // changed in Matura, so manifests leave it alone
	Version     int64    `json:"version"`
}

const roleCols = `a.slug, r.name, r.description, r.permissions, r.is_default, r.origin, r.edited, r.version`

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.App, &r.Name, &r.Description, &r.Permissions, &r.IsDefault, &r.Origin, &r.Edited, &r.Version)
	return r, mapErr(err)
}

func getRole(ctx context.Context, tx pgx.Tx, appID uuid.UUID, name string, lock bool) (Role, error) {
	q := `SELECT ` + roleCols + ` FROM app_role r JOIN app a ON a.id = r.app_id WHERE r.app_id = $1 AND r.name = $2`
	if lock {
		q += ` FOR UPDATE OF r`
	}
	return scanRole(tx.QueryRow(ctx, q, appID, name))
}

func roleSubject(app, name string) string { return "apps/" + app + "/roles/" + name }

func catalogueOf(ctx context.Context, tx pgx.Tx, appID uuid.UUID) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT name FROM app_permission WHERE app_id = $1`, appID)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out, nil
}

func normalizePerms(perms []string) []string {
	out := slices.Clone(perms)
	if out == nil {
		out = []string{}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// syncManifestRoles applies a manifest's permission catalogue and starter roles (technical specification §6.1).
// Roles created or edited in Matura are left alone; the whole apply fails if a role would be left with a
// permission the catalogue no longer has, or if a role someone holds would disappear.
func syncManifestRoles(ctx context.Context, tx pgx.Tx, app App, m Manifest, v int64) error {
	if _, err := tx.Exec(ctx, `DELETE FROM app_permission WHERE app_id = $1`, app.ID); err != nil {
		return err
	}
	for _, p := range m.Permissions {
		if _, err := tx.Exec(ctx, `INSERT INTO app_permission (app_id, name, description) VALUES ($1, $2, $3)`,
			app.ID, p.Name, nullable(p.Description)); err != nil {
			return mapErr(err)
		}
	}

	rows, err := tx.Query(ctx, `SELECT `+roleCols+` FROM app_role r JOIN app a ON a.id = r.app_id
		WHERE r.app_id = $1 FOR UPDATE OF r`, app.ID)
	if err != nil {
		return err
	}
	existing, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) { return scanRole(r) })
	if err != nil {
		return err
	}
	byName := map[string]Role{}
	for _, r := range existing {
		byName[r.Name] = r
	}

	inManifest := map[string]bool{}
	for _, def := range m.Roles {
		inManifest[def.Name] = true
		cur, ok := byName[def.Name]
		if ok && (cur.Origin == "platform" || cur.Edited) {
			continue
		}
		perms := normalizePerms(def.Permissions)
		if ok && slices.Equal(cur.Permissions, perms) && eq(cur.Description, def.Description) {
			continue
		}
		r, err := scanRole(tx.QueryRow(ctx, `WITH up AS (
				INSERT INTO app_role (app_id, name, description, permissions, origin, edited, version)
				VALUES ($1, $2, $3, $4, 'manifest', false, $5)
				ON CONFLICT (app_id, name) DO UPDATE SET description = EXCLUDED.description,
					permissions = EXCLUDED.permissions, version = EXCLUDED.version
				RETURNING *)
			SELECT `+roleCols+` FROM up r JOIN app a ON a.id = r.app_id`,
			app.ID, def.Name, nullable(def.Description), perms, v))
		if err != nil {
			return err
		}
		typ := "app.role.updated"
		if !ok {
			typ = "app.role.created"
		}
		if err := emit(ctx, tx, v, uuid.Nil, typ, roleSubject(app.Slug, r.Name), r); err != nil {
			return err
		}
	}
	for _, r := range existing {
		if r.Origin == "manifest" && !r.Edited && !inManifest[r.Name] {
			if err := deleteRole(ctx, tx, app, r, v, m.DefaultRole); err != nil {
				return err
			}
		}
	}

	if m.DefaultRole != "" {
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_role WHERE app_id = $1 AND name = $2)`,
			app.ID, m.DefaultRole).Scan(&found); err != nil {
			return err
		}
		if !found {
			return invalid("default_role %q is not one of the app's roles", m.DefaultRole)
		}
		if _, err := tx.Exec(ctx, `UPDATE app_role SET is_default = (name = $2) WHERE app_id = $1
			AND is_default <> (name = $2)`, app.ID, m.DefaultRole); err != nil {
			return err
		}
	}

	// every role, wherever it was defined, may only use permissions the app still checks
	rows, err = tx.Query(ctx, `SELECT r.name FROM app_role r WHERE r.app_id = $1 AND EXISTS (
			SELECT 1 FROM unnest(r.permissions) p(name)
			WHERE p.name <> '*' AND NOT EXISTS (SELECT 1 FROM app_permission c WHERE c.app_id = r.app_id AND c.name = p.name))
		ORDER BY r.name`, app.ID)
	if err != nil {
		return err
	}
	stale, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		return invalid("roles %v use permissions this manifest removes; edit those roles in Matura first", stale)
	}
	return nil
}

// deleteRole removes a role nobody holds. Revoked grants of it go too, since they reference it.
func deleteRole(ctx context.Context, tx pgx.Tx, app App, r Role, v int64, defaultRole string) error {
	if r.IsDefault && r.Name == defaultRole {
		return invalid("role %q is the app's default role; choose another default first", r.Name)
	}
	// role_grant has RLS; callers act in operator scope, which sees every tenant's grants
	var held int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_grant WHERE app_id = $1 AND role = $2 AND status = 'active'`,
		app.ID, r.Name).Scan(&held); err != nil {
		return err
	}
	if held > 0 {
		return invalid("role %q is held by %d grants; revoke them before deleting the role", r.Name, held)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_grant WHERE app_id = $1 AND role = $2`, app.ID, r.Name); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_role WHERE app_id = $1 AND name = $2`, app.ID, r.Name); err != nil {
		return err
	}
	r.Version = v
	return emit(ctx, tx, v, uuid.Nil, "app.role.deleted", roleSubject(app.Slug, r.Name), r)
}

func (s *Store) ListRoles(ctx context.Context, appSlug string) ([]Role, error) {
	var out []Role
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+roleCols+` FROM app_role r JOIN app a ON a.id = r.app_id
			WHERE r.app_id = $1 ORDER BY r.name`, app.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) { return scanRole(r) })
		return err
	})
	return out, err
}

type NewRole struct {
	Name        string
	Description string
	Permissions []string
}

// CreateRole adds a role defined in Matura (RL-8). sc must be operator scope.
func (s *Store) CreateRole(ctx context.Context, sc Scope, appSlug string, in NewRole) (Role, error) {
	var out Role
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		cat, err := catalogueOf(ctx, tx, app.ID)
		if err != nil {
			return err
		}
		if err := validateRole(in.Name, in.Permissions, cat); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_role (app_id, name, description, permissions, origin, version)
			VALUES ($1, $2, $3, $4, 'platform', $5)`, app.ID, in.Name, nullable(in.Description),
			normalizePerms(in.Permissions), v); err != nil {
			return mapErr(err)
		}
		if out, err = getRole(ctx, tx, app.ID, in.Name, false); err != nil {
			return err
		}
		return emit(ctx, tx, v, uuid.Nil, "app.role.created", roleSubject(app.Slug, out.Name), out)
	})
	return out, err
}

type RolePatch struct {
	Name        *string // rename; grants follow (ON UPDATE CASCADE)
	Description *string
	Permissions *[]string
	IsDefault   *bool // only true: makes this the role new members get
}

// UpdateRole edits a role in Matura (RL-8). The role is marked edited, so manifests stop changing it (RL-10).
func (s *Store) UpdateRole(ctx context.Context, sc Scope, appSlug, name string, p RolePatch) (Role, error) {
	var out Role
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		cur, err := getRole(ctx, tx, app.ID, name, true)
		if err != nil {
			return err
		}
		cat, err := catalogueOf(ctx, tx, app.ID)
		if err != nil {
			return err
		}
		newName, perms := cur.Name, cur.Permissions
		if p.Name != nil {
			newName = *p.Name
		}
		if p.Permissions != nil {
			perms = normalizePerms(*p.Permissions)
		}
		if err := validateRole(newName, perms, cat); err != nil {
			return err
		}
		if p.IsDefault != nil && !*p.IsDefault {
			return invalid("make another role the default instead of unsetting this one")
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app_role SET name = $3, description = CASE WHEN $4::boolean THEN $5 ELSE description END,
			permissions = $6, edited = true, version = $7 WHERE app_id = $1 AND name = $2`,
			app.ID, cur.Name, newName, p.Description != nil, p.Description, perms, v); err != nil {
			return mapErr(err)
		}
		if p.IsDefault != nil {
			if _, err := tx.Exec(ctx, `UPDATE app_role SET is_default = (name = $2) WHERE app_id = $1`, app.ID, newName); err != nil {
				return err
			}
		}
		if out, err = getRole(ctx, tx, app.ID, newName, false); err != nil {
			return err
		}
		payload := map[string]any{"role": out}
		if newName != cur.Name {
			payload["previous_name"] = cur.Name
		}
		return emit(ctx, tx, v, uuid.Nil, "app.role.updated", roleSubject(app.Slug, newName), payload)
	})
	return out, err
}

// DeleteRole removes a role nobody holds and that is not the default (RL-11).
func (s *Store) DeleteRole(ctx context.Context, sc Scope, appSlug, name string) error {
	return s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		r, err := getRole(ctx, tx, app.ID, name, true)
		if err != nil {
			return err
		}
		if r.IsDefault {
			return invalid("role %q is the app's default role; choose another default first", r.Name)
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		return deleteRole(ctx, tx, app, r, v, "")
	})
}
