package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// SCIMGroup is a group the tenant's identity provider pushed. Members are provisioned users of the tenant.
type SCIMGroup struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	DisplayName string
	ExternalID  *string
	Members     []SCIMRef // nil when not loaded
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const scimGroupCols = `g.id, g.tenant_id, g.display_name, g.external_id, g.version, g.created_at, g.updated_at`

func scanSCIMGroup(row pgx.Row) (SCIMGroup, error) {
	var g SCIMGroup
	err := row.Scan(&g.ID, &g.TenantID, &g.DisplayName, &g.ExternalID, &g.Version, &g.CreatedAt, &g.UpdatedAt)
	return g, mapErr(err)
}

func scimGroupTarget(tenantID, id uuid.UUID) string {
	return "tenants/" + tenantID.String() + "/scim/groups/" + id.String()
}

func scimMembersOf(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, groups []SCIMGroup) error {
	if len(groups) == 0 {
		return nil
	}
	idx := map[uuid.UUID]int{}
	gids := make([]uuid.UUID, len(groups))
	for i, g := range groups {
		idx[g.ID], gids[i] = i, g.ID
		groups[i].Members = []SCIMRef{}
	}
	rows, err := tx.Query(ctx, `SELECT m.group_id, u.user_id, coalesce(u.display_name, u.user_name)
		FROM scim_group_member m JOIN scim_user u ON u.tenant_id = m.tenant_id AND u.user_id = m.user_id
		WHERE m.tenant_id = $1 AND m.group_id = ANY($2) ORDER BY lower(u.user_name)`, tenantID, gids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var gid uuid.UUID
		var ref SCIMRef
		if err := rows.Scan(&gid, &ref.ID, &ref.Display); err != nil {
			return err
		}
		groups[idx[gid]].Members = append(groups[idx[gid]].Members, ref)
	}
	return rows.Err()
}

func getSCIMGroup(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, members, lock bool) (SCIMGroup, error) {
	q := `SELECT ` + scimGroupCols + ` FROM scim_group g WHERE g.tenant_id = $1 AND g.id = $2`
	if lock {
		q += ` FOR UPDATE`
	}
	g, err := scanSCIMGroup(tx.QueryRow(ctx, q, tenantID, id))
	if err != nil || !members {
		return g, err
	}
	list := []SCIMGroup{g}
	err = scimMembersOf(ctx, tx, tenantID, list)
	return list[0], err
}

// GetSCIMGroup reads a group, with its members when members is set.
func (s *Store) GetSCIMGroup(ctx context.Context, tenantID, id uuid.UUID, members bool) (SCIMGroup, error) {
	var out SCIMGroup
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) (err error) {
		out, err = getSCIMGroup(ctx, tx, tenantID, id, members, false)
		return err
	})
	return out, err
}

var scimGroupFilterCols = map[string]string{
	"id":          `g.id::text = lower($%d)`,
	"displayname": `lower(g.display_name) = lower($%d)`,
	"externalid":  `g.external_id = $%d`,
}

// ListSCIMGroups returns one page of the tenant's groups matching q, oldest first, and how many match.
func (s *Store) ListSCIMGroups(ctx context.Context, tenantID uuid.UUID, q SCIMQuery, members bool) ([]SCIMGroup, int, error) {
	args := []any{tenantID}
	where, err := whereSCIM(q.Conds, scimGroupFilterCols, &args)
	if err != nil {
		return nil, 0, err
	}
	var out []SCIMGroup
	var total int
	err = s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scim_group g WHERE g.tenant_id = $1 AND `+where, args...).
			Scan(&total); err != nil {
			return err
		}
		if q.Limit <= 0 {
			out = []SCIMGroup{}
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT `+scimGroupCols+` FROM scim_group g WHERE g.tenant_id = $1 AND `+where+
			fmt.Sprintf(` ORDER BY g.created_at, g.id OFFSET %d LIMIT %d`, q.Offset, q.Limit), args...)
		if err != nil {
			return err
		}
		if out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SCIMGroup, error) { return scanSCIMGroup(r) }); err != nil {
			return err
		}
		if members {
			return scimMembersOf(ctx, tx, tenantID, out)
		}
		return nil
	})
	return out, total, err
}

func checkGroupName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 256 {
		return invalid("displayName is required (at most 256 characters)")
	}
	return nil
}

// checkSCIMMembers makes sure every member is a provisioned user of the tenant.
func checkSCIMMembers(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, members []uuid.UUID) error {
	if len(members) == 0 {
		return nil
	}
	var missing []string
	rows, err := tx.Query(ctx, `SELECT x::text FROM unnest($2::uuid[]) x WHERE NOT EXISTS
		(SELECT 1 FROM scim_user u WHERE u.tenant_id = $1 AND u.user_id = x)`, tenantID, members)
	if err != nil {
		return err
	}
	if missing, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return err
	}
	if len(missing) > 0 {
		return invalid("members must be users provisioned in this tenant; unknown: %s", strings.Join(missing, ", "))
	}
	return nil
}

func memberIDs(refs []SCIMRef) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(refs))
	seen := map[uuid.UUID]bool{}
	for _, r := range refs {
		if !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r.ID)
		}
	}
	return out
}

// CreateSCIMGroup adds a group with its members and grants the roles mapped to its name.
func (s *Store) CreateSCIMGroup(ctx context.Context, in SCIMGroup) (SCIMGroup, error) {
	if err := checkGroupName(in.DisplayName); err != nil {
		return SCIMGroup{}, err
	}
	tid := in.TenantID
	var out SCIMGroup
	err := s.tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		members := memberIDs(in.Members)
		if err := checkSCIMMembers(ctx, tx, tid, members); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group (id, tenant_id, display_name, external_id, version)
			VALUES ($1, $2, $3, $4, $5)`, id, tid, in.DisplayName, in.ExternalID, v); err != nil {
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_member (tenant_id, group_id, user_id)
			SELECT $1, $2, unnest($3::uuid[])`, tid, id, members); err != nil {
			return mapErr(err)
		}
		if err := reconcileGroupGrants(ctx, tx, tid, members); err != nil {
			return err
		}
		if out, err = getSCIMGroup(ctx, tx, tid, id, true, false); err != nil {
			return err
		}
		return audit(ctx, tx, tid, "scim.group_created", scimGroupTarget(tid, id), map[string]any{
			"display_name": out.DisplayName, "external_id": out.ExternalID, "members": len(members)})
	})
	return out, err
}

// ReplaceSCIMGroup sets a group's name, external id and members (PUT, or PATCH after it is applied) and grants or
// revokes mapped roles for the people affected. A replacement that changes nothing keeps the version.
func (s *Store) ReplaceSCIMGroup(ctx context.Context, in SCIMGroup, ifVersion int64) (SCIMGroup, error) {
	if err := checkGroupName(in.DisplayName); err != nil {
		return SCIMGroup{}, err
	}
	tid := in.TenantID
	var out SCIMGroup
	err := s.tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		cur, err := getSCIMGroup(ctx, tx, tid, in.ID, true, true)
		if err != nil {
			return err
		}
		if ifVersion != 0 && cur.Version != ifVersion {
			return ErrVersion
		}
		want := memberIDs(in.Members)
		if err := checkSCIMMembers(ctx, tx, tid, want); err != nil {
			return err
		}
		had := map[uuid.UUID]bool{}
		for _, m := range cur.Members {
			had[m.ID] = true
		}
		keep := map[uuid.UUID]bool{}
		var added, removed []uuid.UUID
		for _, id := range want {
			keep[id] = true
			if !had[id] {
				added = append(added, id)
			}
		}
		for id := range had {
			if !keep[id] {
				removed = append(removed, id)
			}
		}
		renamed := cur.DisplayName != in.DisplayName
		if !renamed && eqPtr(cur.ExternalID, in.ExternalID) && len(added) == 0 && len(removed) == 0 {
			out = cur
			return nil
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_group SET display_name = $3, external_id = $4, version = $5,
			updated_at = now() WHERE tenant_id = $1 AND id = $2`, tid, in.ID, in.DisplayName, in.ExternalID, v); err != nil {
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group_member WHERE tenant_id = $1 AND group_id = $2
			AND user_id = ANY($3)`, tid, in.ID, removed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_member (tenant_id, group_id, user_id)
			SELECT $1, $2, unnest($3::uuid[])`, tid, in.ID, added); err != nil {
			return mapErr(err)
		}
		affected := append(append([]uuid.UUID{}, added...), removed...)
		if renamed { // mappings go by name
			affected = append(affected, want...)
		}
		if err := reconcileGroupGrants(ctx, tx, tid, affected); err != nil {
			return err
		}
		if out, err = getSCIMGroup(ctx, tx, tid, in.ID, true, false); err != nil {
			return err
		}
		return audit(ctx, tx, tid, "scim.group_updated", scimGroupTarget(tid, in.ID), map[string]any{
			"display_name": out.DisplayName, "external_id": out.ExternalID, "added": added, "removed": removed})
	})
	return out, err
}

// DeleteSCIMGroup removes a group; its members lose the roles it gave them.
func (s *Store) DeleteSCIMGroup(ctx context.Context, tenantID, id uuid.UUID, ifVersion int64) error {
	return s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		cur, err := getSCIMGroup(ctx, tx, tenantID, id, true, true)
		if err != nil {
			return err
		}
		if ifVersion != 0 && cur.Version != ifVersion {
			return ErrVersion
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		if err := reconcileGroupGrants(ctx, tx, tenantID, memberIDs(cur.Members)); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "scim.group_deleted", scimGroupTarget(tenantID, id), map[string]any{
			"display_name": cur.DisplayName, "members": len(cur.Members)})
	})
}

// --- group-to-role mappings ---------------------------------------------------------------------------------------

// SCIMGroupMapping gives members of the SCIM group named Group the app role Role for the whole tenant.
type SCIMGroupMapping struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Group     string    `json:"group"`
	App       string    `json:"app"`
	Role      string    `json:"role"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

const scimMappingCols = `mp.id, mp.tenant_id, mp.group_name, a.slug, mp.role, mp.version, mp.created_at`

func scanSCIMMapping(row pgx.Row) (SCIMGroupMapping, error) {
	var m SCIMGroupMapping
	err := row.Scan(&m.ID, &m.TenantID, &m.Group, &m.App, &m.Role, &m.Version, &m.CreatedAt)
	return m, mapErr(err)
}

func scimMappingTarget(m SCIMGroupMapping) string {
	return "tenants/" + m.TenantID.String() + "/scim/group-mappings/" + m.ID.String()
}

// ListSCIMGroupMappings lists the tenant's mappings by group name.
func (s *Store) ListSCIMGroupMappings(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]SCIMGroupMapping, error) {
	var out []SCIMGroupMapping
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+scimMappingCols+` FROM scim_group_mapping mp JOIN app a ON a.id = mp.app_id
			WHERE mp.tenant_id = $1 ORDER BY lower(mp.group_name), a.slug, mp.role`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SCIMGroupMapping, error) { return scanSCIMMapping(r) })
		return err
	})
	return out, err
}

// membersOfGroupsNamed lists the provisioned users in groups with this name.
func membersOfGroupsNamed(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, name string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT m.user_id FROM scim_group g JOIN scim_group_member m
		ON m.tenant_id = g.tenant_id AND m.group_id = g.id WHERE g.tenant_id = $1 AND lower(g.display_name) = lower($2)`,
		tenantID, name)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// CreateSCIMGroupMapping maps a group name to an app role and grants it to the group's current members.
func (s *Store) CreateSCIMGroupMapping(ctx context.Context, sc Scope, tenantID uuid.UUID, group, app, role string) (SCIMGroupMapping, error) {
	if err := checkGroupName(group); err != nil {
		return SCIMGroupMapping{}, invalid("group is required (at most 256 characters)")
	}
	var out SCIMGroupMapping
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		a, err := getAppBySlug(ctx, tx, app)
		if err == ErrNotFound {
			return invalid("app %q does not exist", app)
		}
		if err != nil {
			return err
		}
		var known bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_role WHERE app_id = $1 AND name = $2)`,
			a.ID, role).Scan(&known); err != nil {
			return err
		}
		if !known {
			return invalid("%s has no role %q", a.Slug, role)
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_mapping (id, tenant_id, group_name, app_id, role, version,
			created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, tenantID, group, a.ID, role, v,
			uuidOrNil(sc.UserID)); err != nil {
			return mapErr(err)
		}
		if out, err = scanSCIMMapping(tx.QueryRow(ctx, `SELECT `+scimMappingCols+` FROM scim_group_mapping mp
			JOIN app a ON a.id = mp.app_id WHERE mp.tenant_id = $1 AND mp.id = $2`, tenantID, id)); err != nil {
			return err
		}
		users, err := membersOfGroupsNamed(ctx, tx, tenantID, group)
		if err != nil {
			return err
		}
		if err := reconcileGroupGrants(ctx, tx, tenantID, users); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "scim.mapping_created", scimMappingTarget(out), out)
	})
	return out, err
}

// DeleteSCIMGroupMapping removes a mapping; the grants it made are revoked.
func (s *Store) DeleteSCIMGroupMapping(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		m, err := scanSCIMMapping(tx.QueryRow(ctx, `SELECT `+scimMappingCols+` FROM scim_group_mapping mp
			JOIN app a ON a.id = mp.app_id WHERE mp.tenant_id = $1 AND mp.id = $2`, tenantID, id))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group_mapping WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
			return err
		}
		users, err := membersOfGroupsNamed(ctx, tx, tenantID, m.Group)
		if err != nil {
			return err
		}
		if err := reconcileGroupGrants(ctx, tx, tenantID, users); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "scim.mapping_deleted", scimMappingTarget(m), m)
	})
}

// reconcileGroupGrants makes each user's group-made grants match the mappings of the groups they are in: a missing
// tenant-wide grant is created (unless the person already has that role some other way) and remembered as
// group-made; a group-made grant no longer backed by a group is revoked. Only active members of the tenant get
// grants, and only for enabled apps. Grants made by hand are never touched.
func reconcileGroupGrants(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, users []uuid.UUID) error {
	type pair struct{ app, role string }
	done := map[uuid.UUID]bool{}
	for _, uid := range users {
		if done[uid] {
			continue
		}
		done[uid] = true
		rows, err := tx.Query(ctx, `SELECT DISTINCT a.slug, mp.role FROM scim_group_member gm
			JOIN scim_group g ON g.tenant_id = gm.tenant_id AND g.id = gm.group_id
			JOIN scim_group_mapping mp ON mp.tenant_id = g.tenant_id AND lower(mp.group_name) = lower(g.display_name)
			JOIN app a ON a.id = mp.app_id AND a.status = 'active'
			JOIN tenant_app ta ON ta.tenant_id = mp.tenant_id AND ta.app_id = a.id AND ta.status = 'enabled'
			JOIN app_role r ON r.app_id = a.id AND r.name = mp.role
			JOIN membership m ON m.tenant_id = gm.tenant_id AND m.user_id = gm.user_id AND m.status = 'active'
			WHERE gm.tenant_id = $1 AND gm.user_id = $2`, tenantID, uid)
		if err != nil {
			return err
		}
		desired, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pair, error) {
			var p pair
			return p, r.Scan(&p.app, &p.role)
		})
		if err != nil {
			return err
		}
		want := map[pair]bool{}
		for _, p := range desired {
			want[p] = true
		}
		rows, err = tx.Query(ctx, `SELECT `+grantCols+` FROM scim_managed_grant mg
			JOIN role_grant g ON g.tenant_id = mg.tenant_id AND g.id = mg.grant_id JOIN app a ON a.id = g.app_id
			WHERE mg.tenant_id = $1 AND mg.user_id = $2`, tenantID, uid)
		if err != nil {
			return err
		}
		managed, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
		if err != nil {
			return err
		}
		have := map[pair]bool{}
		for _, g := range managed {
			p := pair{g.AppSlug, g.Role}
			if g.Status == "active" && want[p] && !have[p] {
				have[p] = true
				continue
			}
			if g.Status == "active" {
				if err := revokeGrant(ctx, tx, g); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `DELETE FROM scim_managed_grant WHERE tenant_id = $1 AND grant_id = $2`,
				tenantID, g.ID); err != nil {
				return err
			}
		}
		for _, p := range desired {
			if have[p] {
				continue
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_grant g JOIN app a ON a.id = g.app_id
				WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.subject_id = $2 AND a.slug = $3
				AND g.role = $4 AND g.workspace_id IS NULL AND g.status = 'active')`, tenantID, uid, p.app, p.role).
				Scan(&exists); err != nil {
				return err
			}
			if exists {
				continue
			}
			g, err := createGrant(ctx, tx, tenantID, NewGrant{App: p.app, UserID: uid, Role: p.role})
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO scim_managed_grant (tenant_id, grant_id, user_id) VALUES ($1, $2, $3)`,
				tenantID, g.ID, uid); err != nil {
				return err
			}
		}
	}
	return nil
}
