package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var tenantRoles = map[string]bool{"owner": true, "admin": true, "billing": true, "member": true}

const memberCols = `m.tenant_id, m.user_id, m.tenant_role, m.status, m.joined_at, m.version, m.updated_at,
	u.email, u.display_name`

func scanMember(row pgx.Row) (Membership, error) {
	var m Membership
	err := row.Scan(&m.TenantID, &m.UserID, &m.TenantRole, &m.Status, &m.JoinedAt, &m.Version, &m.UpdatedAt,
		&m.Email, &m.DisplayName)
	return m, mapErr(err)
}

func memberSubject(tenantID, userID uuid.UUID) string {
	return "tenants/" + tenantID.String() + "/members/" + userID.String()
}

func getMember(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, lock bool) (Membership, error) {
	q := `SELECT ` + memberCols + ` FROM membership m JOIN app_user u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2`
	if lock {
		q += ` FOR UPDATE OF m`
	}
	return scanMember(tx.QueryRow(ctx, q, tenantID, userID))
}

// addMember adds a user, or brings back a removed one with the new role. With enforce, the plan's member limit
// applies (not when a tenant is created with its owner).
func addMember(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, role string, enforce bool) (Membership, error) {
	if !tenantRoles[role] {
		return Membership{}, invalid("tenant role must be owner, admin, billing or member")
	}
	cur, err := getMember(ctx, tx, tenantID, userID, true)
	switch {
	case err == nil && cur.Status != "removed":
		return cur, ErrConflict
	case err != nil && err != ErrNotFound:
		return cur, err
	}
	if enforce {
		if err := checkMemberLimit(ctx, tx, tenantID); err != nil {
			return Membership{}, err
		}
	}
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return Membership{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO membership (tenant_id, user_id, tenant_role, status, version)
		VALUES ($1, $2, $3, 'active', $4)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET tenant_role = EXCLUDED.tenant_role, status = 'active',
			joined_at = now(), version = EXCLUDED.version, updated_at = now()`,
		tenantID, userID, role, v); err != nil {
		return Membership{}, mapErr(err)
	}
	m, err := getMember(ctx, tx, tenantID, userID, false)
	if err != nil {
		return m, err
	}
	return m, emit(ctx, tx, v, tenantID, "membership.added", memberSubject(tenantID, userID), m)
}

// AddMember adds a user with an account; they get each enabled app's default role (RL-4).
func (s *Store) AddMember(ctx context.Context, sc Scope, tenantID, userID uuid.UUID, role string) (Membership, error) {
	var out Membership
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		if out, err = addMember(ctx, tx, tenantID, userID, role, true); err != nil {
			return err
		}
		return grantDefaults(ctx, tx, tenantID, userID, nil)
	})
	return out, err
}

// MembershipOf returns the user's membership in the tenant; ErrNotFound when there is none or it is not active.
func (s *Store) MembershipOf(ctx context.Context, tenantID, userID uuid.UUID) (Membership, error) {
	var out Membership
	err := s.tx(ctx, Scope{TenantID: tenantID, UserID: userID}, func(tx pgx.Tx) error {
		var err error
		out, err = getMember(ctx, tx, tenantID, userID, false)
		if err == nil && out.Status != "active" {
			err = ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *Store) ListMembers(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Membership, error) {
	var out []Membership
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+memberCols+` FROM membership m JOIN app_user u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.status <> 'removed' ORDER BY lower(u.email)`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) { return scanMember(r) })
		return err
	})
	return out, err
}

type MemberPatch struct {
	TenantRole *string
	Status     *string // active or deactivated
}

// errLastOwner explains UM-4: a tenant always keeps at least one active owner.
var errLastOwner = &InvalidError{Msg: "a tenant needs at least one active owner; make someone else owner first"}

func checkNotLastOwner(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, cur Membership) error {
	if cur.TenantRole != "owner" || cur.Status != "active" {
		return nil
	}
	var owners int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM membership WHERE tenant_id = $1 AND tenant_role = 'owner'
		AND status = 'active'`, tenantID).Scan(&owners); err != nil {
		return err
	}
	if owners <= 1 {
		return errLastOwner
	}
	return nil
}

// lockTenant serialises membership changes per tenant so two admins cannot each demote "the other" last owner.
func lockTenant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	var id uuid.UUID
	return mapErr(tx.QueryRow(ctx, `SELECT id FROM tenant WHERE id = $1 FOR UPDATE`, tenantID).Scan(&id))
}

func (s *Store) UpdateMember(ctx context.Context, sc Scope, tenantID, userID uuid.UUID, p MemberPatch) (Membership, error) {
	var out Membership
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := getMember(ctx, tx, tenantID, userID, true)
		if err != nil || cur.Status == "removed" {
			return ErrNotFound
		}
		if p.TenantRole != nil && !tenantRoles[*p.TenantRole] {
			return invalid("tenant role must be owner, admin, billing or member")
		}
		if p.Status != nil && *p.Status != "active" && *p.Status != "deactivated" {
			return invalid("status can be active or deactivated")
		}
		losesOwner := (p.TenantRole != nil && *p.TenantRole != "owner") || (p.Status != nil && *p.Status != "active")
		if losesOwner {
			if err := checkNotLastOwner(ctx, tx, tenantID, cur); err != nil {
				return err
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE membership SET tenant_role = coalesce($3, tenant_role),
			status = coalesce($4, status), version = $5, updated_at = now() WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID, p.TenantRole, p.Status, v); err != nil {
			return mapErr(err)
		}
		if out, err = getMember(ctx, tx, tenantID, userID, false); err != nil {
			return err
		}
		return emit(ctx, tx, v, tenantID, "membership.updated", memberSubject(tenantID, userID), out)
	})
	return out, err
}

// RemoveMember ends the membership and revokes the user's app role grants in the tenant.
func (s *Store) RemoveMember(ctx context.Context, sc Scope, tenantID, userID uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := getMember(ctx, tx, tenantID, userID, true)
		if err != nil || cur.Status == "removed" {
			return ErrNotFound
		}
		if err := checkNotLastOwner(ctx, tx, tenantID, cur); err != nil {
			return err
		}
		if err := revokeGrantsOf(ctx, tx, tenantID, userID); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE membership SET status = 'removed', version = $3, updated_at = now()
			WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, v); err != nil {
			return mapErr(err)
		}
		cur.Status, cur.Version = "removed", v
		return emit(ctx, tx, v, tenantID, "membership.removed", memberSubject(tenantID, userID), cur)
	})
}
