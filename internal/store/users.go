package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const userCols = `id, email, email_verified, display_name, locale, kind, status, version, updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.EmailVerified, &u.DisplayName, &u.Locale, &u.Kind, &u.Status, &u.Version,
		&u.UpdatedAt)
	return u, mapErr(err)
}

// UserProfile is what a verified token says about its subject.
type UserProfile struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	DisplayName   string
	Locale        string
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// UpsertUser records the token's subject on first sight and refreshes the profile when it changed. The version
// moves, and user.updated is emitted, only on a real change, so calling this on every request is cheap.
func (s *Store) UpsertUser(ctx context.Context, p UserProfile) (User, error) {
	var out User
	err := s.tx(ctx, Scope{UserID: p.ID}, func(tx pgx.Tx) error {
		cur, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1 FOR UPDATE`, p.ID))
		switch {
		case err == ErrNotFound:
			v, err := nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			out, err = scanUser(tx.QueryRow(ctx, `INSERT INTO app_user
				(id, email, email_verified, display_name, locale, status, version)
				VALUES ($1, $2, $3, $4, $5, 'active', $6) RETURNING `+userCols,
				p.ID, nullable(p.Email), p.EmailVerified, nullable(p.DisplayName), nullable(p.Locale), v))
			if err != nil {
				return err
			}
			return emit(ctx, tx, v, uuid.Nil, "user.created", "users/"+p.ID.String(), out)
		case err != nil:
			return err
		}
		// a deleted account is never brought back by an old token; agents' profiles are managed in Matura (their
		// Keycloak service-account users have no name or email)
		if cur.Status == "deleted" || cur.Kind != "human" {
			out = cur
			return nil
		}
		if eq(cur.Email, p.Email) && cur.EmailVerified == p.EmailVerified && eq(cur.DisplayName, p.DisplayName) &&
			eq(cur.Locale, p.Locale) {
			out = cur
			return nil
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanUser(tx.QueryRow(ctx, `UPDATE app_user SET email = $2, email_verified = $3, display_name = $4,
			locale = $5, version = $6, updated_at = now() WHERE id = $1 RETURNING `+userCols,
			p.ID, nullable(p.Email), p.EmailVerified, nullable(p.DisplayName), nullable(p.Locale), v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, uuid.Nil, "user.updated", "users/"+p.ID.String(), out)
	})
	return out, err
}

func eq(p *string, s string) bool {
	if p == nil {
		return s == ""
	}
	return *p == s
}

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	var out User
	err := s.tx(ctx, Scope{UserID: id}, func(tx pgx.Tx) error {
		var err error
		out, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1`, id))
		return err
	})
	return out, err
}

// UserActive reports whether the user (or agent) exists and is active.
func (s *Store) UserActive(ctx context.Context, id uuid.UUID) (bool, error) {
	u, err := s.GetUser(ctx, id)
	if err == ErrNotFound {
		return false, nil
	}
	return err == nil && u.Status == "active", err
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (User, error) {
	var out User
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		var err error
		out, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE lower(email) = lower($1)`, email))
		return err
	})
	return out, err
}

// --- profile and operator user management -----------------------------------------------------------------------

// MyTenant is a tenant the user belongs to, with their role in it.
type MyTenant struct {
	Tenant
	TenantRole string `json:"tenant_role"`
}

// ListMyTenants returns the tenants the user is an active member of, for tenant switchers.
func (s *Store) ListMyTenants(ctx context.Context, userID uuid.UUID) ([]MyTenant, error) {
	var out []MyTenant
	err := s.tx(ctx, Scope{UserID: userID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tenantColsOf("t")+`, m.tenant_role
			FROM membership m JOIN tenant t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND m.status = 'active' AND t.status NOT IN ('deleting','deleted')
			ORDER BY t.name`, userID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (MyTenant, error) {
			var m MyTenant
			err := r.Scan(append(tenantDest(&m.Tenant), &m.TenantRole)...)
			m.StatusReason = nil
			return m, err
		})
		return err
	})
	return out, err
}

// ListUsers finds users across tenants (operators). q matches email or name; after pages by id.
func (s *Store) ListUsers(ctx context.Context, sc Scope, q string, after uuid.UUID, limit int) ([]User, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []User
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userCols+` FROM app_user
			WHERE ($1 = '' OR email ILIKE '%' || $1 || '%' OR display_name ILIKE '%' || $1 || '%') AND id > $2
			ORDER BY id LIMIT $3`, q, after, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
		return err
	})
	return out, err
}

// SetUserStatus deactivates or reactivates an account everywhere (operators). Deactivated users are refused by
// maturad at once and lose sign-in when Keycloak syncs (TS5).
func (s *Store) SetUserStatus(ctx context.Context, sc Scope, id uuid.UUID, status string) (User, error) {
	if status != "active" && status != "deactivated" {
		return User{}, invalid("status can be active or deactivated; use DELETE to delete a user")
	}
	var out User
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		cur, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if cur.Status == "deleted" {
			return ErrNotFound
		}
		if cur.Status == status {
			out = cur
			return nil
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanUser(tx.QueryRow(ctx, `UPDATE app_user SET status = $2, version = $3, updated_at = now()
			WHERE id = $1 RETURNING `+userCols, id, status, v))
		if err != nil {
			return err
		}
		typ := "user.updated"
		if status == "deactivated" {
			typ = "user.deactivated"
		}
		return emit(ctx, tx, v, uuid.Nil, typ, "users/"+id.String(), out)
	})
	return out, err
}

// LastOwnerError refuses to erase a user who is the only active owner of tenants: each needs another owner, or
// to be deleted, first (UM-4).
type LastOwnerError struct{ Tenants []uuid.UUID }

func (e *LastOwnerError) Error() string {
	return fmt.Sprintf("the user is the only owner of %d tenant(s); make someone else owner of each, or delete it, first",
		len(e.Tenants))
}

// DeleteUser erases a person (operators, or the user themselves; GDPR Art. 17): memberships end and grants are
// revoked (contract events, so apps delete or anonymise the user), pending invitations to their address are
// revoked, invitations to their address carry the pseudonym instead and mail queued or sent to it is deleted, their email and name are pseudonymised in the audit log as it is read (audit_redaction), and the row
// stays with email and name cleared so apps' foreign keys remain valid (contract §3). Nothing changes when the user
// is the only owner of a tenant. sc must be operator scope: the erasure spans tenants.
func (s *Store) DeleteUser(ctx context.Context, sc Scope, id uuid.UUID) error {
	return s.tx(ctx, sc, func(tx pgx.Tx) error {
		cur, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if cur.Status == "deleted" {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT tenant_id FROM membership WHERE user_id = $1 AND status <> 'removed'
			ORDER BY tenant_id`, id)
		if err != nil {
			return err
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		members := make([]Membership, len(tenants))
		var sole []uuid.UUID
		for i, tid := range tenants {
			if err := lockTenant(ctx, tx, tid); err != nil {
				return err
			}
			if members[i], err = getMember(ctx, tx, tid, id, true); err != nil {
				return err
			}
			if err := checkNotLastOwner(ctx, tx, tid, members[i]); errors.Is(err, errLastOwner) {
				sole = append(sole, tid)
			} else if err != nil {
				return err
			}
		}
		if len(sole) > 0 {
			return &LastOwnerError{Tenants: sole}
		}
		for i, tid := range tenants {
			if err := revokeGrantsOf(ctx, tx, tid, id); err != nil {
				return err
			}
			v, err := nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE membership SET status = 'removed', version = $3, updated_at = now()
				WHERE tenant_id = $1 AND user_id = $2`, tid, id, v); err != nil {
				return mapErr(err)
			}
			m := members[i]
			m.Status, m.Version, m.Email, m.DisplayName = "removed", v, nil, nil
			if err := emit(ctx, tx, v, tid, "membership.removed", memberSubject(tid, id), m); err != nil {
				return err
			}
		}
		if cur.Email != nil && *cur.Email != "" {
			if err := revokeInvitationsTo(ctx, tx, *cur.Email); err != nil {
				return err
			}
			// invitation rows are not hashed, so the address itself is replaced
			if _, err := tx.Exec(ctx, `UPDATE invitation SET email = $2, deliver_to = NULL WHERE lower(email) = lower($1)`,
				*cur.Email, Pseudonym(id)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM email_outbox WHERE lower(to_address) = lower($1)`, *cur.Email); err != nil {
				return err
			}
		}
		if err := recordErasure(ctx, tx, cur); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err := scanUser(tx.QueryRow(ctx, `UPDATE app_user SET email = NULL, display_name = NULL, avatar_url = NULL,
			locale = NULL, status = 'deleted', version = $2, updated_at = now() WHERE id = $1 RETURNING `+userCols, id, v))
		if err != nil {
			return err
		}
		return emit(ctx, tx, v, uuid.Nil, "user.deleted", "users/"+id.String(), out)
	})
}

func revokeInvitationsTo(ctx context.Context, tx pgx.Tx, email string) error {
	rows, err := tx.Query(ctx, `SELECT `+invitationCols+` FROM invitation
		WHERE lower(email) = lower($1) AND state = 'pending' FOR UPDATE`, email)
	if err != nil {
		return err
	}
	pending, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Invitation, error) { return scanInvitation(r) })
	if err != nil {
		return err
	}
	for _, inv := range pending {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE invitation SET state = 'revoked', version = $3 WHERE tenant_id = $1 AND id = $2`,
			inv.TenantID, inv.ID, v); err != nil {
			return err
		}
		inv.State, inv.Version = "revoked", v
		if err := auditInvitation(ctx, tx, "invitation.revoked", inv); err != nil {
			return err
		}
	}
	return nil
}
