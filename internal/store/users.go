package store

import (
	"context"

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
		if cur.Status == "deleted" { // a deleted account is never brought back by an old token
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
		rows, err := tx.Query(ctx, `SELECT t.id, t.slug, t.name, t.kind, t.status, t.plan, t.data_mode_default, t.version,
				t.created_at, t.updated_at, m.tenant_role
			FROM membership m JOIN tenant t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND m.status = 'active' AND t.status NOT IN ('deleting','deleted')
			ORDER BY t.name`, userID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (MyTenant, error) {
			var m MyTenant
			err := r.Scan(&m.ID, &m.Slug, &m.Name, &m.Kind, &m.Status, &m.Plan, &m.DataModeDefault, &m.Version,
				&m.CreatedAt, &m.UpdatedAt, &m.TenantRole)
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

// DeleteUser removes a person (operators, GDPR erasure): memberships end, grants are revoked, and the row stays with
// email and name cleared so apps' foreign keys remain valid (contract §3). A sole owner must be replaced first.
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
		for _, tid := range tenants {
			if err := lockTenant(ctx, tx, tid); err != nil {
				return err
			}
			m, err := getMember(ctx, tx, tid, id, true)
			if err != nil {
				return err
			}
			if err := checkNotLastOwner(ctx, tx, tid, m); err != nil {
				return invalid("the user is the only owner of tenant %s; make someone else owner first", tid)
			}
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
			m.Status, m.Version, m.Email, m.DisplayName = "removed", v, nil, nil
			if err := emit(ctx, tx, v, tid, "membership.removed", memberSubject(tid, id), m); err != nil {
				return err
			}
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
