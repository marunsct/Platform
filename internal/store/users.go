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
