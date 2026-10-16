// Package store is maturad's access to the control-plane database.
//
// Every call runs in a transaction whose first statement sets matura.tenant_id, matura.user_id and matura.scope
// with set_config(..., true), so the row-level security policies in migrations/0001_core.sql decide what the
// query can see. This is safe behind PgBouncer in transaction mode (doc 17 §2.8).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrVersion  = errors.New("version mismatch")
)

// InvalidError is a request the caller can fix; Msg is safe to show.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{Msg: fmt.Sprintf(format, a...)} }

// Scope is who a transaction acts for. A zero TenantID sets no tenant, so tenant-owned tables return nothing
// unless the user is a member (tenant table only) or Operator is set.
type Scope struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Operator bool
}

func (s Scope) InTenant(id uuid.UUID) Scope { s.TenantID = id; return s }

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func uuidSetting(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func (s *Store) tx(ctx context.Context, sc Scope, fn func(pgx.Tx) error) error {
	scope := "tenant"
	if sc.Operator {
		scope = "operator"
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT set_config('matura.tenant_id', $1, true), set_config('matura.user_id', $2, true),
			        set_config('matura.scope', $3, true)`,
			uuidSetting(sc.TenantID), uuidSetting(sc.UserID), scope); err != nil {
			return err
		}
		return fn(tx)
	})
}

// setTenant switches the tenant setting inside a transaction, used when the tenant is created in it.
func setTenant(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT set_config('matura.tenant_id', $1, true)`, id.String())
	return err
}

func nextVersion(ctx context.Context, tx pgx.Tx) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx, `SELECT nextval('matura_version_seq')`).Scan(&v)
	return v, err
}

// emit records a change in the outbox, in the same transaction as the change (technical specification §8).
func emit(ctx context.Context, tx pgx.Tx, version int64, tenantID uuid.UUID, typ, subject string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox (version, tenant_id, type, subject, payload) VALUES ($1, $2, $3, $4, $5)`,
		version, tid, "matura."+typ, subject, body)
	return err
}

// mapErr turns driver errors into the package's errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, strings.TrimSuffix(pg.ConstraintName, "_key"))
		case "23503":
			return invalid("refers to something that does not exist (%s)", pg.ConstraintName)
		case "23514":
			return invalid("a value is not allowed (%s)", pg.ConstraintName)
		case "42501":
			// row-level security refused a write: the caller is outside the tenant
			return ErrNotFound
		}
	}
	return err
}
