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

// LeaderConns is how many connections the background loops can hold at once: each leader keeps its advisory lock
// on a connection of its own for as long as it leads (TryLeader).
const LeaderConns = 9

// Open connects a pool sized for maturad. pgx defaults to max(4, CPUs) connections, which the leader loops alone
// can exhaust on a small machine and leave no connection for requests; unless the URL sets pool_max_conns, the
// pool gets LeaderConns more than that default.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(url, "pool_max_conns") {
		cfg.MaxConns += LeaderConns
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func uuidSetting(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func (s *Store) tx(ctx context.Context, sc Scope, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := setScope(ctx, tx, sc); err != nil {
			return err
		}
		return fn(tx)
	})
}

// setScope is the first statement of tx, so row-level security sees who acts.
func setScope(ctx context.Context, tx pgx.Tx, sc Scope) error {
	scope := "tenant"
	if sc.Operator {
		scope = "operator"
	}
	_, err := tx.Exec(ctx, `SELECT set_config('matura.tenant_id', $1, true), set_config('matura.user_id', $2, true),
		set_config('matura.scope', $3, true)`, uuidSetting(sc.TenantID), uuidSetting(sc.UserID), scope)
	return err
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

// emit records a change in the outbox and the audit log, in the same transaction as the change (technical
// specification §8, §13).
func emit(ctx context.Context, tx pgx.Tx, version int64, tenantID uuid.UUID, typ, subject string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	if _, err = tx.Exec(ctx, `INSERT INTO outbox (version, tenant_id, type, subject, payload) VALUES ($1, $2, $3, $4, $5)`,
		version, tid, "matura."+typ, subject, body); err != nil {
		return err
	}
	return audit(ctx, tx, tenantID, typ, subject, json.RawMessage(body))
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

// TryLeader takes a session-level advisory lock on a connection of its own, so one replica runs a background loop.
// release unlocks and returns the connection; ok is false when another replica holds the lock.
func (s *Store) TryLeader(ctx context.Context, key int64) (release func(), ok bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil || !ok {
		conn.Release()
		return nil, false, err
	}
	return func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
		conn.Release()
	}, true, nil
}
