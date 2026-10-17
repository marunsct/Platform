package matura

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// TxBeginner starts transactions: *pgxpool.Pool, *pgx.Conn or a pgx.Tx (a savepoint).
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ErrNoTenant: a tenant-scoped transaction was asked for without a tenant.
var ErrNoTenant = errors.New("matura: no tenant: choose an organisation first")

// SetTenant scopes the current transaction to a tenant for row-level security in shared mode:
// set_config('matura.tenant_id', tenantID, true). The setting ends with the transaction.
func SetTenant(ctx context.Context, tx Executor, tenantID string) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	_, err := tx.Exec(ctx, `SELECT set_config('matura.tenant_id', $1, true)`, tenantID)
	return err
}

// WithTenant runs fn in a transaction scoped to the tenant (SetTenant), committing when fn returns nil and rolling
// back otherwise. Connect as a role that owns nothing and has no BYPASSRLS, so the policies apply.
func WithTenant(ctx context.Context, db TxBeginner, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if err := SetTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// WithPrincipalTenant is WithTenant for the tenant of the request's principal (see Middleware).
func WithPrincipalTenant(ctx context.Context, db TxBeginner, fn func(pgx.Tx) error) error {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return ErrNoTenant
	}
	return WithTenant(ctx, db, p.TenantID, fn)
}
