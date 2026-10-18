package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// SCIMToken is a bearer token an identity provider uses to provision a tenant (TS14). Only its hash is stored.
type SCIMToken struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedBy  *uuid.UUID `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

const scimTokenCols = `id, tenant_id, name, prefix, created_by, created_at, expires_at, last_used_at`

func scanSCIMToken(row pgx.Row) (SCIMToken, error) {
	var t SCIMToken
	err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Prefix, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt)
	return t, mapErr(err)
}

func scimTokenTarget(t SCIMToken) string {
	return "tenants/" + t.TenantID.String() + "/scim/tokens/" + t.ID.String()
}

// MaxSCIMTokens is how many live tokens a tenant may hold (two cover a rotation; more for several directories).
const MaxSCIMTokens = 5

// CreateSCIMToken stores a token's hash for a company tenant.
func (s *Store) CreateSCIMToken(ctx context.Context, sc Scope, tenantID uuid.UUID, name string, hash []byte,
	prefix string, expiresAt *time.Time) (SCIMToken, error) {
	if name == "" || len(name) > 100 {
		return SCIMToken{}, invalid("name is required (at most 100 characters)")
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return SCIMToken{}, invalid("expires_at must be in the future")
	}
	var out SCIMToken
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		var kind string
		if err := tx.QueryRow(ctx, `SELECT kind FROM tenant WHERE id = $1`, tenantID).Scan(&kind); err != nil {
			return mapErr(err)
		}
		if kind != "company" {
			return invalid("SCIM provisioning is for company tenants")
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scim_token WHERE tenant_id = $1 AND revoked_at IS NULL
			AND (expires_at IS NULL OR expires_at > now())`, tenantID).Scan(&live); err != nil {
			return err
		}
		if live >= MaxSCIMTokens {
			return invalid("a tenant can hold %d SCIM tokens; revoke one first", MaxSCIMTokens)
		}
		var err error
		out, err = scanSCIMToken(tx.QueryRow(ctx, `INSERT INTO scim_token (id, tenant_id, name, hash, prefix, created_by,
			expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+scimTokenCols,
			ids.New(), tenantID, name, hash, prefix, uuidOrNil(sc.UserID), expiresAt))
		if err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "scim.token_created", scimTokenTarget(out), out)
	})
	return out, err
}

// ListSCIMTokens lists the tenant's tokens that are neither revoked nor expired.
func (s *Store) ListSCIMTokens(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]SCIMToken, error) {
	var out []SCIMToken
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+scimTokenCols+` FROM scim_token WHERE tenant_id = $1
			AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SCIMToken, error) { return scanSCIMToken(r) })
		return err
	})
	return out, err
}

// RevokeSCIMToken stops a token at once.
func (s *Store) RevokeSCIMToken(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		t, err := scanSCIMToken(tx.QueryRow(ctx, `UPDATE scim_token SET revoked_at = now()
			WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL RETURNING `+scimTokenCols, tenantID, id))
		if err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "scim.token_revoked", scimTokenTarget(t), nil)
	})
}

// ErrSCIMTenantInactive is a SCIM call for a tenant that is suspended or being deleted.
var ErrSCIMTenantInactive = errors.New("this organisation is not active")

// AuthenticateSCIMToken finds the live token with this hash in the tenant (another tenant's token is not found)
// and records its use at most once a minute.
func (s *Store) AuthenticateSCIMToken(ctx context.Context, tenantID uuid.UUID, hash []byte) (SCIMToken, error) {
	var out SCIMToken
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		var err error
		out, err = scanSCIMToken(tx.QueryRow(ctx, `SELECT `+scimTokenCols+` FROM scim_token WHERE tenant_id = $1
			AND hash = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, tenantID, hash))
		if err != nil {
			return err
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM tenant WHERE id = $1`, tenantID).Scan(&status); err != nil {
			return mapErr(err)
		}
		if status != "active" {
			return ErrSCIMTenantInactive
		}
		if out.LastUsedAt == nil || time.Since(*out.LastUsedAt) > time.Minute {
			_, err = tx.Exec(ctx, `UPDATE scim_token SET last_used_at = now() WHERE tenant_id = $1 AND id = $2`,
				tenantID, out.ID)
		}
		return err
	})
	return out, err
}
