package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DefaultRetentionDays is how long a tenant's audit events are kept when it never set a retention.
const DefaultRetentionDays = 400

// Retention is a tenant's audit retention and legal hold (technical specification §14.4).
type Retention struct {
	TenantID        uuid.UUID  `json:"tenant_id"`
	RetentionDays   int        `json:"retention_days"`
	LegalHold       bool       `json:"legal_hold"`
	LegalHoldReason *string    `json:"legal_hold_reason"`
	AnchorSeq       int64      `json:"anchor_seq"` // events up to here have been purged
	Version         int64      `json:"version"`
	UpdatedAt       *time.Time `json:"updated_at"`
}

func getRetention(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (Retention, error) {
	out := Retention{TenantID: tenantID, RetentionDays: DefaultRetentionDays}
	err := tx.QueryRow(ctx, `SELECT retention_days, legal_hold, legal_hold_reason, version, updated_at
		FROM audit_retention WHERE tenant_id = $1`, tenantID).
		Scan(&out.RetentionDays, &out.LegalHold, &out.LegalHoldReason, &out.Version, &out.UpdatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT coalesce((SELECT anchor_seq FROM audit_chain WHERE chain = $1), 0)`, tenantID).
		Scan(&out.AnchorSeq)
	return out, err
}

func (s *Store) Retention(ctx context.Context, sc Scope, tenantID uuid.UUID) (Retention, error) {
	var out Retention
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) (err error) {
		out, err = getRetention(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// PutRetention replaces the tenant's retention (30 days to 10 years) and legal hold. A hold needs a reason.
// ifVersion 0 skips the version check.
func (s *Store) PutRetention(ctx context.Context, sc Scope, tenantID uuid.UUID, in Retention, ifVersion int64) (Retention, error) {
	if in.RetentionDays < 30 || in.RetentionDays > 3650 {
		return Retention{}, invalid("retention_days must be between 30 and 3650")
	}
	if in.LegalHoldReason != nil {
		r := strings.TrimSpace(*in.LegalHoldReason)
		in.LegalHoldReason = nullable(r)
	}
	if in.LegalHold && in.LegalHoldReason == nil {
		return Retention{}, invalid("legal_hold_reason is required while legal_hold is on")
	}
	if !in.LegalHold {
		in.LegalHoldReason = nil
	}
	var out Retention
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		before, err := getRetention(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if ifVersion != 0 && ifVersion != before.Version {
			return ErrVersion
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_retention (tenant_id, retention_days, legal_hold, legal_hold_reason,
				version) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id) DO UPDATE SET retention_days = EXCLUDED.retention_days,
				legal_hold = EXCLUDED.legal_hold, legal_hold_reason = EXCLUDED.legal_hold_reason,
				version = EXCLUDED.version, updated_at = now()`,
			tenantID, in.RetentionDays, in.LegalHold, in.LegalHoldReason, v); err != nil {
			return mapErr(err)
		}
		if out, err = getRetention(ctx, tx, tenantID); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "audit_retention.updated", "tenants/"+tenantID.String()+"/retention",
			map[string]any{"before": before, "after": out})
	})
	return out, err
}

// Purge is what one retention run removed from a tenant's chain.
type Purge struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	Purged     int64     `json:"purged"`
	AnchorSeq  int64     `json:"anchor_seq"`
	AnchorHash string    `json:"anchor_hash"`
}

// PurgeAudit deletes the tenant's audit events older than its retention, unless it is under legal hold, by
// moving the chain's anchor (matura_audit_purge in migration 0012), and records audit.purged in the same chain.
func (s *Store) PurgeAudit(ctx context.Context, tenantID uuid.UUID) (Purge, error) {
	out := Purge{TenantID: tenantID}
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		var seq *int64
		var hash []byte
		if err := tx.QueryRow(ctx, `SELECT purged, anchor_seq, anchor_hash FROM matura_audit_purge($1)`, tenantID).
			Scan(&out.Purged, &seq, &hash); err != nil {
			return err
		}
		if out.Purged == 0 || seq == nil {
			return nil
		}
		out.AnchorSeq, out.AnchorHash = *seq, hex.EncodeToString(hash)
		return audit(ctx, tx, tenantID, "audit.purged", "tenants/"+tenantID.String()+"/audit", out)
	})
	return out, err
}

// AuditTenants lists the tenants that have an audit chain, for the retention run.
func (s *Store) AuditTenants(ctx context.Context) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT chain FROM audit_chain
			WHERE chain <> '00000000-0000-0000-0000-000000000000' ORDER BY chain`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	return out, err
}
