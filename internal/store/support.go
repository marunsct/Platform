package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// Support access (TS10): an operator asks for time-boxed, read-only access to one tenant's admin views; a tenant
// owner approves or denies it, unless the tenant allows support access without approval. Nothing here issues a
// token or acts as a user: the operator keeps their own identity and every request and use is listed for the tenant.

var supportPolicies = map[string]bool{"approval": true, "allowed": true, "off": true}

// MaxSupportMinutes is the longest a grant may last (8 hours). A request nobody answers within a day lapses.
const MaxSupportMinutes = 8 * 60

var ErrSupportAccessOff = errors.New("this organisation does not allow support access")

type SupportAccess struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	OperatorID      uuid.UUID  `json:"operator_id"`
	OperatorEmail   *string    `json:"operator_email"`
	Reason          string     `json:"reason"`
	DurationMinutes int        `json:"duration_minutes"`
	State           string     `json:"state"` // pending, active, expired, denied, revoked, ended
	AutoApproved    bool       `json:"auto_approved"`
	RequestedAt     time.Time  `json:"requested_at"`
	DecidedBy       *uuid.UUID `json:"decided_by"`
	DecidedAt       *time.Time `json:"decided_at"`
	StartsAt        *time.Time `json:"starts_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	EndedBy         *uuid.UUID `json:"ended_by"`
	EndedAt         *time.Time `json:"ended_at"`
	LastUsedAt      *time.Time `json:"last_used_at"`
	Uses            int        `json:"uses"`
}

// supportCols reports approved access as active or expired, and pending requests older than a day as expired.
const supportCols = `s.id, s.tenant_id, s.operator_id, u.email, s.reason, s.duration_minutes,
	CASE WHEN s.state = 'approved' AND s.expires_at > now() THEN 'active'
	     WHEN s.state = 'approved' THEN 'expired'
	     WHEN s.state = 'pending' AND s.requested_at <= now() - interval '24 hours' THEN 'expired'
	     ELSE s.state END,
	s.auto_approved, s.requested_at, s.decided_by, s.decided_at, s.starts_at, s.expires_at, s.ended_by, s.ended_at,
	s.last_used_at, s.uses`

const supportFrom = ` FROM support_access s JOIN app_user u ON u.id = s.operator_id`

func scanSupport(row pgx.Row) (SupportAccess, error) {
	var a SupportAccess
	err := row.Scan(&a.ID, &a.TenantID, &a.OperatorID, &a.OperatorEmail, &a.Reason, &a.DurationMinutes, &a.State,
		&a.AutoApproved, &a.RequestedAt, &a.DecidedBy, &a.DecidedAt, &a.StartsAt, &a.ExpiresAt, &a.EndedBy, &a.EndedAt,
		&a.LastUsedAt, &a.Uses)
	return a, mapErr(err)
}

func getSupport(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (SupportAccess, error) {
	return scanSupport(tx.QueryRow(ctx, `SELECT `+supportCols+supportFrom+` WHERE s.tenant_id = $1 AND s.id = $2`,
		tenantID, id))
}

// RequestSupportAccess records an operator's request. With the tenant's support_access "allowed" it starts at
// once; with "approval" it waits for an owner; with "off" it is refused.
func (s *Store) RequestSupportAccess(ctx context.Context, sc Scope, tenantID, operatorID uuid.UUID, reason string, minutes int) (SupportAccess, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 {
		return SupportAccess{}, invalid("a reason is required (at most 500 characters); the tenant sees it")
	}
	if minutes < 1 || minutes > MaxSupportMinutes {
		return SupportAccess{}, invalid("duration_minutes must be between 1 and %d (8 hours)", MaxSupportMinutes)
	}
	var out SupportAccess
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var status, policy string
		if err := tx.QueryRow(ctx, `SELECT status, support_access FROM tenant WHERE id = $1`, tenantID).
			Scan(&status, &policy); err != nil {
			return mapErr(err)
		}
		switch {
		case status == "deleting" || status == "deleted":
			return ErrNotFound
		case policy == "off":
			return ErrSupportAccessOff
		}
		id := ids.New()
		q := `INSERT INTO support_access (id, tenant_id, operator_id, reason, duration_minutes, state)
			VALUES ($1, $2, $3, $4, $5, 'pending')`
		if policy == "allowed" {
			q = `INSERT INTO support_access (id, tenant_id, operator_id, reason, duration_minutes, state, auto_approved,
				decided_at, starts_at, expires_at)
				VALUES ($1, $2, $3, $4, $5, 'approved', true, now(), now(), now() + make_interval(mins => $5))`
		}
		if _, err := tx.Exec(ctx, q, id, tenantID, operatorID, reason, minutes); err != nil {
			return mapErr(err)
		}
		var err error
		out, err = getSupport(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

func (s *Store) ListSupportAccess(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]SupportAccess, error) {
	var out []SupportAccess
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+supportCols+supportFrom+` WHERE s.tenant_id = $1
			ORDER BY s.requested_at DESC LIMIT 200`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SupportAccess, error) { return scanSupport(r) })
		return err
	})
	return out, err
}

// DecideSupportAccess approves (the window starts now) or denies a pending request (tenant owners).
func (s *Store) DecideSupportAccess(ctx context.Context, sc Scope, tenantID, id, by uuid.UUID, approve bool) (SupportAccess, error) {
	var out SupportAccess
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := scanSupport(tx.QueryRow(ctx, `SELECT `+supportCols+supportFrom+` WHERE s.tenant_id = $1
			AND s.id = $2 FOR UPDATE OF s`, tenantID, id))
		if err != nil {
			return err
		}
		if cur.State != "pending" {
			return fmt.Errorf("%w: the request is %s; only a pending request can be approved or denied", ErrConflict, cur.State)
		}
		set := `state = 'denied'`
		if approve {
			set = `state = 'approved', starts_at = now(), expires_at = now() + make_interval(mins => duration_minutes)`
		}
		if _, err := tx.Exec(ctx, `UPDATE support_access SET `+set+`, decided_by = $3, decided_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, by); err != nil {
			return mapErr(err)
		}
		out, err = getSupport(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// EndSupportAccess stops a pending or active grant early: revoked by the tenant, or ended by its operator.
func (s *Store) EndSupportAccess(ctx context.Context, sc Scope, tenantID, id, by uuid.UUID, byTenant bool) (SupportAccess, error) {
	var out SupportAccess
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := scanSupport(tx.QueryRow(ctx, `SELECT `+supportCols+supportFrom+` WHERE s.tenant_id = $1
			AND s.id = $2 FOR UPDATE OF s`, tenantID, id))
		if err != nil {
			return err
		}
		if !byTenant && cur.OperatorID != by {
			return ErrNotFound
		}
		if cur.State != "pending" && cur.State != "active" {
			return fmt.Errorf("%w: the request is %s", ErrConflict, cur.State)
		}
		state := "ended"
		if byTenant {
			state = "revoked"
		}
		if _, err := tx.Exec(ctx, `UPDATE support_access SET state = $3, ended_by = $4, ended_at = now(),
			expires_at = CASE WHEN expires_at > now() THEN now() ELSE expires_at END
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, state, by); err != nil {
			return mapErr(err)
		}
		out, err = getSupport(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// UseSupportAccess finds the operator's active grant for the tenant and counts the use, so the tenant sees when
// it was last used. ErrNotFound when there is none.
func (s *Store) UseSupportAccess(ctx context.Context, tenantID, operatorID uuid.UUID) (SupportAccess, error) {
	var out SupportAccess
	err := s.tx(ctx, Scope{TenantID: tenantID, UserID: operatorID}, func(tx pgx.Tx) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `UPDATE support_access SET uses = uses + 1, last_used_at = now()
			WHERE id = (SELECT id FROM support_access WHERE tenant_id = $1 AND operator_id = $2 AND state = 'approved'
				AND starts_at <= now() AND expires_at > now() ORDER BY expires_at DESC LIMIT 1)
			RETURNING id`, tenantID, operatorID).Scan(&id)
		if err != nil {
			return mapErr(err)
		}
		out, err = getSupport(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}
