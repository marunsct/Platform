package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// Revocation makes tokens issued at or before NotBefore unusable (technical specification §21): tokens whose sub,
// or act.sub, is UserID; only those for TenantID when set (tid claim); only those of SessionID when set (sid claim).
type Revocation struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id"`
	UserID    uuid.UUID  `json:"user_id"`
	SessionID *string    `json:"session_id"`
	NotBefore time.Time  `json:"not_before"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
}

// RevocationWindow is how long a revocation matters: the longest access-token lifetime (5 minutes) plus clock skew
// and leeway, with margin. Lists return revocations newer than this; older ones are pruned.
const RevocationWindow = 15 * time.Minute

// Revocation reasons.
const (
	RevokeRequested         = "requested"
	RevokeSessionEnded      = "session_ended"
	RevokeSignedOut         = "signed_out"
	RevokeMFAReset          = "mfa_reset"
	RevokeMembershipRemoved = "membership_removed"
	RevokeMembershipStatus  = "membership_deactivated"
	RevokeUserDeactivated   = "user_deactivated"
	RevokeUserDeleted       = "user_deleted"
	RevokeAgentDeactivated  = "agent_deactivated"
	RevokeAgentDeleted      = "agent_deleted"
	RevokeAgentSecret       = "agent_secret_rotated"
	RevokeConsentWithdrawn  = "consent_withdrawn"
)

const revocationCols = `id, tenant_id, user_id, session_id, not_before, reason, created_at`

func scanRevocation(row pgx.Row) (Revocation, error) {
	var r Revocation
	err := row.Scan(&r.ID, &r.TenantID, &r.UserID, &r.SessionID, &r.NotBefore, &r.Reason, &r.CreatedAt)
	return r, err
}

// revokeTokens records a revocation in tx and emits matura.revocation.created (to apps by webhook and feed: those
// the tenant enabled, or for a revocation everywhere, those of every tenant the user belongs to).
func revokeTokens(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, sessionID, reason string) (Revocation, error) {
	var tid *uuid.UUID
	if tenantID != uuid.Nil {
		tid = &tenantID
	}
	var sid *string
	if sessionID != "" {
		sid = &sessionID
	}
	r, err := scanRevocation(tx.QueryRow(ctx, `INSERT INTO token_revocation
		(id, tenant_id, user_id, session_id, not_before, reason) VALUES ($1, $2, $3, $4, now(), $5)
		RETURNING `+revocationCols, ids.New(), tid, userID, sid, reason))
	if err != nil {
		return r, mapErr(err)
	}
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return r, err
	}
	return r, emit(ctx, tx, v, tenantID, "revocation.created", "users/"+userID.String()+"/revocations/"+r.ID.String(), r)
}

// RevokeTokens records a revocation on its own (session ends, sign-outs, explicit requests). sc must allow writing
// the tenant's rows, or be operator scope for a revocation everywhere.
func (s *Store) RevokeTokens(ctx context.Context, sc Scope, tenantID, userID uuid.UUID, sessionID, reason string) (Revocation, error) {
	var out Revocation
	if tenantID != uuid.Nil {
		sc = sc.InTenant(tenantID)
	}
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		var err error
		out, err = revokeTokens(ctx, tx, tenantID, userID, sessionID, reason)
		return err
	})
	return out, err
}

// RecentRevocations lists every revocation newer than RevocationWindow, oldest first (maturad's own check).
func (s *Store) RecentRevocations(ctx context.Context) ([]Revocation, error) {
	var out []Revocation
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+revocationCols+` FROM token_revocation
			WHERE not_before > now() - $1::interval ORDER BY created_at, id`, RevocationWindow.String())
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Revocation, error) { return scanRevocation(r) })
		return err
	})
	return out, err
}

// AppRevocations lists the recent revocations an app needs: those in tenants that enabled it, and revocations
// everywhere of users who belong to such a tenant (the same rule as the change feed).
func (s *Store) AppRevocations(ctx context.Context, app App) ([]Revocation, error) {
	var out []Revocation
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+revocationCols+` FROM token_revocation r
			WHERE r.not_before > now() - $2::interval AND (
				(r.tenant_id IS NOT NULL AND EXISTS (SELECT 1 FROM tenant_app ta
					WHERE ta.tenant_id = r.tenant_id AND ta.app_id = $1 AND ta.status = 'enabled'))
				OR (r.tenant_id IS NULL AND EXISTS (SELECT 1 FROM membership m
					JOIN tenant_app ta ON ta.tenant_id = m.tenant_id
					WHERE m.user_id = r.user_id AND ta.app_id = $1 AND ta.status = 'enabled')))
			ORDER BY r.created_at, r.id`, app.ID, RevocationWindow.String())
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Revocation, error) { return scanRevocation(r) })
		return err
	})
	return out, err
}

// PruneRevocations deletes revocations an hour past their not_before.
func (s *Store) PruneRevocations(ctx context.Context) (int64, error) {
	var n int64
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM token_revocation WHERE not_before < now() - interval '1 hour'`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// Revokes says whether r makes a token unusable: the token's subject (or the agent acting, actor) is r's user, it
// is for r's tenant when r names one, of r's session when r names one, and was issued at or before NotBefore.
func (r Revocation) Revokes(subject, actor, tenant uuid.UUID, session string, issuedAt time.Time) bool {
	if r.UserID != subject && (actor == uuid.Nil || r.UserID != actor) {
		return false
	}
	if r.TenantID != nil && *r.TenantID != tenant {
		return false
	}
	if r.SessionID != nil && *r.SessionID != session {
		return false
	}
	return !issuedAt.After(r.NotBefore)
}
