package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/secrets"
)

// AuditSink is a destination a tenant streams its audit log to (TS9). Delivery is at least once and in chain
// order; Cursor is the last seq the receiver acknowledged.
type AuditSink struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	Kind          string    `json:"kind"`
	URL           string    `json:"url"`
	Secret        string    `json:"secret,omitempty"` // only when created
	Status        string    `json:"status"`
	Cursor        int64     `json:"cursor"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastStatus    *int      `json:"last_status"`
	LastError     *string   `json:"last_error"`
	Delivered     int64     `json:"delivered"`
	CreatedAt     time.Time `json:"created_at"`

	sealed []byte
}

const auditSinkCols = `id, tenant_id, kind, url, status, cursor, attempts, next_attempt_at, last_status, last_error,
	delivered, created_at, secret`

func scanAuditSink(row pgx.Row) (AuditSink, error) {
	var a AuditSink
	err := row.Scan(&a.ID, &a.TenantID, &a.Kind, &a.URL, &a.Status, &a.Cursor, &a.Attempts, &a.NextAttemptAt,
		&a.LastStatus, &a.LastError, &a.Delivered, &a.CreatedAt, &a.sealed)
	return a, mapErr(err)
}

func auditSinkAAD(id uuid.UUID) string { return "audit_sink:" + id.String() }

func auditSinkEvent(ctx context.Context, tx pgx.Tx, action string, a AuditSink) error {
	return audit(ctx, tx, a.TenantID, action, "tenants/"+a.TenantID.String()+"/audit/sinks/"+a.ID.String(),
		map[string]any{"id": a.ID, "kind": a.Kind, "url": a.URL, "status": a.Status, "cursor": a.Cursor})
}

// CreateAuditSink adds a webhook destination. It starts after the newest event, or at the start of the chain
// when backfill is set.
func (s *Store) CreateAuditSink(ctx context.Context, sc Scope, km secrets.KeyManager, tenantID uuid.UUID, rawURL string, backfill bool) (AuditSink, error) {
	if err := validWebhookURL(rawURL, AllowHTTPWebhooks); err != nil {
		return AuditSink{}, err
	}
	secret, err := randomSecret("whsec_")
	if err != nil {
		return AuditSink{}, err
	}
	id := ids.New()
	sealed, err := s.forTenant(km, tenantID).Seal([]byte(secret), auditSinkAAD(id))
	if err != nil {
		return AuditSink{}, err
	}
	var out AuditSink
	err = s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_sink WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
			return err
		}
		if n >= 10 {
			return invalid("a tenant can have at most 10 audit destinations")
		}
		start := `(SELECT coalesce(max(seq), 0) FROM audit_chain WHERE chain = $1)`
		if backfill {
			start = `0`
		}
		if out, err = scanAuditSink(tx.QueryRow(ctx, `INSERT INTO audit_sink (id, tenant_id, url, secret, cursor)
			VALUES ($2, $1, $3, $4, `+start+`) RETURNING `+auditSinkCols, tenantID, id, rawURL, sealed)); err != nil {
			return err
		}
		return auditSinkEvent(ctx, tx, "audit.sink.created", out)
	})
	out.Secret = secret
	return out, err
}

func (s *Store) ListAuditSinks(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]AuditSink, error) {
	var out []AuditSink
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+auditSinkCols+` FROM audit_sink WHERE tenant_id = $1 ORDER BY created_at`,
			tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditSink, error) { return scanAuditSink(r) })
		return err
	})
	return out, err
}

// UpdateAuditSink changes the URL or turns delivery on (active) or off (disabled).
func (s *Store) UpdateAuditSink(ctx context.Context, sc Scope, tenantID, id uuid.UUID, p WebhookPatch) (AuditSink, error) {
	if p.URL != nil {
		if err := validWebhookURL(*p.URL, AllowHTTPWebhooks); err != nil {
			return AuditSink{}, err
		}
	}
	if p.Status != nil && *p.Status != "active" && *p.Status != "disabled" {
		return AuditSink{}, invalid("status can be active or disabled")
	}
	var out AuditSink
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		if out, err = scanAuditSink(tx.QueryRow(ctx, `UPDATE audit_sink SET url = coalesce($3::text, url),
			status = coalesce($4::text, status),
			next_attempt_at = CASE WHEN $4::text = 'active' THEN now() ELSE next_attempt_at END, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 RETURNING `+auditSinkCols, tenantID, id, p.URL, p.Status)); err != nil {
			return err
		}
		return auditSinkEvent(ctx, tx, "audit.sink.updated", out)
	})
	return out, err
}

func (s *Store) DeleteAuditSink(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		out, err := scanAuditSink(tx.QueryRow(ctx, `DELETE FROM audit_sink WHERE tenant_id = $1 AND id = $2
			RETURNING `+auditSinkCols, tenantID, id))
		if err != nil {
			return err
		}
		return auditSinkEvent(ctx, tx, "audit.sink.deleted", out)
	})
}

// DueAuditSink is a destination ready for delivery, with its signing secret opened.
type DueAuditSink struct {
	AuditSink
	Key []byte
}

// DueAuditSinks returns destinations whose next attempt is due. Only the streaming leader calls it.
func (s *Store) DueAuditSinks(ctx context.Context, km secrets.KeyManager, limit int) ([]DueAuditSink, error) {
	var sinks []AuditSink
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+auditSinkCols+` FROM audit_sink s
			WHERE status <> 'disabled' AND next_attempt_at <= now()
			AND EXISTS (SELECT 1 FROM audit_chain c WHERE c.chain = s.tenant_id AND c.seq > s.cursor)
			ORDER BY next_attempt_at LIMIT $1`, limit)
		if err != nil {
			return err
		}
		sinks, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditSink, error) { return scanAuditSink(r) })
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]DueAuditSink, 0, len(sinks))
	for _, a := range sinks {
		key, err := km.Open(a.sealed, auditSinkAAD(a.ID))
		if err != nil {
			return nil, err
		}
		out = append(out, DueAuditSink{AuditSink: a, Key: key})
	}
	return out, nil
}

// AuditSinkDelivered moves the cursor past events the receiver acknowledged.
func (s *Store) AuditSinkDelivered(ctx context.Context, id uuid.UUID, cursor int64, n int) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_sink SET cursor = greatest(cursor, $2), delivered = delivered + $3,
			attempts = 0, last_status = NULL, last_error = NULL,
			status = CASE WHEN status = 'failing' THEN 'active' ELSE status END, next_attempt_at = now(),
			updated_at = now() WHERE id = $1`, id, cursor, n)
		return err
	})
}

// AuditSinkFailed records a failed delivery and backs off. Audit events are never skipped: the destination keeps
// retrying (at most hourly) until it accepts them or is disabled.
func (s *Store) AuditSinkFailed(ctx context.Context, id uuid.UUID, status int, msg string) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	msg = strings.ToValidUTF8(msg, "?")
	var st *int
	if status != 0 {
		st = &status
	}
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var attempts int
		if err := tx.QueryRow(ctx, `SELECT attempts FROM audit_sink WHERE id = $1 FOR UPDATE`, id).Scan(&attempts); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `UPDATE audit_sink SET attempts = attempts + 1, status = CASE WHEN status = 'active'
			THEN 'failing' ELSE status END, last_status = $2, last_error = $3, next_attempt_at = now() + $4::interval,
			updated_at = now() WHERE id = $1`, id, st, msg, Backoff(attempts+1).String())
		return err
	})
}
