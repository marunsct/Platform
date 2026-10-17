package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Email is a message in the email outbox. It is queued in the same transaction as the change that sends it, so a
// rolled-back change sends nothing and a committed one is delivered even if maturad restarts.
type Email struct {
	ID       int64
	TenantID uuid.UUID
	To       string
	Subject  string
	Body     string
	Attempts int
}

// MaxEmailAttempts is how often the mailer tries before marking a message failed.
const MaxEmailAttempts = 8

func enqueueEmail(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, e Email) error {
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	_, err := tx.Exec(ctx, `INSERT INTO email_outbox (tenant_id, to_address, subject, body_text) VALUES ($1, $2, $3, $4)`,
		tid, e.To, e.Subject, e.Body)
	return err
}

// DueEmails returns pending messages whose next attempt is due, oldest first (the mailer's work list).
func (s *Store) DueEmails(ctx context.Context, limit int) ([]Email, error) {
	var out []Email
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'),
			to_address, subject, body_text, attempts FROM email_outbox
			WHERE state = 'pending' AND next_attempt_at <= now() ORDER BY id LIMIT $1`, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Email, error) {
			var e Email
			return e, r.Scan(&e.ID, &e.TenantID, &e.To, &e.Subject, &e.Body, &e.Attempts)
		})
		return err
	})
	return out, err
}

func (s *Store) EmailSent(ctx context.Context, id int64) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE email_outbox SET state = 'sent', sent_at = now(), attempts = attempts + 1,
			last_error = NULL WHERE id = $1`, id)
		return err
	})
}

// EmailFailed records a failed attempt; the message is retried with backoff until MaxEmailAttempts.
func (s *Store) EmailFailed(ctx context.Context, id int64, attempts int, reason string) error {
	backoff := time.Duration(1<<min(attempts, 6)) * time.Minute // 1, 2, 4 … 64 minutes
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE email_outbox SET attempts = attempts + 1, last_error = $2,
			next_attempt_at = now() + $3 * interval '1 second',
			state = CASE WHEN attempts + 1 >= $4 THEN 'failed' ELSE 'pending' END WHERE id = $1`,
			id, reason, int64(backoff.Seconds()), MaxEmailAttempts)
		return err
	})
}
