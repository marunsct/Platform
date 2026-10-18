package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Backlog is the work waiting in maturad's queues, for metrics.
type Backlog struct {
	UnsequencedEvents int64   // changes not yet given a feed position
	WebhookLag        int64   // largest number of events an active endpoint is behind
	WebhooksFailing   int64   // endpoints in the failing state
	EmailsPending     int64   // emails waiting to be sent
	OldestEmailAge    float64 // seconds the oldest pending email has waited
}

// Backlog reads the queue sizes in operator scope.
func (s *Store) Backlog(ctx context.Context) (Backlog, error) {
	var b Backlog
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM outbox WHERE seq IS NULL),
			coalesce((SELECT max(h.max_seq - w.cursor) FROM webhook_endpoint w,
				(SELECT coalesce(max(seq), 0) AS max_seq FROM outbox) h WHERE w.status <> 'disabled'), 0),
			(SELECT count(*) FROM webhook_endpoint WHERE status = 'failing'),
			(SELECT count(*) FROM email_outbox WHERE state = 'pending'),
			coalesce((SELECT extract(epoch FROM now() - min(created_at)) FROM email_outbox WHERE state = 'pending'), 0)`).
			Scan(&b.UnsequencedEvents, &b.WebhookLag, &b.WebhooksFailing, &b.EmailsPending, &b.OldestEmailAge)
	})
	return b, err
}
