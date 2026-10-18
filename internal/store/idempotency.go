package store

import (
	"bytes"
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StoredResponse is a response kept for an idempotency key.
type StoredResponse struct {
	Status      int
	Body        []byte
	ContentType string
}

var (
	// ErrIdempotencyInFlight: the first request with this key is still running.
	ErrIdempotencyInFlight = &InvalidError{Msg: "a request with this Idempotency-Key is still running; retry shortly"}
	// ErrIdempotencyMismatch: the key was used before for a different request.
	ErrIdempotencyMismatch = &InvalidError{Msg: "this Idempotency-Key was already used for a different request"}
)

// ClaimIdempotencyKey records that a request with this key is starting. It returns the stored response when the
// same request already completed, ErrIdempotencyInFlight when it is still running, ErrIdempotencyMismatch when the
// key was used for something else, and (nil, nil) when the caller should run the request.
func (s *Store) ClaimIdempotencyKey(ctx context.Context, principal uuid.UUID, key string, requestHash []byte) (*StoredResponse, error) {
	var out *StoredResponse
	err := s.tx(ctx, Scope{UserID: principal}, func(tx pgx.Tx) error {
		// keys live 24 hours; expired ones are cleared here rather than by a separate job
		if _, err := tx.Exec(ctx, `DELETE FROM idempotency_key WHERE created_at < now() - interval '24 hours'`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO idempotency_key (principal, key, request_hash) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, principal, key, requestHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var hash, body []byte
		var status *int
		var ctype *string
		if err := tx.QueryRow(ctx, `SELECT request_hash, status, response, content_type FROM idempotency_key
			WHERE principal = $1 AND key = $2`, principal, key).Scan(&hash, &status, &body, &ctype); err != nil {
			return mapErr(err)
		}
		switch {
		case !bytes.Equal(hash, requestHash):
			return ErrIdempotencyMismatch
		case status == nil:
			return ErrIdempotencyInFlight
		}
		out = &StoredResponse{Status: *status, Body: body}
		if ctype != nil {
			out.ContentType = *ctype
		}
		return nil
	})
	return out, err
}

// CompleteIdempotencyKey stores the response for replays.
func (s *Store) CompleteIdempotencyKey(ctx context.Context, principal uuid.UUID, key string, r StoredResponse) error {
	return s.tx(ctx, Scope{UserID: principal}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE idempotency_key SET status = $3, response = $4, content_type = $5
			WHERE principal = $1 AND key = $2`, principal, key, r.Status, r.Body, r.ContentType)
		return err
	})
}

// ReleaseIdempotencyKey forgets a key whose request failed on the server side, so the client can retry.
func (s *Store) ReleaseIdempotencyKey(ctx context.Context, principal uuid.UUID, key string) error {
	return s.tx(ctx, Scope{UserID: principal}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM idempotency_key WHERE principal = $1 AND key = $2 AND status IS NULL`,
			principal, key)
		return err
	})
}
