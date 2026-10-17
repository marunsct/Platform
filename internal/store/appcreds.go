package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/secrets"
)

// --- app secrets --------------------------------------------------------------------------------------------------

// AppSecret describes a secret without revealing it; Secret is set only in the response that creates it.
type AppSecret struct {
	ID         uuid.UUID  `json:"id"`
	App        string     `json:"app"`
	ClientID   string     `json:"client_id"`
	Label      string     `json:"label"`
	Secret     string     `json:"secret,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func randomSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hashSecret(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// CreateAppSecret issues a secret the app's backend uses with its client id (HTTP Basic) to read its change feed,
// snapshots and placements. Only a hash is kept. sc must be operator scope.
func (s *Store) CreateAppSecret(ctx context.Context, sc Scope, appSlug, label string) (AppSecret, error) {
	secret, err := randomSecret("mts_")
	if err != nil {
		return AppSecret{}, err
	}
	var out AppSecret
	err = s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		out = AppSecret{ID: ids.New(), App: app.Slug, ClientID: app.ClientID, Label: label, Secret: secret}
		if err := tx.QueryRow(ctx, `INSERT INTO app_secret (id, app_id, label, secret_hash) VALUES ($1, $2, $3, $4)
			RETURNING created_at`, out.ID, app.ID, label, hashSecret(secret)).Scan(&out.CreatedAt); err != nil {
			return err
		}
		return audit(ctx, tx, uuid.Nil, "app.secret.created", "apps/"+app.Slug+"/secrets/"+out.ID.String(),
			map[string]any{"id": out.ID, "app": app.Slug, "label": label})
	})
	return out, err
}

func (s *Store) ListAppSecrets(ctx context.Context, sc Scope, appSlug string) ([]AppSecret, error) {
	var out []AppSecret
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, label, created_at, last_used_at, revoked_at FROM app_secret
			WHERE app_id = $1 ORDER BY created_at`, app.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AppSecret, error) {
			a := AppSecret{App: app.Slug, ClientID: app.ClientID}
			err := r.Scan(&a.ID, &a.Label, &a.CreatedAt, &a.LastUsedAt, &a.RevokedAt)
			return a, err
		})
		return err
	})
	return out, err
}

func (s *Store) RevokeAppSecret(ctx context.Context, sc Scope, appSlug string, id uuid.UUID) error {
	return s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE app_secret SET revoked_at = now() WHERE id = $1 AND app_id = $2
			AND revoked_at IS NULL`, id, app.ID)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, uuid.Nil, "app.secret.revoked", "apps/"+app.Slug+"/secrets/"+id.String(),
			map[string]any{"id": id, "app": app.Slug})
	})
}

// AuthenticateApp returns the active app whose client id and secret match. Any mismatch is ErrNotFound.
func (s *Store) AuthenticateApp(ctx context.Context, clientID, secret string) (App, error) {
	var out App
	err := s.tx(ctx, Scope{}, func(tx pgx.Tx) error {
		var sid uuid.UUID
		var used *time.Time
		err := tx.QueryRow(ctx, `SELECT a.id, a.slug, a.name, a.client_id, a.manifest, a.status, a.version, s.id, s.last_used_at
			FROM app_secret s JOIN app a ON a.id = s.app_id
			WHERE s.secret_hash = $1 AND s.revoked_at IS NULL AND a.client_id = $2 AND a.status = 'active'`,
			hashSecret(secret), clientID).Scan(&out.ID, &out.Slug, &out.Name, &out.ClientID, rawManifest{&out.Manifest},
			&out.Status, &out.Version, &sid, &used)
		if err != nil {
			return mapErr(err)
		}
		if used == nil || time.Since(*used) > time.Minute {
			_, err = tx.Exec(ctx, `UPDATE app_secret SET last_used_at = now() WHERE id = $1`, sid)
		}
		return err
	})
	return out, err
}

// --- webhook endpoints --------------------------------------------------------------------------------------------

type Webhook struct {
	ID            uuid.UUID  `json:"id"`
	App           string     `json:"app"`
	URL           string     `json:"url"`
	Secret        string     `json:"secret,omitempty"` // only when created
	Status        string     `json:"status"`
	Cursor        int64      `json:"cursor"`
	Attempts      int        `json:"attempts"`
	FirstFailedAt *time.Time `json:"first_failed_at"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastStatus    *int       `json:"last_status"`
	LastError     *string    `json:"last_error"`
	Delivered     int64      `json:"delivered"`
	Dropped       int64      `json:"dropped"`
	CreatedAt     time.Time  `json:"created_at"`

	appID  uuid.UUID
	sealed []byte
}

const webhookCols = `w.id, a.slug, w.url, w.status, w.cursor, w.attempts, w.first_failed_at, w.next_attempt_at,
	w.last_status, w.last_error, w.delivered, w.dropped, w.created_at, w.app_id, w.secret`

func scanWebhook(row pgx.Row) (Webhook, error) {
	var h Webhook
	err := row.Scan(&h.ID, &h.App, &h.URL, &h.Status, &h.Cursor, &h.Attempts, &h.FirstFailedAt, &h.NextAttemptAt,
		&h.LastStatus, &h.LastError, &h.Delivered, &h.Dropped, &h.CreatedAt, &h.appID, &h.sealed)
	return h, mapErr(err)
}

func webhookAAD(id uuid.UUID) string { return "webhook:" + id.String() }

func validWebhookURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) || u.User != nil {
		return invalid("webhook url must be an https:// URL without credentials")
	}
	return nil
}

// AllowHTTPWebhooks lets development installs deliver to http:// URLs (MATURA_ENV=development).
var AllowHTTPWebhooks = false

// CreateWebhook registers an endpoint for an app. It starts at the current end of the feed: history comes from a
// snapshot and the feed, not from a burst of old webhooks. sc must be operator scope.
func (s *Store) CreateWebhook(ctx context.Context, sc Scope, km secrets.KeyManager, appSlug, rawURL string) (Webhook, error) {
	if err := validWebhookURL(rawURL, AllowHTTPWebhooks); err != nil {
		return Webhook{}, err
	}
	if _, err := s.Sequence(ctx); err != nil {
		return Webhook{}, err
	}
	secret, err := randomSecret("whsec_")
	if err != nil {
		return Webhook{}, err
	}
	id := ids.New()
	sealed, err := km.Seal([]byte(secret), webhookAAD(id))
	if err != nil {
		return Webhook{}, err
	}
	var out Webhook
	err = s.tx(ctx, sc, func(tx pgx.Tx) error {
		app, err := getAppBySlug(ctx, tx, appSlug)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO webhook_endpoint (id, app_id, url, secret, cursor)
			VALUES ($1, $2, $3, $4, (SELECT coalesce(max(seq), 0) FROM outbox))`, id, app.ID, rawURL, sealed); err != nil {
			return mapErr(err)
		}
		out, err = scanWebhook(tx.QueryRow(ctx, `SELECT `+webhookCols+` FROM webhook_endpoint w
			JOIN app a ON a.id = w.app_id WHERE w.id = $1`, id))
		if err != nil {
			return err
		}
		return auditWebhook(ctx, tx, "app.webhook.created", out)
	})
	out.Secret = secret
	return out, err
}

func (s *Store) ListWebhooks(ctx context.Context, sc Scope, appSlug string) ([]Webhook, error) {
	var out []Webhook
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+webhookCols+` FROM webhook_endpoint w JOIN app a ON a.id = w.app_id
			WHERE a.slug = $1 ORDER BY w.created_at`, appSlug)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Webhook, error) { return scanWebhook(r) })
		return err
	})
	return out, err
}

type WebhookPatch struct {
	URL    *string
	Status *string // active or disabled; failing is set by delivery
}

func (s *Store) UpdateWebhook(ctx context.Context, sc Scope, appSlug string, id uuid.UUID, p WebhookPatch) (Webhook, error) {
	if p.URL != nil {
		if err := validWebhookURL(*p.URL, AllowHTTPWebhooks); err != nil {
			return Webhook{}, err
		}
	}
	if p.Status != nil && *p.Status != "active" && *p.Status != "disabled" {
		return Webhook{}, invalid("status can be active or disabled")
	}
	var out Webhook
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		// re-enabling retries at once
		tag, err := tx.Exec(ctx, `UPDATE webhook_endpoint w SET url = coalesce($3::text, w.url), status = coalesce($4::text, w.status),
			next_attempt_at = CASE WHEN $4::text = 'active' THEN now() ELSE w.next_attempt_at END, updated_at = now()
			FROM app a WHERE a.id = w.app_id AND a.slug = $1 AND w.id = $2`, appSlug, id, p.URL, p.Status)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		out, err = scanWebhook(tx.QueryRow(ctx, `SELECT `+webhookCols+` FROM webhook_endpoint w
			JOIN app a ON a.id = w.app_id WHERE w.id = $1`, id))
		if err != nil {
			return err
		}
		return auditWebhook(ctx, tx, "app.webhook.updated", out)
	})
	return out, err
}

func (s *Store) DeleteWebhook(ctx context.Context, sc Scope, appSlug string, id uuid.UUID) error {
	return s.tx(ctx, sc, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM webhook_endpoint w USING app a WHERE a.id = w.app_id AND a.slug = $1
			AND w.id = $2`, appSlug, id)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, uuid.Nil, "app.webhook.deleted", "apps/"+appSlug+"/webhooks/"+id.String(),
			map[string]any{"id": id, "app": appSlug})
	})
}

// DueWebhook is an endpoint ready for its next delivery, with its secret opened.
type DueWebhook struct {
	Webhook
	AppRef App
	Key    []byte
}

// DueWebhooks returns endpoints whose next attempt is due. Only the relay leader calls it.
func (s *Store) DueWebhooks(ctx context.Context, km secrets.KeyManager, limit int) ([]DueWebhook, error) {
	var hooks []Webhook
	var apps = map[uuid.UUID]App{}
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+webhookCols+` FROM webhook_endpoint w JOIN app a ON a.id = w.app_id
			WHERE w.status <> 'disabled' AND w.next_attempt_at <= now() AND a.status = 'active'
			ORDER BY w.next_attempt_at LIMIT $1`, limit)
		if err != nil {
			return err
		}
		if hooks, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Webhook, error) { return scanWebhook(r) }); err != nil {
			return err
		}
		for _, h := range hooks {
			if _, ok := apps[h.appID]; ok {
				continue
			}
			a, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE id = $1`, h.appID))
			if err != nil {
				return err
			}
			apps[h.appID] = a
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]DueWebhook, 0, len(hooks))
	for _, h := range hooks {
		key, err := km.Open(h.sealed, webhookAAD(h.ID))
		if err != nil {
			return nil, err
		}
		out = append(out, DueWebhook{Webhook: h, AppRef: apps[h.appID], Key: key})
	}
	return out, nil
}

// WebhookDelivered moves the endpoint's cursor past delivered events (and past events it may not see).
func (s *Store) WebhookDelivered(ctx context.Context, id uuid.UUID, cursor int64, delivered int, next time.Time) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE webhook_endpoint SET cursor = greatest(cursor, $2), delivered = delivered + $3,
			attempts = 0, first_failed_at = NULL, status = CASE WHEN status = 'failing' THEN 'active' ELSE status END,
			next_attempt_at = $4, updated_at = now() WHERE id = $1`, id, cursor, delivered, next)
		return err
	})
}

// WebhookFailed records a failed attempt for the event after the cursor. After giveUp of failures the event is
// skipped (the app's feed reader still gets it) and the endpoint is marked failing.
func (s *Store) WebhookFailed(ctx context.Context, id uuid.UUID, failedSeq int64, status int, msg string, giveUp time.Duration) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	msg = strings.ToValidUTF8(msg, "?")
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var attempts int
		var first *time.Time
		if err := tx.QueryRow(ctx, `SELECT attempts, first_failed_at FROM webhook_endpoint WHERE id = $1 FOR UPDATE`, id).
			Scan(&attempts, &first); err != nil {
			return mapErr(err)
		}
		var st *int
		if status != 0 {
			st = &status
		}
		if first != nil && time.Since(*first) > giveUp {
			_, err := tx.Exec(ctx, `UPDATE webhook_endpoint SET cursor = greatest(cursor, $2), dropped = dropped + 1,
				attempts = 0, first_failed_at = NULL, status = 'failing', last_status = $3, last_error = $4,
				next_attempt_at = now(), updated_at = now() WHERE id = $1`, id, failedSeq, st, msg)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE webhook_endpoint SET attempts = attempts + 1,
			first_failed_at = coalesce(first_failed_at, now()), last_status = $2, last_error = $3,
			next_attempt_at = now() + $4::interval, updated_at = now() WHERE id = $1`,
			id, st, msg, Backoff(attempts+1).String())
		return err
	})
}

// Backoff is the wait before attempt n+1: 1 s doubling to at most 1 h (technical specification §8).
func Backoff(n int) time.Duration {
	if n > 12 {
		return time.Hour
	}
	return min(time.Second<<(n-1), time.Hour)
}

// WebhookKey opens an endpoint's signing secret, for the test delivery.
func (s *Store) WebhookKey(ctx context.Context, km secrets.KeyManager, id uuid.UUID) ([]byte, error) {
	var sealed []byte
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT secret FROM webhook_endpoint WHERE id = $1`, id).Scan(&sealed))
	})
	if err != nil {
		return nil, err
	}
	return km.Open(sealed, webhookAAD(id))
}

func auditWebhook(ctx context.Context, tx pgx.Tx, action string, h Webhook) error {
	return audit(ctx, tx, uuid.Nil, action, "apps/"+h.App+"/webhooks/"+h.ID.String(),
		map[string]any{"id": h.ID, "app": h.App, "url": h.URL, "status": h.Status})
}
