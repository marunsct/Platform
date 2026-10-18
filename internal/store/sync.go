package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Change is one outbox row as an app sees it (contract §5–§7).
type Change struct {
	Seq      int64           `json:"seq"`
	ID       int64           `json:"-"`
	Type     string          `json:"type"`
	Subject  string          `json:"subject"`
	TenantID *uuid.UUID      `json:"tenant_id"`
	Version  int64           `json:"version"`
	Time     time.Time       `json:"time"`
	Payload  json.RawMessage `json:"payload"`
}

// ErrGone is a feed cursor older than the outbox keeps (30 days): the app must take a snapshot.
var ErrGone = errors.New("cursor is older than the change feed keeps; take a snapshot")

const sequencerLock = 7351002

// Sequence gives committed outbox rows their feed position, in the order the sequencer sees them. Only one
// sequencer runs at a time (advisory lock); a caller that finds it busy returns 0 and leaves the work to it.
func (s *Store) Sequence(ctx context.Context) (int, error) {
	var n int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, sequencerLock).Scan(&got); err != nil || !got {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM outbox WHERE seq IS NULL ORDER BY id LIMIT 5000 FOR UPDATE`)
		if err != nil {
			return err
		}
		idList, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil || len(idList) == 0 {
			return err
		}
		n = len(idList)
		var last int64
		// only the lock holder draws from outbox_seq, so these n values are consecutive
		if err := tx.QueryRow(ctx, `SELECT max(nextval('outbox_seq')) FROM generate_series(1, $1)`, n).Scan(&last); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE outbox o SET seq = $2::bigint - $3::bigint + x.rn
			FROM (SELECT id, row_number() OVER (ORDER BY id) AS rn FROM unnest($1::bigint[]) AS id) x
			WHERE o.id = x.id`, idList, last, n)
		return err
	})
	return n, err
}

// appChangeFilter limits outbox rows to what one app may see (technical specification §8): its own manifest and
// roles, tenants that enabled it, its own grants and placements, and users who belong to those tenants. SCIM group
// membership events are for the OpenFGA syncer only (apps get the grants groups make).
// $1 is the app id, $2 its slug.
const appChangeFilter = `(o.type NOT LIKE 'matura.scim_group.%' AND (
	(o.type LIKE 'matura.app.%' AND (o.subject = 'apps/' || $2 OR o.subject LIKE 'apps/' || $2 || '/%'))
	OR (o.type LIKE 'matura.user.%' AND EXISTS (
		SELECT 1 FROM membership m JOIN tenant_app ta ON ta.tenant_id = m.tenant_id
		WHERE m.user_id = (o.payload->>'id')::uuid AND ta.app_id = $1 AND ta.status = 'enabled'))
	OR (o.tenant_id IS NOT NULL
		AND EXISTS (SELECT 1 FROM tenant_app ta WHERE ta.tenant_id = o.tenant_id AND ta.app_id = $1
			AND (ta.status = 'enabled' OR o.type LIKE 'matura.tenant_app.%'))
		AND (NOT o.payload ? 'app_id' OR o.payload->>'app_id' = $1::text))
))`

// Changes returns the app's changes after the cursor, in feed order, and the cursor to continue from.
func (s *Store) Changes(ctx context.Context, app App, after int64, limit int) ([]Change, int64, error) {
	if _, err := s.Sequence(ctx); err != nil {
		return nil, 0, err
	}
	limit = FeedLimit(limit)
	var out []Change
	next := after
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var pruned, head int64
		if err := tx.QueryRow(ctx, `SELECT pruned_through, (SELECT coalesce(max(seq), 0) FROM outbox)
			FROM outbox_horizon`).Scan(&pruned, &head); err != nil {
			return err
		}
		if after < pruned {
			return ErrGone
		}
		rows, err := tx.Query(ctx, `SELECT o.seq, o.id, o.type, o.subject, o.tenant_id, o.version, o.created_at, o.payload
			FROM outbox o WHERE o.seq > $3 AND o.seq <= $4 AND `+appChangeFilter+`
			ORDER BY o.seq LIMIT $5`, app.ID, app.Slug, after, head, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Change, error) {
			var c Change
			err := r.Scan(&c.Seq, &c.ID, &c.Type, &c.Subject, &c.TenantID, &c.Version, &c.Time, &c.Payload)
			return c, err
		})
		if err != nil {
			return err
		}
		// a short page means everything up to head was looked at, including rows this app may not see
		if len(out) == limit {
			next = out[len(out)-1].Seq
		} else {
			next = max(head, after)
		}
		return nil
	})
	return out, next, err
}

// FeedLimit is the page size used for a requested limit: 500 by default, at most 1000.
func FeedLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 500
	}
	return limit
}

// PruneOutbox deletes sequenced rows older than keep and moves the horizon, so stale cursors get ErrGone.
func (s *Store) PruneOutbox(ctx context.Context, keep time.Duration) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var through *int64
		if err := tx.QueryRow(ctx, `SELECT max(seq) FROM outbox WHERE seq IS NOT NULL AND created_at < now() - $1::interval`,
			keep.String()).Scan(&through); err != nil || through == nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM outbox WHERE seq <= $1`, *through)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		_, err = tx.Exec(ctx, `UPDATE outbox_horizon SET pruned_through = greatest(pruned_through, $1)`, *through)
		return err
	})
	return n, err
}

// Snapshot is the current state of one tenant as an app sees it, and the feed cursor to continue from.
type Snapshot struct {
	Cursor     int64        `json:"cursor"`
	Tenant     *Tenant      `json:"tenant,omitempty"`
	Workspaces []Workspace  `json:"workspaces,omitempty"`
	Users      []User       `json:"users,omitempty"`
	Members    []Membership `json:"memberships,omitempty"`
	Grants     []Grant      `json:"grants,omitempty"`
	Placement  *Placement   `json:"placement,omitempty"`
	Roles      []Role       `json:"roles"`
	Tenants    []uuid.UUID  `json:"tenants,omitempty"` // without a tenant: the tenants that enabled the app
}

// AppSnapshot returns the app's roles and, for a tenant that enabled the app, its full directory. Without a tenant
// it lists the tenants to snapshot next. The cursor is taken first, so replaying the feed from it can only repeat
// changes already included, which the version rule ignores.
func (s *Store) AppSnapshot(ctx context.Context, app App, tenantID uuid.UUID) (Snapshot, error) {
	if _, err := s.Sequence(ctx); err != nil {
		return Snapshot{}, err
	}
	var out Snapshot
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM outbox`).Scan(&out.Cursor); err != nil {
			return err
		}
		var err error
		if out.Roles, err = listRoles(ctx, tx, app.ID); err != nil {
			return err
		}
		if tenantID == uuid.Nil {
			rows, err := tx.Query(ctx, `SELECT tenant_id FROM tenant_app WHERE app_id = $1 AND status = 'enabled'
				ORDER BY tenant_id`, app.ID)
			if err != nil {
				return err
			}
			out.Tenants, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			return err
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_app WHERE tenant_id = $1 AND app_id = $2
			AND status = 'enabled')`, tenantID, app.ID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return ErrNotFound
		}
		t, err := scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1`, tenantID))
		if err != nil {
			return err
		}
		t = t.Contract()
		out.Tenant = &t
		rows, err := tx.Query(ctx, `SELECT `+workspaceCols+` FROM workspace WHERE tenant_id = $1 ORDER BY id`, tenantID)
		if err != nil {
			return err
		}
		if out.Workspaces, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Workspace, error) { return scanWorkspace(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+memberCols+` FROM membership m JOIN app_user u ON u.id = m.user_id
			WHERE m.tenant_id = $1 ORDER BY m.user_id`, tenantID)
		if err != nil {
			return err
		}
		if out.Members, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) { return scanMember(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+userCols+` FROM app_user WHERE id IN
			(SELECT user_id FROM membership WHERE tenant_id = $1) ORDER BY id`, tenantID)
		if err != nil {
			return err
		}
		if out.Users, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
			WHERE g.tenant_id = $1 AND g.app_id = $2 ORDER BY g.id`, tenantID, app.ID)
		if err != nil {
			return err
		}
		if out.Grants, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) }); err != nil {
			return err
		}
		p, err := scanPlacement(tx.QueryRow(ctx, `SELECT `+placementCols+` FROM placement WHERE tenant_id = $1
			AND app_id = $2`, tenantID, app.ID))
		switch {
		case err == nil:
			out.Placement = &p
		case err != ErrNotFound:
			return err
		}
		return nil
	})
	return out, err
}
