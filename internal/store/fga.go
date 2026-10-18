package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Fine-grained permissions (TS11): bookkeeping for the OpenFGA store, and the facts and changes internal/access
// writes to it. Everything here is installation-wide and runs with operator scope.

// FGAState is the installation's OpenFGA store, base model and sync cursor.
type FGAState struct {
	StoreID     string
	BaseModelID string
	BaseHash    string
	Cursor      *int64 // nil: write every current fact again
	SyncedAt    *time.Time
}

func (s *Store) FGAState(ctx context.Context) (FGAState, error) {
	var out FGAState
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(store_id, ''), coalesce(base_model_id, ''), coalesce(base_hash, ''),
			cursor, synced_at FROM fga_state`).Scan(&out.StoreID, &out.BaseModelID, &out.BaseHash, &out.Cursor, &out.SyncedAt)
	})
	return out, err
}

// SetFGAStore records the store; a store other than the one recorded starts over: no models, no cursor.
func (s *Store) SetFGAStore(ctx context.Context, storeID string) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var cur *string
		if err := tx.QueryRow(ctx, `SELECT store_id FROM fga_state FOR UPDATE`).Scan(&cur); err != nil {
			return err
		}
		if cur != nil && *cur == storeID {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM fga_app_model`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE fga_state SET store_id = $1, base_model_id = NULL, base_hash = NULL,
			cursor = NULL, synced_at = NULL`, storeID)
		return err
	})
}

// ForgetFGAModels drops the recorded model ids (OpenFGA lost them); the store id and cursor stay.
func (s *Store) ForgetFGAModels(ctx context.Context) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM fga_app_model`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE fga_state SET base_model_id = NULL, base_hash = NULL`)
		return err
	})
}

func (s *Store) SetFGABaseModel(ctx context.Context, id, hash string) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE fga_state SET base_model_id = $1, base_hash = $2`, id, hash)
		return err
	})
}

// SetFGACursor records how far the sync has applied the outbox; nil makes the next round write everything again.
func (s *Store) SetFGACursor(ctx context.Context, cursor *int64) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE fga_state SET cursor = $1, synced_at = now()`, cursor)
		return err
	})
}

// FGAAppModel returns the OpenFGA model id written for the app's model with this hash ("" when none).
func (s *Store) FGAAppModel(ctx context.Context, appID uuid.UUID, hash string) (string, error) {
	var id string
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT model_id FROM fga_app_model WHERE app_id = $1 AND model_hash = $2`,
			appID, hash).Scan(&id)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	})
	return id, err
}

func (s *Store) SetFGAAppModel(ctx context.Context, appID uuid.UUID, hash, modelID string) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO fga_app_model (app_id, model_hash, model_id) VALUES ($1, $2, $3)
			ON CONFLICT (app_id) DO UPDATE SET model_hash = EXCLUDED.model_hash, model_id = EXCLUDED.model_id,
				written_at = now()`, appID, hash, modelID)
		return err
	})
}

// AppTenantStatus says whether the tenant enabled the app and, if so, the tenant's status. A tenant that did not
// enable the app (or does not exist) is ErrNotFound, so apps cannot probe other tenants.
func (s *Store) AppTenantStatus(ctx context.Context, app App, tenantID uuid.UUID) (string, error) {
	var status string
	err := s.tx(ctx, Scope{TenantID: tenantID, Operator: true}, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT t.status FROM tenant_app ta JOIN tenant t ON t.id = ta.tenant_id
			WHERE ta.tenant_id = $1 AND ta.app_id = $2 AND ta.status = 'enabled'`, tenantID, app.ID).Scan(&status))
	})
	return status, err
}

// OutboxAfter returns up to limit sequenced outbox rows after the cursor, of every tenant and app, in feed order.
// A cursor older than the feed keeps is ErrGone.
func (s *Store) OutboxAfter(ctx context.Context, after int64, limit int) ([]Change, error) {
	if _, err := s.Sequence(ctx); err != nil {
		return nil, err
	}
	var out []Change
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var pruned int64
		if err := tx.QueryRow(ctx, `SELECT pruned_through FROM outbox_horizon`).Scan(&pruned); err != nil {
			return err
		}
		if after < pruned {
			return ErrGone
		}
		rows, err := tx.Query(ctx, `SELECT o.seq, o.id, o.type, o.subject, o.tenant_id, o.version, o.created_at, o.payload
			FROM outbox o WHERE o.seq > $1 ORDER BY o.seq LIMIT $2`, after, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Change, error) {
			var c Change
			err := r.Scan(&c.Seq, &c.ID, &c.Type, &c.Subject, &c.TenantID, &c.Version, &c.Time, &c.Payload)
			return c, err
		})
		return err
	})
	return out, err
}

// AccessFacts is everything maturad mirrors into OpenFGA, and the outbox position it was read at.
type AccessFacts struct {
	Cursor     int64
	Members    []Membership // active
	Workspaces []Workspace  // not deleted
	Grants     []Grant      // active
	Groups     []SCIMGroupMember
}

// FGAFacts reads the current facts of every tenant that is not deleted. The cursor is taken first, so replaying the
// outbox from it repeats at most changes already included, which writes ignore.
func (s *Store) FGAFacts(ctx context.Context) (AccessFacts, error) {
	if _, err := s.Sequence(ctx); err != nil {
		return AccessFacts{}, err
	}
	var out AccessFacts
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM outbox`).Scan(&out.Cursor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+memberCols+` FROM membership m JOIN app_user u ON u.id = m.user_id
			JOIN tenant t ON t.id = m.tenant_id WHERE m.status = 'active' AND t.status NOT IN ('deleting', 'deleted')
			ORDER BY m.tenant_id, m.user_id`)
		if err != nil {
			return err
		}
		if out.Members, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) { return scanMember(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+workspaceCols+` FROM workspace w WHERE status NOT IN ('deleting', 'deleted')
			AND EXISTS (SELECT 1 FROM tenant t WHERE t.id = w.tenant_id AND t.status NOT IN ('deleting', 'deleted')) ORDER BY tenant_id, id`)
		if err != nil {
			return err
		}
		if out.Workspaces, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Workspace, error) { return scanWorkspace(r) }); err != nil {
			return err
		}
		if out.Grants, err = activeGrants(ctx, tx, uuid.Nil); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT m.tenant_id, m.group_id, m.user_id FROM scim_group_member m
			JOIN tenant t ON t.id = m.tenant_id WHERE t.status NOT IN ('deleting', 'deleted')
			ORDER BY m.tenant_id, m.group_id, m.user_id`)
		if err != nil {
			return err
		}
		out.Groups, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SCIMGroupMember, error) {
			var g SCIMGroupMember
			return g, r.Scan(&g.TenantID, &g.GroupID, &g.UserID)
		})
		return err
	})
	return out, err
}

// AppGrants returns the app's active grants in every tenant (after a role is renamed).
func (s *Store) AppGrants(ctx context.Context, appID uuid.UUID) ([]Grant, error) {
	var out []Grant
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var err error
		out, err = activeGrants(ctx, tx, appID)
		return err
	})
	return out, err
}

func activeGrants(ctx context.Context, tx pgx.Tx, appID uuid.UUID) ([]Grant, error) {
	rows, err := tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
		JOIN tenant t ON t.id = g.tenant_id
		WHERE g.status = 'active' AND t.status NOT IN ('deleting', 'deleted') AND ($1::uuid IS NULL OR g.app_id = $1)
		ORDER BY g.tenant_id, g.id`, nullUUID(appID))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
