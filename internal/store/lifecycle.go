package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Tenant lifecycle (TN-3, TS10):
//
//	active ⇄ suspended                     :suspend (reason) / :resume, operators
//	active|suspended → pending_deletion    DELETE, owners and operators; restorable until purge_after
//	pending_deletion → (status before)     :restore, owners and operators
//	pending_deletion → deleting            the purger, after purge_after: apps delete the data, placements retire
//	deleting → deleted                     the purger, once every placement is deleted
//
// Apps see pending_deletion as suspended (Tenant.Contract): no access, data kept.

// TenantAction is a lifecycle change.
type TenantAction struct {
	Do        string        // suspend, resume, delete or restore
	Reason    string        // suspend: required; delete: optional
	Grace     time.Duration // delete: time until the purge
	IfVersion int64
}

// ChangeTenantStatus applies a lifecycle action and emits the tenant's contract event.
func (s *Store) ChangeTenantStatus(ctx context.Context, sc Scope, id uuid.UUID, a TenantAction) (Tenant, error) {
	var out Tenant
	err := s.tx(ctx, sc.InTenant(id), func(tx pgx.Tx) error {
		cur, err := scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if a.IfVersion != 0 && a.IfVersion != cur.Version {
			return ErrVersion
		}
		if cur.Status == "deleted" {
			return ErrNotFound
		}
		conflict := func(want string) error {
			return fmt.Errorf("%w: the tenant is %s; this needs it to be %s", ErrConflict, cur.Status, want)
		}
		var set, event string
		reason := nullable(strings.TrimSpace(a.Reason))
		switch a.Do {
		case "suspend":
			if reason == nil {
				return invalid("a reason is required to suspend a tenant")
			}
			if cur.Status != "active" && cur.Status != "suspended" {
				return conflict("active")
			}
			set, event = `status = 'suspended', status_reason = $3`, "tenant.suspended"
		case "resume":
			if cur.Status == "active" {
				out = cur
				return nil
			}
			if cur.Status != "suspended" {
				return conflict("suspended")
			}
			set, event = `status = 'active', status_reason = NULL`, "tenant.reactivated"
		case "delete":
			if cur.Status == "pending_deletion" {
				out = cur
				return nil
			}
			if cur.Status != "active" && cur.Status != "suspended" {
				return conflict("active or suspended")
			}
			// apps see pending_deletion as suspended: the same event as a suspension
			set = fmt.Sprintf(`status = 'pending_deletion', restore_status = status,
				status_reason = coalesce($3, status_reason), purge_after = now() + make_interval(secs => %d)`,
				int64(a.Grace/time.Second))
			event = "tenant.suspended"
			if cur.Status == "suspended" {
				event = "tenant.updated"
			}
		case "restore":
			if cur.Status != "pending_deletion" {
				return conflict("pending deletion")
			}
			set = `status = coalesce(restore_status, 'active'), restore_status = NULL, purge_after = NULL,
				status_reason = CASE WHEN restore_status = 'suspended' THEN status_reason END`
			event = "tenant.updated"
		default:
			return invalid("unknown action %q", a.Do)
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		args := []any{id, v}
		if strings.Contains(set, "$3") {
			args = append(args, reason)
		}
		out, err = scanTenant(tx.QueryRow(ctx, `UPDATE tenant SET `+set+`, version = $2, updated_at = now()
			WHERE id = $1 RETURNING `+tenantCols, args...))
		if err != nil {
			return err
		}
		if a.Do == "restore" && out.Status == "active" {
			event = "tenant.reactivated"
		}
		return emit(ctx, tx, v, id, event, "tenants/"+id.String(), out.Contract())
	})
	return out, err
}

// PurgeDueTenants moves tenants whose grace period is over to deleting: each app is told to delete their data
// (tenant.deleting) and their placements retire, pending invitations are revoked and support access ends.
// It returns how many tenants it purged.
func (s *Store) PurgeDueTenants(ctx context.Context) (int, error) {
	var due []uuid.UUID
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenant WHERE status = 'pending_deletion' AND purge_after <= now()
			ORDER BY purge_after LIMIT 100`)
		if err != nil {
			return err
		}
		due, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range due {
		err := s.tx(ctx, Scope{Operator: true, TenantID: id}, func(tx pgx.Tx) error {
			v, err := nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			t, err := scanTenant(tx.QueryRow(ctx, `UPDATE tenant SET status = 'deleting', restore_status = NULL,
				version = $2, updated_at = now() WHERE id = $1 AND status = 'pending_deletion' AND purge_after <= now()
				RETURNING `+tenantCols, id, v))
			if err != nil {
				return err
			}
			if err := emit(ctx, tx, v, id, "tenant.deleting", "tenants/"+id.String(), t.Contract()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE invitation SET state = 'revoked' WHERE tenant_id = $1
				AND state = 'pending'`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE support_access SET state = 'ended', ended_at = now()
				WHERE tenant_id = $1 AND state IN ('pending', 'approved')`, id); err != nil {
				return err
			}
			return retirePlacements(ctx, tx, id)
		})
		if errors.Is(err, ErrNotFound) { // restored meanwhile
			continue
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// FinishDeletedTenants marks deleting tenants deleted once none of their placements holds data any more.
func (s *Store) FinishDeletedTenants(ctx context.Context) (int, error) {
	n := 0
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenant t WHERE status = 'deleting' AND NOT EXISTS
			(SELECT 1 FROM placement p WHERE p.tenant_id = t.id AND p.state <> 'deleted') LIMIT 100 FOR UPDATE`)
		if err != nil {
			return err
		}
		done, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range done {
			v, err := nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			t, err := scanTenant(tx.QueryRow(ctx, `UPDATE tenant SET status = 'deleted', version = $2,
				updated_at = now() WHERE id = $1 RETURNING `+tenantCols, id, v))
			if err != nil {
				return err
			}
			if err := emit(ctx, tx, v, id, "tenant.deleted", "tenants/"+id.String(), t.Contract()); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// TenantAccessOf returns the user's active membership in a tenant and the tenant's status, in one transaction.
// ErrNotFound when the user is not an active member.
func (s *Store) TenantAccessOf(ctx context.Context, tenantID, userID uuid.UUID) (Membership, string, error) {
	var m Membership
	var status string
	err := s.tx(ctx, Scope{TenantID: tenantID, UserID: userID}, func(tx pgx.Tx) error {
		var err error
		m, err = getMember(ctx, tx, tenantID, userID, false)
		if err == nil && m.Status != "active" {
			err = ErrNotFound
		}
		if err != nil {
			return err
		}
		return mapErr(tx.QueryRow(ctx, `SELECT status FROM tenant WHERE id = $1`, tenantID).Scan(&status))
	})
	return m, status, err
}

// --- operator views -----------------------------------------------------------------------------------------------

// TenantSummary is a row of the operator's tenant list.
type TenantSummary struct {
	Tenant
	MemberCount int `json:"member_count"`
}

type TenantQuery struct {
	Q        string   // matches slug or name
	Statuses []string // empty: every status but deleted
	Cursor   string   // from the previous page
	Limit    int
}

var tenantStatuses = map[string]bool{"provisioning": true, "active": true, "suspended": true,
	"pending_deletion": true, "deleting": true, "deleted": true}

// ListTenantsAdmin pages through every tenant by slug (operators), with active member counts. next is empty on
// the last page.
func (s *Store) ListTenantsAdmin(ctx context.Context, sc Scope, q TenantQuery) (items []TenantSummary, next string, err error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	for _, st := range q.Statuses {
		if !tenantStatuses[st] {
			return nil, "", invalid("status %q is not a tenant status", st)
		}
	}
	after := ""
	if q.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		if err != nil {
			return nil, "", invalid("cursor is not one this API returned")
		}
		after = string(b)
	}
	if q.Statuses == nil {
		q.Statuses = []string{}
	}
	err = s.tx(ctx, sc, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tenantColsOf("t")+`,
				(SELECT count(*) FROM membership m WHERE m.tenant_id = t.id AND m.status = 'active')
			FROM tenant t
			WHERE ($1 = '' OR t.slug ILIKE '%' || $1 || '%' OR t.name ILIKE '%' || $1 || '%')
				AND (CASE WHEN cardinality($2::text[]) = 0 THEN t.status <> 'deleted' ELSE t.status = ANY($2) END)
				AND t.slug > $3
			ORDER BY t.slug LIMIT $4`, q.Q, q.Statuses, after, q.Limit+1)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TenantSummary, error) {
			var ts TenantSummary
			err := r.Scan(append(tenantDest(&ts.Tenant), &ts.MemberCount)...)
			return ts, err
		})
		return err
	})
	if len(items) > q.Limit {
		items = items[:q.Limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].Slug))
	}
	return items, next, err
}

// Stats is the operator dashboard's count of tenants, users and apps.
type Stats struct {
	Tenants map[string]int `json:"tenants"` // by status, plus "total"
	Users   map[string]int `json:"users"`   // by status, plus "total"
	Apps    AppStats       `json:"apps"`
}

type AppStats struct {
	Total int           `json:"total"`
	Items []AppTenantCt `json:"items"`
}

type AppTenantCt struct {
	App     string `json:"app"`
	Status  string `json:"status"`
	Tenants int    `json:"tenants"` // tenants that enabled it
}

func (s *Store) Stats(ctx context.Context, sc Scope) (Stats, error) {
	out := Stats{Tenants: map[string]int{"total": 0}, Users: map[string]int{"total": 0}, Apps: AppStats{Items: []AppTenantCt{}}}
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		for _, c := range []struct {
			q string
			m map[string]int
		}{
			{`SELECT status, count(*) FROM tenant GROUP BY status`, out.Tenants},
			{`SELECT status, count(*) FROM app_user GROUP BY status`, out.Users},
		} {
			rows, err := tx.Query(ctx, c.q)
			if err != nil {
				return err
			}
			var st string
			var n int
			if _, err := pgx.ForEachRow(rows, []any{&st, &n}, func() error {
				c.m[st] = n
				c.m["total"] += n
				return nil
			}); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT a.slug, a.status, count(ta.tenant_id) FILTER (WHERE ta.status = 'enabled')
			FROM app a LEFT JOIN tenant_app ta ON ta.app_id = a.id GROUP BY a.slug, a.status ORDER BY a.slug`)
		if err != nil {
			return err
		}
		out.Apps.Items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AppTenantCt, error) {
			var a AppTenantCt
			err := r.Scan(&a.App, &a.Status, &a.Tenants)
			return a, err
		})
		out.Apps.Total = len(out.Apps.Items)
		return err
	})
	return out, err
}
