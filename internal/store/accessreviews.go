package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// Access reviews (TS11, technical specification §18.4).

type AccessReview struct {
	ID          uuid.UUID          `json:"id"`
	TenantID    uuid.UUID          `json:"tenant_id"`
	Name        string             `json:"name"`
	Status      string             `json:"status"`
	OnPending   string             `json:"on_pending"`
	DueAt       time.Time          `json:"due_at"`
	CreatedBy   *uuid.UUID         `json:"created_by"`
	CreatedAt   time.Time          `json:"created_at"`
	CompletedAt *time.Time         `json:"completed_at"`
	CompletedBy *uuid.UUID         `json:"completed_by"`
	Kept        int                `json:"kept"`
	Revoked     int                `json:"revoked"`
	Version     int64              `json:"version"`
	Pending     int                `json:"pending"`
	Items       []AccessReviewItem `json:"items,omitempty"`
}

type AccessReviewItem struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"`
	GrantID     *uuid.UUID `json:"grant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	UserKind    string     `json:"user_kind"`
	Email       *string    `json:"email"`
	DisplayName *string    `json:"display_name"`
	App         *string    `json:"app"`
	Role        string     `json:"role"`
	WorkspaceID *uuid.UUID `json:"workspace_id"`
	Decision    string     `json:"decision"`
	DecidedBy   *uuid.UUID `json:"decided_by"`
	DecidedAt   *time.Time `json:"decided_at"`
	Note        *string    `json:"note"`
	Outcome     *string    `json:"outcome"`
}

const reviewCols = `r.id, r.tenant_id, r.name, r.status, r.on_pending, r.due_at, r.created_by, r.created_at,
	r.completed_at, r.completed_by, r.kept, r.revoked, r.version,
	(SELECT count(*) FROM access_review_item i WHERE i.review_id = r.id AND i.decision = 'pending')`

func scanReview(row pgx.Row) (AccessReview, error) {
	var r AccessReview
	err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Status, &r.OnPending, &r.DueAt, &r.CreatedBy, &r.CreatedAt,
		&r.CompletedAt, &r.CompletedBy, &r.Kept, &r.Revoked, &r.Version, &r.Pending)
	return r, err
}

const reviewItemCols = `i.id, i.kind, i.grant_id, i.user_id, u.kind, u.email, u.display_name, i.app, i.role,
	i.workspace_id, i.decision, i.decided_by, i.decided_at, i.note, i.outcome`

func reviewItems(ctx context.Context, tx pgx.Tx, reviewID uuid.UUID) ([]AccessReviewItem, error) {
	rows, err := tx.Query(ctx, `SELECT `+reviewItemCols+` FROM access_review_item i JOIN app_user u ON u.id = i.user_id
		WHERE i.review_id = $1 ORDER BY u.email NULLS LAST, i.kind, i.app, i.role`, reviewID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AccessReviewItem, error) {
		var it AccessReviewItem
		err := r.Scan(&it.ID, &it.Kind, &it.GrantID, &it.UserID, &it.UserKind, &it.Email, &it.DisplayName, &it.App,
			&it.Role, &it.WorkspaceID, &it.Decision, &it.DecidedBy, &it.DecidedAt, &it.Note, &it.Outcome)
		return it, err
	})
}

func reviewSubject(r AccessReview) string {
	return "tenants/" + r.TenantID.String() + "/access-reviews/" + r.ID.String()
}

// NewAccessReview starts a review.
type NewAccessReview struct {
	Name      string
	DueAt     time.Time
	OnPending string   // revoke (default) or keep
	Apps      []string // only these apps' grants; empty: every app
	NoRoles   bool     // leave tenant roles out
}

// StartAccessReview snapshots the tenant's active app role grants (of the apps asked) and its owner, admin and
// billing tenant roles as items to decide.
func (s *Store) StartAccessReview(ctx context.Context, sc Scope, tenantID uuid.UUID, in NewAccessReview) (AccessReview, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 {
		return AccessReview{}, invalid("name is required (at most 200 characters)")
	}
	if in.OnPending == "" {
		in.OnPending = "revoke"
	}
	if in.OnPending != "revoke" && in.OnPending != "keep" {
		return AccessReview{}, invalid("on_pending must be revoke or keep")
	}
	if !in.DueAt.After(time.Now().Add(time.Hour)) {
		return AccessReview{}, invalid("due_at must be at least an hour from now")
	}
	var out AccessReview
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO access_review (id, tenant_id, name, status, on_pending, due_at, created_by, version)
			VALUES ($1, $2, $3, 'open', $4, $5, $6, $7)`, id, tenantID, in.Name, in.OnPending, in.DueAt,
			nilIfZero(ActorFrom(ctx).ID), v); err != nil {
			return mapErr(err)
		}
		var apps any
		if len(in.Apps) > 0 {
			apps = in.Apps
		}
		if _, err := tx.Exec(ctx, `INSERT INTO access_review_item (id, review_id, tenant_id, kind, grant_id, user_id, app, role, workspace_id)
			SELECT gen_random_uuid(), $1, g.tenant_id, 'grant', g.id, g.subject_id, a.slug, g.role, g.workspace_id
			FROM role_grant g JOIN app a ON a.id = g.app_id JOIN membership m ON m.tenant_id = g.tenant_id AND m.user_id = g.subject_id
			WHERE g.tenant_id = $2 AND g.status = 'active' AND g.subject_type = 'user' AND m.status <> 'removed'
			AND ($3::text[] IS NULL OR a.slug = ANY($3))`, id, tenantID, apps); err != nil {
			return err
		}
		if !in.NoRoles {
			if _, err := tx.Exec(ctx, `INSERT INTO access_review_item (id, review_id, tenant_id, kind, user_id, role)
				SELECT gen_random_uuid(), $1, m.tenant_id, 'tenant_role', m.user_id, m.tenant_role FROM membership m
				WHERE m.tenant_id = $2 AND m.status = 'active' AND m.tenant_role IN ('owner','admin','billing')`, id, tenantID); err != nil {
				return err
			}
		}
		if out, err = scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_review r WHERE r.id = $1`, id)); err != nil {
			return err
		}
		if out.Items, err = reviewItems(ctx, tx, id); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "access_review.started", reviewSubject(out),
			map[string]any{"name": out.Name, "due_at": out.DueAt, "items": len(out.Items), "on_pending": out.OnPending})
	})
	return out, err
}

// ListAccessReviews lists the tenant's reviews, newest first (without items).
func (s *Store) ListAccessReviews(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]AccessReview, error) {
	out := []AccessReview{}
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+reviewCols+` FROM access_review r WHERE r.tenant_id = $1 ORDER BY r.created_at DESC`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AccessReview, error) { return scanReview(r) })
		return err
	})
	return out, err
}

// GetAccessReview returns a review with its items.
func (s *Store) GetAccessReview(ctx context.Context, sc Scope, tenantID, id uuid.UUID) (AccessReview, error) {
	var out AccessReview
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		if out, err = scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_review r WHERE r.id = $1 AND r.tenant_id = $2`,
			id, tenantID)); err != nil {
			return mapErr(err)
		}
		out.Items, err = reviewItems(ctx, tx, id)
		return err
	})
	return out, err
}

// DecideAccessReviewItem records keep or revoke for an item of an open review. Nobody decides on their own access.
func (s *Store) DecideAccessReviewItem(ctx context.Context, sc Scope, tenantID, reviewID, itemID, by uuid.UUID, decision, note string) (AccessReviewItem, error) {
	if decision != "keep" && decision != "revoke" && decision != "pending" {
		return AccessReviewItem{}, invalid("decision must be keep, revoke or pending")
	}
	var out AccessReviewItem
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM access_review WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, reviewID, tenantID).
			Scan(&status); err != nil {
			return mapErr(err)
		}
		if status != "open" {
			return invalid("the review is %s", status)
		}
		var owner uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM access_review_item WHERE id = $1 AND review_id = $2`, itemID, reviewID).
			Scan(&owner); err != nil {
			return mapErr(err)
		}
		if owner == by {
			return invalid("someone else must review your own access")
		}
		var decidedBy, decidedAt any
		if decision != "pending" {
			decidedBy, decidedAt = by, time.Now()
		}
		if _, err := tx.Exec(ctx, `UPDATE access_review_item SET decision = $2, decided_by = $3, decided_at = $4, note = nullif($5, '')
			WHERE id = $1`, itemID, decision, decidedBy, decidedAt, note); err != nil {
			return err
		}
		items, err := reviewItems(ctx, tx, reviewID)
		if err != nil {
			return err
		}
		for _, it := range items {
			if it.ID == itemID {
				out = it
			}
		}
		return nil
	})
	return out, err
}

// CompleteAccessReview applies a review: items marked revoke, and undecided items when on_pending is revoke, lose
// their app role grant (grant.revoked) or have their tenant role lowered to member (membership.updated). The last
// owner is never lowered. by is nil when the deadline completes it.
func (s *Store) CompleteAccessReview(ctx context.Context, sc Scope, tenantID, reviewID uuid.UUID, by *uuid.UUID) (AccessReview, error) {
	var out AccessReview
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		r, err := scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_review r WHERE r.id = $1 AND r.tenant_id = $2 FOR UPDATE`,
			reviewID, tenantID))
		if err != nil {
			return mapErr(err)
		}
		if r.Status != "open" {
			return invalid("the review is %s", r.Status)
		}
		items, err := reviewItems(ctx, tx, reviewID)
		if err != nil {
			return err
		}
		kept, revoked := 0, 0
		for _, it := range items {
			revoke := it.Decision == "revoke" || (it.Decision == "pending" && r.OnPending == "revoke")
			outcome := "kept"
			if revoke {
				if outcome, err = applyRevoke(ctx, tx, tenantID, it); err != nil {
					return err
				}
			}
			if outcome == "revoked" {
				revoked++
			} else {
				kept++
			}
			if _, err := tx.Exec(ctx, `UPDATE access_review_item SET outcome = $2 WHERE id = $1`, it.ID, outcome); err != nil {
				return err
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		var byID any
		if by != nil {
			byID = *by
		}
		if _, err := tx.Exec(ctx, `UPDATE access_review SET status = 'completed', completed_at = now(), completed_by = $2,
			kept = $3, revoked = $4, version = $5 WHERE id = $1`, reviewID, byID, kept, revoked, v); err != nil {
			return err
		}
		if out, err = scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_review r WHERE r.id = $1`, reviewID)); err != nil {
			return err
		}
		if out.Items, err = reviewItems(ctx, tx, reviewID); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "access_review.completed", reviewSubject(out),
			map[string]any{"name": out.Name, "kept": kept, "revoked": revoked, "by_deadline": by == nil})
	})
	return out, err
}

func applyRevoke(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, it AccessReviewItem) (string, error) {
	switch it.Kind {
	case "grant":
		g, err := getGrant(ctx, tx, tenantID, *it.GrantID)
		if err == ErrNotFound || (err == nil && g.Status != "active") {
			return "already_gone", nil
		}
		if err != nil {
			return "", err
		}
		return "revoked", revokeGrant(ctx, tx, g)
	default: // tenant_role
		m, err := getMember(ctx, tx, tenantID, it.UserID, true)
		if err == ErrNotFound || (err == nil && (m.Status == "removed" || m.TenantRole != it.Role)) {
			return "already_gone", nil
		}
		if err != nil {
			return "", err
		}
		if err := checkNotLastOwner(ctx, tx, tenantID, m); err != nil {
			return "last_owner_kept", nil
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `UPDATE membership SET tenant_role = 'member', version = $3, updated_at = now()
			WHERE tenant_id = $1 AND user_id = $2`, tenantID, it.UserID, v); err != nil {
			return "", err
		}
		m, err = getMember(ctx, tx, tenantID, it.UserID, false)
		if err != nil {
			return "", err
		}
		return "revoked", emit(ctx, tx, v, tenantID, "membership.updated", memberSubject(tenantID, it.UserID), m)
	}
}

// CancelAccessReview closes an open review without changing anything.
func (s *Store) CancelAccessReview(ctx context.Context, sc Scope, tenantID, reviewID uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE access_review SET status = 'cancelled', completed_at = now(), completed_by = $3
			WHERE id = $1 AND tenant_id = $2 AND status = 'open'`, reviewID, tenantID, nilIfZero(ActorFrom(ctx).ID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(ctx, tx, tenantID, "access_review.cancelled", "tenants/"+tenantID.String()+"/access-reviews/"+reviewID.String(), nil)
	})
}

// CompleteDueAccessReviews completes open reviews past their deadline (the lifecycle worker).
func (s *Store) CompleteDueAccessReviews(ctx context.Context) (int, error) {
	type due struct{ id, tenant uuid.UUID }
	var list []due
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id FROM access_review WHERE status = 'open' AND due_at <= now() LIMIT 100`)
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
			var d due
			return d, r.Scan(&d.id, &d.tenant)
		})
		return err
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range list {
		ctx := WithActor(ctx, Actor{Kind: "system", Email: "access-review-deadline"})
		if _, err := s.CompleteAccessReview(ctx, Scope{Operator: true}, d.tenant, d.id, nil); err != nil {
			if _, ok := err.(*InvalidError); ok { // completed meanwhile
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}
