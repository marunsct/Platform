package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Entitlements (doc 10 §1, TS18): a plan's limits, overridden per tenant by operators. Limits are JSON:
//
//	{"max_members": 10, "max_workspaces": 3, "apps": ["devflow"], "features": {"sso": true}}
//
// A missing limit, or a negative number, means no limit; a missing apps list allows every app ("*" in it does too).
// Other keys are kept for apps and later meters. Overrides have the same shape and replace the plan's value key by
// key (features flag by flag).

type Limits struct {
	MaxMembers    *int            `json:"max_members,omitempty"`
	MaxWorkspaces *int            `json:"max_workspaces,omitempty"`
	Apps          *[]string       `json:"apps,omitempty"`
	Features      map[string]bool `json:"features,omitempty"`
}

// ParseLimits checks the keys Matura enforces; it is used for plans and overrides.
func ParseLimits(raw json.RawMessage) (Limits, error) {
	var l Limits
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return l, nil
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			return l, invalid("limits must be a JSON object")
		}
		return l, invalid("limits: max_members and max_workspaces are whole numbers, apps a list of app slugs, " +
			"features an object of true or false")
	}
	return l, nil
}

// merge returns the plan's limits with the overrides applied.
func (l Limits) merge(o Limits) Limits {
	out := l
	if o.MaxMembers != nil {
		out.MaxMembers = o.MaxMembers
	}
	if o.MaxWorkspaces != nil {
		out.MaxWorkspaces = o.MaxWorkspaces
	}
	if o.Apps != nil {
		out.Apps = o.Apps
	}
	if len(l.Features)+len(o.Features) > 0 {
		out.Features = map[string]bool{}
		for k, v := range l.Features {
			out.Features[k] = v
		}
		for k, v := range o.Features {
			out.Features[k] = v
		}
	}
	return out
}

func (l Limits) allowsApp(slug string) bool {
	return l.Apps == nil || slices.Contains(*l.Apps, "*") || slices.Contains(*l.Apps, slug)
}

// LimitError is a change the tenant's plan does not allow (402 plan-limit). Max is nil for the apps list.
type LimitError struct {
	Limit string
	Max   *int
	Used  int
	Msg   string
}

func (e *LimitError) Error() string { return e.Msg }

func planExists(ctx context.Context, tx pgx.Tx, id string) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM plan WHERE id = $1)`, id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return invalid("plan %q does not exist", id)
	}
	return nil
}

// tenantLimits reads the plan's limits and the tenant's overrides.
func tenantLimits(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (plan, overrides Limits, planRef *PlanRef, rawOverrides json.RawMessage, err error) {
	var planID, planName *string
	var planRaw []byte
	err = tx.QueryRow(ctx, `SELECT t.plan, p.name, p.limits, t.entitlement_overrides FROM tenant t
		LEFT JOIN plan p ON p.id = t.plan WHERE t.id = $1`, tenantID).Scan(&planID, &planName, &planRaw, &rawOverrides)
	if err != nil {
		err = mapErr(err)
		return
	}
	if planID != nil {
		planRef = &PlanRef{ID: *planID}
		if planName != nil {
			planRef.Name = *planName
		}
	}
	// stored values were checked when written; a plan edited by hand into a bad shape counts as no limits
	plan, _ = ParseLimits(planRaw)
	overrides, _ = ParseLimits(rawOverrides)
	return
}

func effectiveLimits(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (Limits, error) {
	plan, over, _, _, err := tenantLimits(ctx, tx, tenantID)
	return plan.merge(over), err
}

func atLimit(max *int, used int) bool { return max != nil && *max >= 0 && used >= *max }

// checkMemberLimit refuses a new member when the tenant has max_members members (deactivated ones hold a seat).
// It locks the tenant row so concurrent additions are counted one after another.
func checkMemberLimit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if err := lockTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	l, err := effectiveLimits(ctx, tx, tenantID)
	if err != nil || l.MaxMembers == nil {
		return err
	}
	var used int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM membership WHERE tenant_id = $1 AND status <> 'removed'`,
		tenantID).Scan(&used); err != nil {
		return err
	}
	if atLimit(l.MaxMembers, used) {
		return &LimitError{Limit: "max_members", Max: l.MaxMembers, Used: used,
			Msg: fmt.Sprintf("the plan allows %d members and the organisation has %d; remove someone or upgrade", *l.MaxMembers, used)}
	}
	return nil
}

func checkWorkspaceLimit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if err := lockTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	l, err := effectiveLimits(ctx, tx, tenantID)
	if err != nil || l.MaxWorkspaces == nil {
		return err
	}
	var used int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace WHERE tenant_id = $1 AND status <> 'deleted'`,
		tenantID).Scan(&used); err != nil {
		return err
	}
	if atLimit(l.MaxWorkspaces, used) {
		return &LimitError{Limit: "max_workspaces", Max: l.MaxWorkspaces, Used: used,
			Msg: fmt.Sprintf("the plan allows %d workspaces and the organisation has %d", *l.MaxWorkspaces, used)}
	}
	return nil
}

func checkAppAllowed(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, slug string) error {
	l, err := effectiveLimits(ctx, tx, tenantID)
	if err != nil || l.allowsApp(slug) {
		return err
	}
	return &LimitError{Limit: "apps", Msg: fmt.Sprintf("the plan does not include %s", slug)}
}

type PlanRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Usage struct {
	Members    int      `json:"members"`
	Workspaces int      `json:"workspaces"`
	Apps       []string `json:"apps"` // enabled
}

// Entitlements is what a tenant may use and what it uses (GET /v1/tenants/{tid}/entitlements).
type Entitlements struct {
	TenantID   uuid.UUID       `json:"tenant_id"`
	Plan       *PlanRef        `json:"plan"`
	Limits     Limits          `json:"limits"`      // effective: the plan with the overrides applied
	PlanLimits Limits          `json:"plan_limits"` // the plan's own
	Overrides  json.RawMessage `json:"overrides"`
	Usage      Usage           `json:"usage"`
}

func entitlementsOf(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (Entitlements, error) {
	plan, over, ref, raw, err := tenantLimits(ctx, tx, tenantID)
	if err != nil {
		return Entitlements{}, err
	}
	out := Entitlements{TenantID: tenantID, Plan: ref, Limits: plan.merge(over), PlanLimits: plan, Overrides: raw,
		Usage: Usage{Apps: []string{}}}
	if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM membership WHERE tenant_id = $1 AND status <> 'removed'),
			(SELECT count(*) FROM workspace WHERE tenant_id = $1 AND status <> 'deleted')`, tenantID).
		Scan(&out.Usage.Members, &out.Usage.Workspaces); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT a.slug FROM tenant_app ta JOIN app a ON a.id = ta.app_id
		WHERE ta.tenant_id = $1 AND ta.status = 'enabled' ORDER BY a.slug`, tenantID)
	if err != nil {
		return out, err
	}
	apps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return out, err
	}
	out.Usage.Apps = append(out.Usage.Apps, apps...)
	return out, nil
}

func (s *Store) TenantEntitlements(ctx context.Context, sc Scope, tenantID uuid.UUID) (Entitlements, error) {
	var out Entitlements
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		out, err = entitlementsOf(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// SetTenantPlan moves a tenant to a plan (empty: none) and, when overrides is not nil, replaces its overrides
// (operators). Usage above a new limit is kept; only new additions are refused. Existing placements keep their mode.
func (s *Store) SetTenantPlan(ctx context.Context, sc Scope, tenantID uuid.UUID, plan string, overrides json.RawMessage) (Entitlements, error) {
	if overrides != nil {
		if _, err := ParseLimits(overrides); err != nil {
			return Entitlements{}, err
		}
		if string(bytes.TrimSpace(overrides)) == "null" {
			overrides = json.RawMessage(`{}`)
		}
	}
	var out Entitlements
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if plan != "" {
			if err := planExists(ctx, tx, plan); err != nil {
				return err
			}
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		var ov any
		if overrides != nil {
			ov = []byte(overrides)
		}
		t, err := scanTenant(tx.QueryRow(ctx, `UPDATE tenant SET plan = nullif($2, ''),
			entitlement_overrides = coalesce($3::jsonb, entitlement_overrides), version = $4, updated_at = now()
			WHERE id = $1 AND status <> 'deleted' RETURNING `+tenantCols, tenantID, plan, ov, v))
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, v, tenantID, "tenant.updated", "tenants/"+tenantID.String(), t.Contract()); err != nil {
			return err
		}
		if out, err = entitlementsOf(ctx, tx, tenantID); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "tenant.plan.changed", "tenants/"+tenantID.String()+"/entitlements",
			map[string]any{"plan": t.Plan, "overrides": out.Overrides})
	})
	return out, err
}
