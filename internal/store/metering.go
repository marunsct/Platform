package store

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Metering and quotas (TS18, technical specification §22). Plans limit meters per period:
//
//	"meters": {"devflow.runs": {"limit": 1000, "period": "month", "hard": true}}
//
// Apps report usage (idempotent by event id) and, for hard limits, consume quota atomically before doing the work.

// MeterLimit is a plan's limit on one meter. Limit nil (or negative) means unlimited; the period is month (calendar
// month, UTC; the default), day or total; hard limits refuse a quota consume that would pass them, soft ones only
// announce the 80% and 100% thresholds.
type MeterLimit struct {
	Limit  *int64 `json:"limit,omitempty"`
	Period string `json:"period,omitempty"`
	Hard   bool   `json:"hard,omitempty"`
}

func (m MeterLimit) period() string {
	if m.Period == "" {
		return "month"
	}
	return m.Period
}

func (m MeterLimit) limited() bool { return m.Limit != nil && *m.Limit >= 0 }

var (
	meterName   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// validMeters checks a plan's or override's meters.
func validMeters(ms map[string]MeterLimit) error {
	for name, m := range ms {
		app, short, ok := strings.Cut(name, ".")
		if !ok || !slugPattern.MatchString(app) || !meterName.MatchString(short) {
			return invalid("meter %q must be <app slug>.<name>, e.g. devflow.runs", name)
		}
		switch m.Period {
		case "", "month", "day", "total":
		default:
			return invalid("meter %q: period must be month, day or total", name)
		}
	}
	return nil
}

// periodStart is the start of the period t falls in.
func periodStart(period string, t time.Time) time.Time {
	t = t.UTC()
	switch period {
	case "day":
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	case "total":
		return time.Unix(0, 0).UTC()
	}
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// UsageEvent is usage an app reports.
type UsageEvent struct {
	ID       string    `json:"id"`
	Meter    string    `json:"meter"` // the app's own name (runs); stored as <app>.<meter>
	Quantity int64     `json:"quantity"`
	Time     time.Time `json:"time"`
}

// UsageResult says what became of one reported event.
type UsageResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // recorded or duplicate
}

const usageWindow = 35 * 24 * time.Hour // how late usage may arrive (it counts in the period it occurred in)

func (e *UsageEvent) check(now time.Time) error {
	switch {
	case e.ID == "" || len(e.ID) > 200:
		return invalid("each usage event needs an id (at most 200 characters) so a retry is not counted twice")
	case !meterName.MatchString(e.Meter):
		return invalid("meter %q must be lowercase letters, digits and _", e.Meter)
	case e.Quantity < 0:
		return invalid("quantity must not be negative")
	}
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.Time.After(now.Add(5*time.Minute)) || e.Time.Before(now.Add(-usageWindow)) {
		return invalid("usage time must be within the last 35 days")
	}
	return nil
}

// counterAdd adds quantity to the meter's counter for the period of t, announcing the 80% and 100% thresholds of a
// limit once per period (matura.usage.threshold to the app, and the audit log). It returns the new total.
func counterAdd(ctx context.Context, tx pgx.Tx, tenantID, appID uuid.UUID, meter string, lim MeterLimit, quantity int64, t time.Time) (int64, error) {
	start := periodStart(lim.period(), t)
	var total int64
	var notified int
	if err := tx.QueryRow(ctx, `INSERT INTO usage_counter (tenant_id, meter, period, period_start, quantity)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, meter, period, period_start)
		DO UPDATE SET quantity = usage_counter.quantity + EXCLUDED.quantity
		RETURNING quantity, notified_pct`, tenantID, meter, lim.period(), start, quantity).Scan(&total, &notified); err != nil {
		return 0, err
	}
	if !lim.limited() || *lim.Limit == 0 && total == 0 {
		return total, nil
	}
	pct := 0
	switch {
	case total >= *lim.Limit:
		pct = 100
	case total*100 >= *lim.Limit*80:
		pct = 80
	}
	if pct <= notified {
		return total, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE usage_counter SET notified_pct = $5 WHERE tenant_id = $1 AND meter = $2
		AND period = $3 AND period_start = $4`, tenantID, meter, lim.period(), start, pct); err != nil {
		return 0, err
	}
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return 0, err
	}
	return total, emit(ctx, tx, v, tenantID, "usage.threshold", "tenants/"+tenantID.String()+"/usage/"+meter,
		map[string]any{"tenant_id": tenantID, "app_id": appID, "meter": meter, "period": lim.period(),
			"period_start": start, "used": total, "limit": *lim.Limit, "percent": pct, "hard": lim.Hard})
}

func meterLimit(l Limits, meter string) MeterLimit {
	if m, ok := l.Meters[meter]; ok {
		return m
	}
	return MeterLimit{}
}

// RecordUsage stores usage an app reports for a tenant that enabled it. Usage is never refused for being over a
// limit (it already happened); use ConsumeQuota before the work for hard limits.
func (s *Store) RecordUsage(ctx context.Context, app App, tenantID uuid.UUID, events []UsageEvent) ([]UsageResult, error) {
	if len(events) == 0 || len(events) > 1000 {
		return nil, invalid("send 1 to 1000 usage events")
	}
	now := time.Now()
	for i := range events {
		if err := events[i].check(now); err != nil {
			return nil, err
		}
	}
	out := make([]UsageResult, 0, len(events))
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tenantUsesApp(ctx, tx, tenantID, app.ID); err != nil {
			return err
		}
		lim, err := effectiveLimits(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		for _, e := range events {
			full := app.Slug + "." + e.Meter
			tag, err := tx.Exec(ctx, `INSERT INTO usage_event (tenant_id, app_id, meter, quantity, event_id, occurred_at)
				VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`, tenantID, app.ID, full, e.Quantity, e.ID, e.Time)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				out = append(out, UsageResult{ID: e.ID, Status: "duplicate"})
				continue
			}
			if _, err := counterAdd(ctx, tx, tenantID, app.ID, full, meterLimit(lim, full), e.Quantity, e.Time); err != nil {
				return err
			}
			out = append(out, UsageResult{ID: e.ID, Status: "recorded"})
		}
		return nil
	})
	return out, err
}

func tenantUsesApp(ctx context.Context, tx pgx.Tx, tenantID, appID uuid.UUID) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_app WHERE tenant_id = $1 AND app_id = $2
		AND status = 'enabled')`, tenantID, appID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

// QuotaResult answers a quota consume.
type QuotaResult struct {
	Allowed   bool   `json:"allowed"`
	Meter     string `json:"meter"`
	Used      int64  `json:"used"`
	Limit     *int64 `json:"limit"`
	Remaining *int64 `json:"remaining"`
	Period    string `json:"period"`
	Duplicate bool   `json:"duplicate,omitempty"` // this event id was consumed before
}

// ConsumeQuota records quantity of a meter only if the tenant's limit allows it, atomically: concurrent consumers
// never take a hard limit past its value. The event id makes a retry return the first answer without consuming
// again. A soft or missing limit always allows.
func (s *Store) ConsumeQuota(ctx context.Context, app App, tenantID uuid.UUID, e UsageEvent) (QuotaResult, error) {
	if err := e.check(time.Now()); err != nil {
		return QuotaResult{}, err
	}
	full := app.Slug + "." + e.Meter
	out := QuotaResult{Meter: full}
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tenantUsesApp(ctx, tx, tenantID, app.ID); err != nil {
			return err
		}
		lim, err := effectiveLimits(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		ml := meterLimit(lim, full)
		out.Period, out.Limit = ml.period(), ml.Limit
		start := periodStart(ml.period(), e.Time)
		// lock the period's counter (creating it), so consumers queue here
		if _, err := tx.Exec(ctx, `INSERT INTO usage_counter (tenant_id, meter, period, period_start) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, tenantID, full, ml.period(), start); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT quantity FROM usage_counter WHERE tenant_id = $1 AND meter = $2 AND period = $3
			AND period_start = $4 FOR UPDATE`, tenantID, full, ml.period(), start).Scan(&out.Used); err != nil {
			return err
		}
		var seen bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM usage_event WHERE tenant_id = $1 AND app_id = $2
			AND event_id = $3)`, tenantID, app.ID, e.ID).Scan(&seen); err != nil {
			return err
		}
		if seen {
			out.Allowed, out.Duplicate = true, true
		} else if ml.Hard && ml.limited() && out.Used+e.Quantity > *ml.Limit {
			out.Allowed = false
		} else {
			if _, err := tx.Exec(ctx, `INSERT INTO usage_event (tenant_id, app_id, meter, quantity, event_id, occurred_at)
				VALUES ($1, $2, $3, $4, $5, $6)`, tenantID, app.ID, full, e.Quantity, e.ID, e.Time); err != nil {
				return mapErr(err)
			}
			if out.Used, err = counterAdd(ctx, tx, tenantID, app.ID, full, ml, e.Quantity, e.Time); err != nil {
				return err
			}
			out.Allowed = true
		}
		if ml.limited() {
			r := max(*ml.Limit-out.Used, 0)
			out.Remaining = &r
		}
		return nil
	})
	return out, err
}

// MeterUsage is one meter's use in its current period.
type MeterUsage struct {
	Meter       string    `json:"meter"`
	Period      string    `json:"period"`
	PeriodStart time.Time `json:"period_start"`
	Used        int64     `json:"used"`
	Limit       *int64    `json:"limit"`
	Hard        bool      `json:"hard"`
}

// meterUsage lists the current period of every meter the tenant has a limit on or has used.
func meterUsage(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, lim Limits, now time.Time) ([]MeterUsage, error) {
	byMeter := map[string]MeterUsage{}
	for name, m := range lim.Meters {
		byMeter[name] = MeterUsage{Meter: name, Period: m.period(), PeriodStart: periodStart(m.period(), now), Limit: m.Limit, Hard: m.Hard}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT meter FROM usage_counter WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	used, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, name := range used {
		if _, ok := byMeter[name]; !ok {
			byMeter[name] = MeterUsage{Meter: name, Period: "month", PeriodStart: periodStart("month", now)}
		}
	}
	out := make([]MeterUsage, 0, len(byMeter))
	for _, m := range byMeter {
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT quantity FROM usage_counter WHERE tenant_id = $1 AND meter = $2
			AND period = $3 AND period_start = $4), 0)`, tenantID, m.Meter, m.Period, m.PeriodStart).Scan(&m.Used); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meter < out[j].Meter })
	return out, nil
}

// AppEntitlements is what an app's SDK caches for a tenant: features, limits and meters (its own only).
type AppEntitlements struct {
	TenantID uuid.UUID       `json:"tenant_id"`
	Plan     *PlanRef        `json:"plan"`
	Features map[string]bool `json:"features"`
	Meters   []MeterUsage    `json:"meters"`
	Version  int64           `json:"version"` // the tenant's version: it changes when the plan or overrides do
}

// AppEntitlementsFor returns the tenant's entitlements as one app sees them.
func (s *Store) AppEntitlementsFor(ctx context.Context, app App, tenantID uuid.UUID) (AppEntitlements, error) {
	out := AppEntitlements{TenantID: tenantID, Features: map[string]bool{}, Meters: []MeterUsage{}}
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tenantUsesApp(ctx, tx, tenantID, app.ID); err != nil {
			return err
		}
		plan, over, ref, _, err := tenantLimits(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		lim := plan.merge(over)
		out.Plan = ref
		for k, v := range lim.Features {
			out.Features[k] = v
		}
		ms, err := meterUsage(ctx, tx, tenantID, lim, time.Now())
		if err != nil {
			return err
		}
		for _, m := range ms {
			if strings.HasPrefix(m.Meter, app.Slug+".") {
				out.Meters = append(out.Meters, m)
			}
		}
		return tx.QueryRow(ctx, `SELECT version FROM tenant WHERE id = $1`, tenantID).Scan(&out.Version)
	})
	return out, err
}

// --- billing ---------------------------------------------------------------------------------------------------------

// BillingCustomer links a tenant to its customer in the billing system.
type BillingCustomer struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	Provider       string    `json:"provider"`
	CustomerID     string    `json:"customer_id"`
	SubscriptionID *string   `json:"subscription_id"`
	Version        int64     `json:"version"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SetBillingCustomer links (or relinks) a tenant to a billing customer (operators).
func (s *Store) SetBillingCustomer(ctx context.Context, sc Scope, tenantID uuid.UUID, provider, customerID, subscriptionID string) (BillingCustomer, error) {
	switch provider {
	case "stripe", "lago", "openmeter":
	default:
		return BillingCustomer{}, invalid("provider must be stripe, lago or openmeter")
	}
	if customerID = strings.TrimSpace(customerID); customerID == "" || len(customerID) > 255 {
		return BillingCustomer{}, invalid("customer_id is required")
	}
	var out BillingCustomer
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO billing_customer (tenant_id, provider, customer_id, subscription_id, version)
			VALUES ($1, $2, $3, nullif($4, ''), $5) ON CONFLICT (tenant_id) DO UPDATE SET provider = EXCLUDED.provider,
			customer_id = EXCLUDED.customer_id, subscription_id = EXCLUDED.subscription_id, version = EXCLUDED.version,
			updated_at = now() RETURNING tenant_id, provider, customer_id, subscription_id, version, updated_at`,
			tenantID, provider, customerID, subscriptionID, v).Scan(&out.TenantID, &out.Provider, &out.CustomerID,
			&out.SubscriptionID, &out.Version, &out.UpdatedAt)
		if err != nil {
			return mapErr(err)
		}
		return audit(ctx, tx, tenantID, "billing.customer_linked", "tenants/"+tenantID.String()+"/billing", out)
	})
	return out, err
}

// GetBillingCustomer returns the tenant's billing link (ErrNotFound when none).
func (s *Store) GetBillingCustomer(ctx context.Context, sc Scope, tenantID uuid.UUID) (BillingCustomer, error) {
	var out BillingCustomer
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT tenant_id, provider, customer_id, subscription_id, version, updated_at
			FROM billing_customer WHERE tenant_id = $1`, tenantID).Scan(&out.TenantID, &out.Provider, &out.CustomerID,
			&out.SubscriptionID, &out.Version, &out.UpdatedAt))
	})
	return out, err
}

// BillableUsage is one usage event ready for a billing provider.
type BillableUsage struct {
	Seq            int64
	EventID        string // unique per installation: <tenant>:<app>:<event id>
	TenantID       uuid.UUID
	CustomerID     string
	SubscriptionID string
	Meter          string
	Quantity       int64
	Time           time.Time
}

// PendingUsage returns usage after the provider's export cursor (at most limit events), with the billing customer
// of each tenant linked to that provider; events of tenants not linked are counted as skipped.
func (s *Store) PendingUsage(ctx context.Context, provider string, limit int) (items []BillableUsage, cursor int64, err error) {
	err = s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO billing_export (provider) VALUES ($1) ON CONFLICT DO NOTHING`, provider); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT cursor FROM billing_export WHERE provider = $1`, provider).Scan(&cursor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT u.seq, u.tenant_id::text || ':' || u.app_id::text || ':' || u.event_id, u.tenant_id,
			coalesce(b.customer_id, ''), coalesce(b.subscription_id, ''), u.meter, u.quantity, u.occurred_at
			FROM usage_event u LEFT JOIN billing_customer b ON b.tenant_id = u.tenant_id AND b.provider = $1
			WHERE u.seq > $2 ORDER BY u.seq LIMIT $3`, provider, cursor, limit)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (BillableUsage, error) {
			var b BillableUsage
			return b, r.Scan(&b.Seq, &b.EventID, &b.TenantID, &b.CustomerID, &b.SubscriptionID, &b.Meter, &b.Quantity, &b.Time)
		})
		return err
	})
	return items, cursor, err
}

// UsageExported moves the provider's cursor past what was sent (exported) and skipped (no customer).
func (s *Store) UsageExported(ctx context.Context, provider string, cursor int64, exported, skipped int, sendErr error) error {
	return s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var msg *string
		if sendErr != nil {
			m := sendErr.Error()
			msg = &m
		}
		_, err := tx.Exec(ctx, `UPDATE billing_export SET cursor = greatest(cursor, $2), exported = exported + $3,
			skipped = skipped + $4, last_error = $5, last_run_at = now(), updated_at = now() WHERE provider = $1`,
			provider, cursor, exported, skipped, msg)
		return err
	})
}

// BillingExportStatus is the export state of one provider.
type BillingExportStatus struct {
	Provider  string     `json:"provider"`
	Cursor    int64      `json:"cursor"`
	Exported  int64      `json:"exported"`
	Skipped   int64      `json:"skipped"`
	Pending   int64      `json:"pending"`
	LastError *string    `json:"last_error"`
	LastRunAt *time.Time `json:"last_run_at"`
}

// BillingExports lists the export state per provider (operators).
func (s *Store) BillingExports(ctx context.Context) ([]BillingExportStatus, error) {
	var out []BillingExportStatus
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, cursor, exported, skipped,
			(SELECT count(*) FROM usage_event WHERE seq > b.cursor), last_error, last_run_at FROM billing_export b ORDER BY provider`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (BillingExportStatus, error) {
			var b BillingExportStatus
			return b, r.Scan(&b.Provider, &b.Cursor, &b.Exported, &b.Skipped, &b.Pending, &b.LastError, &b.LastRunAt)
		})
		return err
	})
	if out == nil {
		out = []BillingExportStatus{}
	}
	return out, err
}

// ErrQuotaExceeded is a refused quota consume (the API answers 200 with allowed false; this is for SDK helpers).
var ErrQuotaExceeded = errors.New("quota exceeded")
