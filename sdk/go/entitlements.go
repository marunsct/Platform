package matura

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Entitlements, usage and quotas (technical specification §22).

// MeterUsage is one meter's use in its current period.
type MeterUsage struct {
	Meter       string    `json:"meter"` // <app>.<name>
	Period      string    `json:"period"`
	PeriodStart time.Time `json:"period_start"`
	Used        int64     `json:"used"`
	Limit       *int64    `json:"limit"`
	Hard        bool      `json:"hard"`
}

// TenantEntitlements are a tenant's features and this app's meters.
type TenantEntitlements struct {
	TenantID string          `json:"tenant_id"`
	Features map[string]bool `json:"features"`
	Meters   []MeterUsage    `json:"meters"`
	Version  int64           `json:"version"`
}

// Has says whether the tenant's plan turns a feature on.
func (e *TenantEntitlements) Has(feature string) bool { return e != nil && e.Features[feature] }

// Entitlements fetches a tenant's entitlements for the app.
func (c *Client) Entitlements(ctx context.Context, app, tenant string) (*TenantEntitlements, error) {
	var out TenantEntitlements
	if err := c.do(ctx, http.MethodGet, "/v1/apps/"+seg(app)+"/tenants/"+seg(tenant)+"/entitlements", nil, nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// Usage is usage to report: Meter is the app's own name (runs), ID makes a retry count once.
type Usage struct {
	ID       string    `json:"id"`
	Meter    string    `json:"meter"`
	Quantity int64     `json:"quantity"`
	Time     time.Time `json:"time,omitempty"`
}

// RecordUsage reports usage for a tenant (at most 1000 events); it returns "recorded" or "duplicate" per event.
func (c *Client) RecordUsage(ctx context.Context, app, tenant string, events []Usage) (map[string]string, error) {
	var out struct {
		Results []struct{ ID, Status string } `json:"results"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/apps/"+seg(app)+"/tenants/"+seg(tenant)+"/usage", nil,
		map[string]any{"events": events}, &out, false); err != nil {
		return nil, err
	}
	res := make(map[string]string, len(out.Results))
	for _, r := range out.Results {
		res[r.ID] = r.Status
	}
	return res, nil
}

// Quota is the answer to a quota consume.
type Quota struct {
	Allowed   bool   `json:"allowed"`
	Meter     string `json:"meter"`
	Used      int64  `json:"used"`
	Limit     *int64 `json:"limit"`
	Remaining *int64 `json:"remaining"`
	Period    string `json:"period"`
	Duplicate bool   `json:"duplicate"`
}

// ConsumeQuota takes u.Quantity of a meter if the tenant's plan allows it, atomically (call it before the work; a
// retry with the same ID gets the first answer and consumes nothing more).
func (c *Client) ConsumeQuota(ctx context.Context, app, tenant string, u Usage) (*Quota, error) {
	var out Quota
	if err := c.do(ctx, http.MethodPost, "/v1/apps/"+seg(app)+"/tenants/"+seg(tenant)+"/quota:consume", nil, u, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// EntitlementCache keeps each tenant's entitlements for TTL (default 30s), so feature checks cost nothing on most
// requests; call Forget on matura.tenant.updated (a plan change) to refresh at once.
type EntitlementCache struct {
	Client *Client
	App    string
	TTL    time.Duration

	mu    sync.Mutex
	items map[string]cachedEntitlements
}

type cachedEntitlements struct {
	e  *TenantEntitlements
	at time.Time
}

// Get returns the tenant's entitlements, from the cache when fresh. When maturad cannot be reached a stale entry is
// returned with the error, so the app can keep serving.
func (c *EntitlementCache) Get(ctx context.Context, tenant string) (*TenantEntitlements, error) {
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	c.mu.Lock()
	hit, ok := c.items[tenant]
	c.mu.Unlock()
	if ok && time.Since(hit.at) < ttl {
		return hit.e, nil
	}
	e, err := c.Client.Entitlements(ctx, c.App, tenant)
	if err != nil {
		if ok {
			return hit.e, err
		}
		return nil, err
	}
	c.mu.Lock()
	if c.items == nil {
		c.items = map[string]cachedEntitlements{}
	}
	c.items[tenant] = cachedEntitlements{e: e, at: time.Now()}
	c.mu.Unlock()
	return e, nil
}

// Has checks a feature through the cache (false when unknown).
func (c *EntitlementCache) Has(ctx context.Context, tenant, feature string) bool {
	e, _ := c.Get(ctx, tenant)
	return e.Has(feature)
}

// Forget drops a tenant's cached entitlements.
func (c *EntitlementCache) Forget(tenant string) {
	c.mu.Lock()
	delete(c.items, tenant)
	c.mu.Unlock()
}
