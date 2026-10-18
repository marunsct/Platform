package matura

import (
	"context"
	"net/http"
)

// Fine-grained permissions (TS11): resource-level checks on OpenFGA through maturad, in one tenant. Objects are
// "type:id" of a type in the app's authorization model; users are "user:<id>", "type:id#relation" (for example
// "role:editor#assignee") or "type:*". maturad answers 501 when the installation runs without OpenFGA.

// Tuple is one relationship: User has Relation on Object.
type Tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// CheckOptions apply to Check, BatchCheck and ListObjects.
type CheckOptions struct {
	Contextual []Tuple // count for this request only
	Fresh      bool    // skip OpenFGA's cache, to read a tuple written just before
}

func (o CheckOptions) body(b map[string]any) map[string]any {
	if len(o.Contextual) > 0 {
		b["contextual_tuples"] = o.Contextual
	}
	if o.Fresh {
		b["consistency"] = "higher"
	}
	return b
}

func tenantPath(app, tenant string) string { return "/v1/apps/" + seg(app) + "/tenants/" + seg(tenant) }

// WriteRelations adds and removes tuples in the tenant, all or nothing (at most 100 together). Repeating a write
// or a delete is not an error.
func (c *Client) WriteRelations(ctx context.Context, app, tenant string, writes, deletes []Tuple) error {
	body := map[string]any{"writes": nonNilTuples(writes), "deletes": nonNilTuples(deletes)}
	return c.do(ctx, http.MethodPost, tenantPath(app, tenant)+"/relations", nil, body, nil, false)
}

func nonNilTuples(t []Tuple) []Tuple {
	if t == nil {
		return []Tuple{}
	}
	return t
}

// Check reports whether user has relation on object in the tenant.
func (c *Client) Check(ctx context.Context, app, tenant, user, relation, object string, opts ...CheckOptions) (bool, error) {
	var o CheckOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	body := o.body(map[string]any{"user": user, "relation": relation, "object": object})
	err := c.do(ctx, http.MethodPost, tenantPath(app, tenant)+":check", nil, body, &out, false)
	return out.Allowed, err
}

// CheckResult answers one check of BatchCheck; Error is set when it could not be evaluated.
type CheckResult struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

// BatchCheck answers up to 50 checks, in the order given.
func (c *Client) BatchCheck(ctx context.Context, app, tenant string, checks []Tuple, opts ...CheckOptions) ([]CheckResult, error) {
	var o CheckOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	var out struct {
		Results []CheckResult `json:"results"`
	}
	err := c.do(ctx, http.MethodPost, tenantPath(app, tenant)+":batch-check", nil,
		o.body(map[string]any{"checks": checks}), &out, false)
	return out.Results, err
}

// ListObjects returns the objects ("type:id") of typ on which user has relation in the tenant.
func (c *Client) ListObjects(ctx context.Context, app, tenant, user, relation, typ string, opts ...CheckOptions) ([]string, error) {
	var o CheckOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	var out struct {
		Objects []string `json:"objects"`
	}
	err := c.do(ctx, http.MethodPost, tenantPath(app, tenant)+":list-objects", nil,
		o.body(map[string]any{"user": user, "relation": relation, "type": typ}), &out, false)
	return out.Objects, err
}
