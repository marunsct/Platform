package matura_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	matura "github.com/marunsct/Platform/sdk/go"
)

func TestEntitlementsAndQuota(t *testing.T) {
	var gets atomic.Int32
	down := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/v1/apps/notes/tenants/t1/entitlements":
			gets.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "t1", "features": map[string]bool{"sso": true},
				"meters": []any{map[string]any{"meter": "notes.exports", "used": 3, "limit": 10}}, "version": 4})
		case "/v1/apps/notes/tenants/t1/quota:consume":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			_ = json.NewEncoder(w).Encode(map[string]any{"allowed": in["quantity"].(float64) <= 7, "meter": "notes.exports", "used": 3})
		case "/v1/apps/notes/tenants/t1/usage":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{map[string]any{"id": "u1", "status": "recorded"}}})
		}
	}))
	defer srv.Close()
	c := matura.NewClient(srv.URL, "notes", "s")
	ctx := context.Background()
	cache := &matura.EntitlementCache{Client: c, App: "notes"}
	if !cache.Has(ctx, "t1", "sso") || cache.Has(ctx, "t1", "scim") || gets.Load() != 1 {
		t.Fatalf("cache: %d fetches", gets.Load())
	}
	down.Store(true)
	cache.Forget("t1")
	if cache.Has(ctx, "t1", "sso") {
		t.Fatal("a forgotten tenant with maturad down has features")
	}
	down.Store(false)
	if q, err := c.ConsumeQuota(ctx, "notes", "t1", matura.Usage{ID: "e1", Meter: "exports", Quantity: 8}); err != nil || q.Allowed {
		t.Fatalf("quota: %+v %v", q, err)
	}
	if res, err := c.RecordUsage(ctx, "notes", "t1", []matura.Usage{{ID: "u1", Meter: "calls", Quantity: 1}}); err != nil || res["u1"] != "recorded" {
		t.Fatalf("usage: %v %v", res, err)
	}
}
