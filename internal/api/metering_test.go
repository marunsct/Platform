package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marunsct/Platform/internal/billing"
	"github.com/marunsct/Platform/internal/ids"
)

// TestMeteringQuotasAndBilling (TS18, technical specification §22): plans limit meters; apps report usage
// idempotently and consume hard quotas atomically (the limit holds under concurrency); thresholds are announced;
// usage reaches the billing system through the adapter for tenants linked to a customer.
func TestMeteringQuotasAndBilling(t *testing.T) {
	srv, st, _ := setupFull(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "b"})
	notes := appClient{t: t, srv: srv, clientID: "notes", pass: sec["secret"].(string)}
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/plans/bad", map[string]any{"name": "Bad",
		"limits": map[string]any{"meters": map[string]any{"exports": map[string]any{"limit": 1}}}})
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/pro", map[string]any{"name": "Pro", "limits": map[string]any{
		"features": map[string]any{"pdf_export": true},
		"meters": map[string]any{
			"notes.exports":   map[string]any{"limit": 10, "period": "month", "hard": true},
			"notes.api_calls": map[string]any{"limit": 100, "period": "day"},
		}}})

	alice := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/notes", nil)
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "pro"})
	bob := client{t: t, srv: srv, user: ids.New()}
	bid := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})["id"].(string)
	base := "/v1/apps/notes/tenants/" + aid

	// the SDK snapshot: features and this app's meters
	_, ent := notes.get(base + "/entitlements")
	if f, _ := ent["features"].(map[string]any); f["pdf_export"] != true || len(ent["meters"].([]any)) != 2 {
		t.Fatalf("app entitlements: %v", ent)
	}
	if code, _ := notes.get("/v1/apps/notes/tenants/" + bid + "/entitlements"); code != http.StatusNotFound {
		t.Fatalf("a tenant that did not enable the app: %d", code)
	}

	// usage reporting is idempotent by id
	code, out := notes.post(base+"/usage", map[string]any{"events": []any{
		map[string]any{"id": "u1", "meter": "api_calls", "quantity": 70},
		map[string]any{"id": "u2", "meter": "api_calls", "quantity": 15},
	}})
	if code != 200 || len(out["results"].([]any)) != 2 {
		t.Fatalf("usage: %d %v", code, out)
	}
	_, out = notes.post(base+"/usage", map[string]any{"events": []any{map[string]any{"id": "u1", "meter": "api_calls", "quantity": 70}}})
	if out["results"].([]any)[0].(map[string]any)["status"] != "duplicate" {
		t.Fatalf("retry counted twice: %v", out)
	}
	if code, _ := notes.post(base+"/usage", map[string]any{"events": []any{map[string]any{"id": "x", "meter": "Bad Meter", "quantity": 1}}}); code != 422 {
		t.Fatalf("bad meter name: %d", code)
	}
	if code, _ := notes.post(base+"/usage", map[string]any{"events": []any{map[string]any{"id": "x", "meter": "a", "quantity": 1,
		"time": time.Now().Add(-60 * 24 * time.Hour)}}}); code != 422 {
		t.Fatalf("usage older than the window: %d", code)
	}
	// soft limit passed 80%: announced once to the app
	_, page := notes.get("/v1/apps/notes/changes")
	thresholds := 0
	for _, it := range page["items"].([]any) {
		if it.(map[string]any)["type"] == "matura.usage.threshold" {
			thresholds++
		}
	}
	if thresholds != 1 {
		t.Fatalf("threshold events: %d (%v)", thresholds, feedTypes(page["items"].([]any)))
	}

	// a hard quota holds under concurrency: 25 consumers race for 10
	var allowed, refused atomic.Int32
	var wg sync.WaitGroup
	for i := range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, q := notes.post(base+"/quota:consume", map[string]any{"id": "e" + strconv.Itoa(i), "meter": "exports", "quantity": 1})
			if code != 200 {
				t.Errorf("consume: %d %v", code, q)
				return
			}
			if q["allowed"] == true {
				allowed.Add(1)
			} else {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 10 || refused.Load() != 15 {
		t.Fatalf("quota: %d allowed, %d refused", allowed.Load(), refused.Load())
	}
	// a retry of an allowed consume is allowed again without consuming
	_, q := notes.post(base+"/quota:consume", map[string]any{"id": "again", "meter": "exports", "quantity": 1})
	if q["allowed"] != false || q["remaining"] != 0.0 || q["used"] != 10.0 {
		t.Fatalf("over the limit: %v", q)
	}
	// the tenant sees its usage
	usage := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/entitlements", nil)["usage"].(map[string]any)
	meters := map[string]float64{}
	for _, m := range usage["meters"].([]any) {
		meters[m.(map[string]any)["meter"].(string)] = m.(map[string]any)["used"].(float64)
	}
	if meters["notes.exports"] != 10 || meters["notes.api_calls"] != 85 {
		t.Fatalf("tenant usage: %v", meters)
	}

	// billing: link the tenant, export through a Stripe-shaped endpoint
	var got []url.Values
	var mu sync.Mutex
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_test_x" || r.URL.Path != "/v1/billing/meter_events" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		mu.Lock()
		got = append(got, r.PostForm)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"billing.meter_event"}`))
	}))
	defer stripe.Close()
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/tenants/"+aid+"/billing", map[string]any{"provider": "paypal", "customer_id": "x"})
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/billing", map[string]any{"provider": "stripe", "customer_id": "cus_123"})
	if code, _ := alice.do("PUT", "/admin/v1/tenants/"+aid+"/billing", map[string]any{"provider": "stripe", "customer_id": "cus_x"}); code != http.StatusForbidden {
		t.Fatalf("a tenant owner sets billing: %d", code)
	}
	exp := &billing.Exporter{Store: st, Adapter: &billing.Stripe{APIKey: "sk_test_x", BaseURL: stripe.URL,
		Events: map[string]string{"notes.exports": "pdf_exports"}}}
	n, err := exp.Round(ctx)
	if err != nil || n != 12 { // 2 usage reports + 10 consumed exports
		t.Fatalf("export: %d %v", n, err)
	}
	if n, _ := exp.Round(ctx); n != 0 {
		t.Fatalf("exported again: %d", n)
	}
	names := map[string]int{}
	for _, f := range got {
		if f.Get("payload[stripe_customer_id]") != "cus_123" || f.Get("identifier") == "" || f.Get("timestamp") == "" {
			t.Fatalf("meter event: %v", f)
		}
		names[f.Get("event_name")]++
	}
	if names["pdf_exports"] != 10 || names["notes_api_calls"] != 2 {
		t.Fatalf("event names: %v", names)
	}
	status := op.must(http.StatusOK, "GET", "/admin/v1/billing/exports", nil)["items"].([]any)
	if len(status) != 1 || status[0].(map[string]any)["exported"] != 12.0 || status[0].(map[string]any)["pending"] != 0.0 {
		t.Fatalf("export status: %v", status)
	}
}

// TestBillingExportResumes: a provider that fails mid-batch gets the rest on the next round, in order, and usage of
// tenants without a billing customer is skipped, not sent.
func TestBillingExportResumes(t *testing.T) {
	srv, st, _ := setupFull(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "b"})
	notes := appClient{t: t, srv: srv, clientID: "notes", pass: sec["secret"].(string)}
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	bid := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})["id"].(string)
	for _, tid := range []string{aid, bid} {
		(client{t: t, srv: srv, user: map[string]client{aid: alice, bid: bob}[tid].user}).must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/notes", nil)
	}
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/billing", map[string]any{"provider": "stripe", "customer_id": "cus_a"})
	for i, tid := range []string{aid, bid, aid, aid} { // acme, globex (no customer), acme, acme
		notes.post("/v1/apps/notes/tenants/"+tid+"/usage", map[string]any{"events": []any{
			map[string]any{"id": "e" + strconv.Itoa(i), "meter": "calls", "quantity": 1}}})
	}
	var seen []string
	fail := atomic.Bool{}
	fail.Store(true)
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if fail.Load() && len(seen) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		seen = append(seen, r.PostForm.Get("identifier"))
		_, _ = w.Write([]byte(`{}`))
	}))
	defer stripe.Close()
	exp := &billing.Exporter{Store: st, Adapter: &billing.Stripe{APIKey: "k", BaseURL: stripe.URL}}
	if n, err := exp.Round(ctx); n != 1 || err == nil {
		t.Fatalf("first round: %d %v", n, err)
	}
	fail.Store(false)
	if n, err := exp.Round(ctx); n != 2 || err != nil {
		t.Fatalf("second round: %d %v", n, err)
	}
	if len(seen) != 3 || !(len(seen[0]) > 0 && seen[0][len(seen[0])-2:] == "e0" && seen[1][len(seen[1])-2:] == "e2" && seen[2][len(seen[2])-2:] == "e3") {
		t.Fatalf("sent: %v", seen)
	}
	s := op.must(http.StatusOK, "GET", "/admin/v1/billing/exports", nil)["items"].([]any)[0].(map[string]any)
	if s["exported"] != 3.0 || s["skipped"] != 1.0 || s["pending"] != 0.0 || s["last_error"] != nil {
		t.Fatalf("status: %v", s)
	}
}
