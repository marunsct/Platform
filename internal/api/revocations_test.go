package api_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/ids"
)

// tokenCall calls maturad as user with a dev token issued at iat for tenant tid (empty: none).
func tokenCall(t *testing.T, c client, iat time.Time, tid, method, path string) int {
	t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, nil)
	req.Header.Set("X-Matura-Dev-User", c.user.String())
	req.Header.Set("X-Matura-Dev-Issued-At", strconv.FormatInt(iat.Unix(), 10))
	if tid != "" {
		req.Header.Set("X-Matura-Dev-Tenant", tid)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func revocationsFor(t *testing.T, a appClient) []map[string]any {
	t.Helper()
	code, out := a.get("/v1/apps/" + a.clientID + "/revocations")
	if code != http.StatusOK {
		t.Fatalf("revocations: %d %v", code, out)
	}
	var list []map[string]any
	for _, it := range out["items"].([]any) {
		list = append(list, it.(map[string]any))
	}
	return list
}

// TestInstantRevocation (technical specification §21): a revocation stops older tokens at once in maturad, reaches
// apps by the change feed and the revocations list, and is scoped to a tenant, a user or everywhere as asked.
func TestInstantRevocation(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "backend"})
	df := appClient{t: t, srv: srv, clientID: "devflow", pass: sec["secret"].(string)}
	nsec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "backend"})
	notes := appClient{t: t, srv: srv, clientID: "notes", pass: nsec["secret"].(string)}

	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carl := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+acme+"/apps/devflow", nil)
	globex := carl.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})["id"].(string)
	carl.must(http.StatusOK, "PUT", "/v1/tenants/"+globex+"/apps/notes", nil)
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+acme+"/members", map[string]any{"user_id": bob.user})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+acme+"/members", map[string]any{"user_id": carl.user})

	old := time.Now().Add(-time.Minute)
	if code := tokenCall(t, bob, old, acme, "GET", "/v1/tenants/"+acme); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}

	// a tenant revokes one member's tokens for itself
	if code, _ := bob.do("POST", "/v1/tenants/"+acme+"/members/"+carl.user.String()+":revoke-tokens", nil); code != http.StatusForbidden {
		t.Fatalf("a member revoked another's tokens: %d", code)
	}
	alice.must(http.StatusNoContent, "POST", "/v1/tenants/"+acme+"/members/"+bob.user.String()+":revoke-tokens", nil)
	if code := tokenCall(t, bob, old, acme, "GET", "/v1/tenants/"+acme); code != http.StatusUnauthorized {
		t.Fatalf("revoked token still works: %d", code)
	}
	if code := tokenCall(t, bob, old, "", "GET", "/v1/me"); code != http.StatusOK {
		t.Fatalf("a tenant revocation stopped a token for no tenant: %d", code)
	}
	if code := tokenCall(t, bob, time.Now().Add(2*time.Second), acme, "GET", "/v1/tenants/"+acme); code != http.StatusOK {
		t.Fatalf("a token issued after the revocation is refused: %d", code)
	}
	if code, _ := alice.do("POST", "/v1/tenants/"+acme+"/members/"+ids.New().String()+":revoke-tokens", nil); code != http.StatusNotFound {
		t.Fatalf("revoking a non-member: %d", code)
	}

	// apps hear of it: the revocations list and the change feed
	list := revocationsFor(t, df)
	if len(list) != 1 || list[0]["user_id"] != bob.user.String() || list[0]["tenant_id"] != acme ||
		list[0]["reason"] != "requested" || list[0]["not_before"] == nil {
		t.Fatalf("devflow revocations: %v", list)
	}
	if got := revocationsFor(t, notes); len(got) != 0 {
		t.Fatalf("notes (not enabled in acme) sees acme's revocation: %v", got)
	}
	_, page := df.get("/v1/apps/devflow/changes")
	found := false
	for _, it := range page["items"].([]any) {
		e := it.(map[string]any)
		if e["type"] == "matura.revocation.created" {
			rv := e["data"].(map[string]any)["revocation"].(map[string]any)
			found = rv["user_id"] == bob.user.String() && e["tenantid"] == acme
		}
	}
	if !found {
		t.Fatalf("feed lacks matura.revocation.created: %v", feedTypes(page["items"].([]any)))
	}

	// removing a member revokes their tokens for the tenant (in the same transaction)
	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+acme+"/members/"+carl.user.String(), nil)
	if code := tokenCall(t, carl, old, acme, "GET", "/v1/tenants/"+acme); code != http.StatusUnauthorized {
		t.Fatalf("removed member's old token: %d", code)
	}
	if code := tokenCall(t, carl, old, globex, "GET", "/v1/tenants/"+globex); code != http.StatusOK {
		t.Fatalf("removal from acme stopped carl's globex token: %d", code)
	}
	reasons := map[string]bool{}
	for _, r := range revocationsFor(t, df) {
		reasons[r["reason"].(string)] = true
	}
	if !reasons["membership_removed"] {
		t.Fatalf("no membership_removed revocation: %v", reasons)
	}

	// a person revokes all their own tokens, everywhere; apps of their tenants see it
	bob.must(http.StatusNoContent, "POST", "/v1/me/tokens:revoke", nil)
	if code := tokenCall(t, bob, old, "", "GET", "/v1/me"); code != http.StatusUnauthorized {
		t.Fatalf("revoke everywhere: %d", code)
	}
	everywhere := false
	for _, r := range revocationsFor(t, df) {
		everywhere = everywhere || (r["user_id"] == bob.user.String() && r["tenant_id"] == nil)
	}
	if !everywhere {
		t.Fatal("devflow does not see bob's revocation everywhere")
	}

	// operators revoke a user everywhere; others cannot
	if code, _ := alice.do("POST", "/admin/v1/users/"+bob.user.String()+":revoke-tokens", nil); code != http.StatusForbidden {
		t.Fatalf("non-operator: %d", code)
	}
	op.must(http.StatusNoContent, "POST", "/admin/v1/users/"+carl.user.String()+":revoke-tokens", nil)
	if code := tokenCall(t, carl, old, globex, "GET", "/v1/tenants/"+globex); code != http.StatusUnauthorized {
		t.Fatalf("operator revocation: %d", code)
	}
	if code, _ := op.do("POST", "/admin/v1/users/"+uuid.NewString()+":revoke-tokens", nil); code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", code)
	}

	// deactivating a user revokes their tokens everywhere at once
	dan := client{t: t, srv: srv, user: ids.New()}
	dan.must(http.StatusOK, "GET", "/v1/me", nil)
	op.must(http.StatusOK, "PATCH", "/admin/v1/users/"+dan.user.String(), map[string]any{"status": "deactivated"})
	if code := tokenCall(t, dan, old, "", "GET", "/v1/me"); code != http.StatusUnauthorized {
		t.Fatalf("deactivated user's old token: %d", code)
	}
}
