package api_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
)

// TestTemporaryPasswordOnboarding (TS6): an admin onboards someone by temporary password; Keycloak makes them
// change it; their first sign-in joins the tenant with the invited roles; an expired temporary password is refused.
func TestTemporaryPasswordOnboarding(t *testing.T) {
	srv, fake, _ := setupIdentity(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusOK, "PUT", base+"/apps/devflow", nil)

	out := alice.must(http.StatusCreated, "POST", base+"/invitations", map[string]any{"email": "Worker@acme.test",
		"delivery": "temp_password", "app_roles": []map[string]any{{"app": "devflow", "role": "admin"}}})
	pw, _ := out["temporary_password"].(string)
	account := out["account_id"].(string)
	inv := out["invitation"].(map[string]any)
	if len(pw) != 16 || inv["delivery"] != "temp_password" || inv["state"] != "pending" {
		t.Fatalf("created: %v", out)
	}
	acct := fake.Account(account)
	creds, _ := acct["credentials"].([]any)
	actions, _ := acct["requiredActions"].([]any)
	if acct == nil || len(creds) != 1 || creds[0].(map[string]any)["temporary"] != true || creds[0].(map[string]any)["value"] != pw ||
		!slices.Contains(actions, any("UPDATE_PASSWORD")) || !slices.Contains(actions, any("VERIFY_EMAIL")) {
		t.Fatalf("keycloak account: %v", acct)
	}
	if code, out := alice.do("POST", base+"/invitations", map[string]any{"email": "worker@acme.test", "delivery": "temp_password"}); code != http.StatusConflict {
		t.Fatalf("a second temporary password for an existing account: %d %v", code, out)
	}

	// the first sign-in (after Keycloak's forced password change) joins the tenant
	code, c := tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": account, "client_id": "devflow",
		"email": "worker@acme.test", "email_verified": true, "tenant": "acme"})
	if code != 200 || c["tid"] != aid || !slices.Equal(strs(c["roles"]), []string{"admin"}) {
		t.Fatalf("first sign-in: %d %v", code, c)
	}
	for _, i := range alice.must(http.StatusOK, "GET", base+"/invitations", nil)["items"].([]any) {
		if i.(map[string]any)["id"] == inv["id"] && i.(map[string]any)["state"] != "accepted" {
			t.Fatalf("invitation after sign-in: %v", i)
		}
	}

	// an expired temporary password refuses the sign-in
	old := store.TempPasswordTTL
	store.TempPasswordTTL = time.Second
	t.Cleanup(func() { store.TempPasswordTTL = old })
	late := alice.must(http.StatusCreated, "POST", base+"/invitations", map[string]any{"email": "late@acme.test",
		"delivery": "temp_password", "deliver_to": "manager@acme.test"})
	time.Sleep(1100 * time.Millisecond)
	if code, c := tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": late["account_id"], "client_id": "devflow",
		"email": "late@acme.test", "email_verified": true}); code != 403 || c["error_description"] != "temporary_password_expired" {
		t.Fatalf("expired temporary password: %d %v", code, c)
	}

	// only owners make owners, and members cannot onboard
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user})
	if code, _ := bob.do("POST", base+"/invitations", map[string]any{"email": "x@acme.test", "delivery": "temp_password"}); code != http.StatusForbidden {
		t.Fatalf("a member onboarded someone: %d", code)
	}
}

// TestBulkInvitations (TS6): a CSV of people becomes link invitations, with an error per bad row.
func TestBulkInvitations(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	csv := "\ufeffEmail,Tenant_Role,App_Roles,Deliver_To\n" +
		"ana@acme.test,admin,devflow:operator,\n" +
		"not-an-email,,,\n" +
		"bo@acme.test,member,devflow,\n" +
		"cy@acme.test,,devflow:nope,\n" +
		"dee@acme.test,,,boss@acme.test\n"
	req, _ := http.NewRequest("POST", srv.URL+"/v1/tenants/"+aid+"/invitations:bulk", strings.NewReader(csv))
	req.Header.Set("Content-Type", "text/csv")
	req.Header.Set("X-Matura-Dev-User", alice.user.String())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != 200 || out["invited"] != 2.0 || out["failed"] != 3.0 {
		t.Fatalf("bulk: %d %v", res.StatusCode, out)
	}
	status := map[string]string{}
	for _, r := range out["results"].([]any) {
		r := r.(map[string]any)
		status[r["email"].(string)] = r["status"].(string)
		if r["status"] == "invited" && r["accept_url"] == "" {
			t.Fatalf("no accept link: %v", r)
		}
	}
	if status["ana@acme.test"] != "invited" || status["dee@acme.test"] != "invited" || status["not-an-email"] != "error" ||
		status["bo@acme.test"] != "error" || status["cy@acme.test"] != "error" {
		t.Fatalf("results: %v", status)
	}
	if n := len(alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/invitations", nil)["items"].([]any)); n != 2 {
		t.Fatalf("invitations: %d", n)
	}
}
