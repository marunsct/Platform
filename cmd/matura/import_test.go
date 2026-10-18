package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/import/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tenantsOf(u ImportUser) map[string]string {
	out := map[string]string{}
	for _, t := range u.Tenants {
		out[t.Slug] = t.TenantRole
	}
	return out
}

func TestFromAuth0(t *testing.T) {
	users, err := fromAuth0(fixtureFile(t, "auth0.ndjson"), importOptions{Tenant: "globex", Owners: map[string]bool{"cy@globex.test": true}})
	if err != nil || len(users) != 3 {
		t.Fatalf("%v %v", users, err)
	}
	ana, bo, cy := users[0], users[1], users[2]
	if ana.FirstName != "Ana" || !ana.EmailVerified || ana.ExternalID != "auth0|1" || tenantsOf(ana)["acme"] != "owner" {
		t.Fatalf("ana: %+v", ana)
	}
	if bo.FirstName != "Bo" || tenantsOf(bo)["acme"] != "member" {
		t.Fatalf("bo: %+v", bo)
	}
	if !cy.Disabled || tenantsOf(cy)["globex"] != "owner" { // no tenant in the export: --tenant
		t.Fatalf("cy: %+v", cy)
	}
}

func TestFromClerk(t *testing.T) {
	users, err := fromClerk(fixtureFile(t, "clerk-users.json"), fixtureFile(t, "clerk-memberships.json"),
		importOptions{AppRole: "devflow:viewer"})
	if err != nil || len(users) != 2 {
		t.Fatalf("%v %v", users, err)
	}
	ana, bo := users[0], users[1]
	if ana.Email != "ana@acme.test" || !ana.EmailVerified || tenantsOf(ana)["acme"] != "admin" || tenantsOf(ana)["globex"] != "member" ||
		len(ana.Tenants[0].AppRoles) != 1 || ana.Tenants[0].AppRoles[0].Role != "viewer" {
		t.Fatalf("ana: %+v", ana)
	}
	if bo.EmailVerified || !bo.Disabled || tenantsOf(bo)["acme"] != "member" {
		t.Fatalf("bo: %+v", bo)
	}
	csv := "id,first_name,last_name,primary_email_address\nuser_9,Dee,Doe,dee@acme.test\n"
	users, err = fromClerk([]byte(csv), nil, importOptions{Tenant: "acme"})
	if err != nil || len(users) != 1 || users[0].Email != "dee@acme.test" || tenantsOf(users[0])["acme"] != "member" {
		t.Fatalf("csv: %+v %v", users, err)
	}
}

func TestFromKeycloak(t *testing.T) {
	users, err := fromKeycloak(fixtureFile(t, "keycloak-realm.json"), importOptions{GroupPrefix: "/orgs"})
	if err != nil || len(users) != 2 { // the service account is left out
		t.Fatalf("%+v %v", users, err)
	}
	if tenantsOf(users[0])["acme"] != "admin" || len(users[0].Tenants) != 1 || !users[1].Disabled || tenantsOf(users[1])["acme"] != "member" {
		t.Fatalf("users: %+v", users)
	}
}

func TestBatchesPutOwnersFirst(t *testing.T) {
	users := []ImportUser{{Email: "m1"}, {Email: "o1", Tenants: []ImportTenant{{Slug: "a", TenantRole: "owner"}}}, {Email: "m2"}}
	b := batches(users, 2)
	if len(b) != 2 || b[0][0].Email != "o1" || len(b[1]) != 1 {
		t.Fatalf("%+v", b)
	}
}

func TestImportCommand(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/users:import" || r.Header.Get("Authorization") != "Bearer op-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		got = append(got, in)
		results := []any{}
		for _, u := range in["users"].([]any) {
			email := u.(map[string]any)["email"].(string)
			status := "created"
			if strings.HasPrefix(email, "cy") {
				status = "existing"
			}
			results = append(results, map[string]any{"email": email, "status": status})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"created": 2, "existing": 1, "failed": 0, "results": results})
	}))
	defer srv.Close()
	t.Setenv("MATURA_URL", srv.URL)
	t.Setenv("MATURA_TOKEN", "op-token")
	var out, errb bytes.Buffer
	code := run([]string{"import", "auth0", "--users", "testdata/import/auth0.ndjson", "--tenant", "globex", "--owners",
		"cy@globex.test", "--send-password-email"}, &out, &errb)
	if code != 0 || len(got) != 1 || got[0]["send_password_email"] != true ||
		!strings.Contains(out.String(), "imported 3 people: 2 created, 1 already there, 0 failed") {
		t.Fatalf("exit %d: %s %s %v", code, out.String(), errb.String(), got)
	}
	// owners go first in the request
	if first := got[0]["users"].([]any)[0].(map[string]any)["email"]; first != "ana@acme.test" && first != "cy@globex.test" {
		t.Fatalf("first: %v", first)
	}
	out.Reset()
	if code := run([]string{"import", "keycloak", "--users", "testdata/import/keycloak-realm.json", "--group-prefix", "/orgs",
		"--dry-run"}, &out, &errb); code != 0 || !strings.Contains(out.String(), `"slug": "acme"`) {
		t.Fatalf("dry run: %d %s", code, out.String())
	}
	if code := run([]string{"import", "okta", "--users", "x"}, &out, &errb); code != 2 {
		t.Fatalf("unknown source: %d", code)
	}
}
