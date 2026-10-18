package api_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/ids"
)

// TestUserImport (TS27): operators import people with their organisations and roles; owners create the
// organisations; a rerun finds what it made; problems are reported per person.
func TestUserImport(t *testing.T) {
	srv, fake, _ := setupIdentity(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	existing := fake.AddAccount("old@acme.test", "Old", "Timer")
	body := map[string]any{"send_password_email": true, "users": []any{
		map[string]any{"email": "bo@acme.test", "first_name": "Bo", "source": "auth0", "external_id": "auth0|2",
			"tenants": []any{map[string]any{"slug": "acme", "tenant_role": "member",
				"app_roles": []any{map[string]any{"app": "devflow", "role": "operator"}}}}},
		map[string]any{"email": "ana@acme.test", "email_verified": true, "first_name": "Ana", "last_name": "Silva",
			"source": "auth0", "external_id": "auth0|1",
			"tenants": []any{map[string]any{"slug": "acme", "name": "Acme Inc", "tenant_role": "owner"}}},
		map[string]any{"email": "old@acme.test", "tenants": []any{map[string]any{"slug": "acme", "tenant_role": "admin"}}},
		map[string]any{"email": "gone@acme.test", "disabled": true, "tenants": []any{map[string]any{"slug": "acme"}}},
		map[string]any{"email": "lost@acme.test", "tenants": []any{map[string]any{"slug": "nobody-owns-this"}}},
		map[string]any{"email": "nope"},
	}}
	if code, _ := (client{t: t, srv: srv, user: ids.New()}).do("POST", "/admin/v1/users:import", body); code != http.StatusForbidden {
		t.Fatalf("a non-operator imported: %d", code)
	}
	out := op.must(http.StatusOK, "POST", "/admin/v1/users:import", body)
	if out["created"] != 4.0 || out["existing"] != 1.0 || out["failed"] != 1.0 {
		t.Fatalf("import: %v", out)
	}
	byEmail := map[string]map[string]any{}
	for _, r := range out["results"].([]any) {
		byEmail[r.(map[string]any)["email"].(string)] = r.(map[string]any)
	}
	if byEmail["ana@acme.test"]["created_tenants"].([]any)[0] != "acme" || byEmail["old@acme.test"]["user_id"] != existing ||
		!strings.Contains(byEmail["lost@acme.test"]["issues"].([]any)[0].(string), "no such organisation") {
		t.Fatalf("results: %v", byEmail)
	}
	ana := fake.Account(byEmail["ana@acme.test"]["user_id"].(string))
	if ana["firstName"] != "Ana" || ana["emailVerified"] != true || ana["attributes"].(map[string]any)["matura_import_id"].([]any)[0] != "auth0|1" {
		t.Fatalf("keycloak account: %v", ana)
	}
	if fake.Account(byEmail["gone@acme.test"]["user_id"].(string))["enabled"] != false {
		t.Fatal("a disabled user was imported enabled")
	}
	fake.Lock()
	emails := len(fake.ActionEmails)
	fake.Unlock()
	if emails != 3 { // bo, ana, lost: created and not disabled
		t.Fatalf("password emails: %d", emails)
	}

	// the organisation and its roles
	tenants := op.must(http.StatusOK, "GET", "/v1/tenants", nil)["items"].([]any)
	var aid string
	for _, tt := range tenants {
		if tt.(map[string]any)["slug"] == "acme" {
			aid = tt.(map[string]any)["id"].(string)
			if tt.(map[string]any)["name"] != "Acme Inc" {
				t.Fatalf("tenant: %v", tt)
			}
		}
	}
	owner := client{t: t, srv: srv, user: uuidOf(t, byEmail["ana@acme.test"]["user_id"].(string))}
	roles := map[string]string{}
	for _, m := range owner.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/members", nil)["items"].([]any) {
		m := m.(map[string]any)
		roles[m["user_id"].(string)] = m["tenant_role"].(string)
	}
	if roles[byEmail["ana@acme.test"]["user_id"].(string)] != "owner" || roles[existing] != "admin" ||
		roles[byEmail["bo@acme.test"]["user_id"].(string)] != "member" {
		t.Fatalf("roles: %v", roles)
	}
	var boRoles []string
	for _, g := range owner.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/grants", nil)["items"].([]any) {
		if g := g.(map[string]any); g["subject_id"] == byEmail["bo@acme.test"]["user_id"] && g["status"] == "active" {
			boRoles = append(boRoles, g["app"].(string)+":"+g["role"].(string))
		}
	}
	if !slices.Contains(boRoles, "devflow:operator") {
		t.Fatalf("bo's app roles: %v", boRoles)
	}

	// a rerun finds everything
	again := op.must(http.StatusOK, "POST", "/admin/v1/users:import", body)
	if again["created"] != 0.0 || again["existing"] != 5.0 {
		t.Fatalf("rerun: %v", again)
	}
}
