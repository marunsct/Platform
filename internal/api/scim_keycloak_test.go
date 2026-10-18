package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// TestSCIMAgainstKeycloak provisions through maturad's SCIM endpoint into a real Keycloak 26.4
// (MATURA_TEST_KEYCLOAK_URL, master admin from MATURA_TEST_KEYCLOAK_ADMIN and MATURA_TEST_KEYCLOAK_PASSWORD, default admin/admin). It
// uses a throwaway realm with the repository's matura-admin client and user profile (so employeeNumber and department
// are kept), and deletes the realm at the end.
func TestSCIMAgainstKeycloak(t *testing.T) {
	base := strings.TrimRight(os.Getenv("MATURA_TEST_KEYCLOAK_URL"), "/")
	if base == "" {
		t.Skip("MATURA_TEST_KEYCLOAK_URL is not set")
	}
	adm := kcMaster(t, base)

	raw, err := os.ReadFile("../../keycloak/realm/matura-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	var export map[string]any
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	var adminClient map[string]any
	for _, c := range export["clients"].([]any) {
		if c.(map[string]any)["clientId"] == "matura-admin" {
			adminClient = c.(map[string]any)
		}
	}
	const secret = "scim-integration-secret-0123456789"
	adminClient["secret"] = secret
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	realm := "matura-scim-it-" + hex.EncodeToString(b)
	var svc []any
	for _, u := range export["users"].([]any) {
		if strings.HasPrefix(u.(map[string]any)["username"].(string), "service-account-") {
			svc = append(svc, u)
		}
	}
	adm.call(t, "POST", "/admin/realms", map[string]any{"realm": realm, "enabled": true,
		"registrationEmailAsUsername": true, "clients": []any{adminClient}, "users": svc,
		"components": export["components"]}, nil, http.StatusCreated)
	t.Cleanup(func() { adm.call(t, "DELETE", "/admin/realms/"+realm, nil, nil, http.StatusNoContent) })
	r := "/admin/realms/" + realm

	kc, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, ClientID: "matura-admin", ClientSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	server := api.New(store.New(testdb.New(t)), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetKeycloak(kc, base+"/realms/"+realm)
	dns := &fakeDNS{txt: map[string][]string{}}
	server.SetResolver(dns)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)

	alice := client{t: t, srv: srv, user: ids.New()}
	tid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	verifyDomain(t, alice, dns, tid, "acme.test")
	tk := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/scim/tokens", map[string]any{"name": "okta"})
	c := scimClient{t: t, base: tk["scim_base_url"].(string), token: tk["token"].(string)}

	// an account that exists in Keycloak is linked
	adm.call(t, "POST", r+"/users", map[string]any{"username": "old@acme.test", "email": "old@acme.test",
		"enabled": true, "firstName": "Old", "lastName": "Timer"}, nil, http.StatusCreated)
	var found []map[string]any
	adm.call(t, "GET", r+"/users?exact=true&email=old@acme.test", nil, &found, http.StatusOK)
	linked := c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "OLD@acme.test"})
	if linked["id"] != found[0]["id"] {
		t.Fatalf("linked %v, want %v", linked["id"], found[0]["id"])
	}

	created := c.must(http.StatusCreated, "POST", "/Users", fixture(t, "okta", "create_user", nil))
	uid := created["id"].(string)
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "enterprise", nil))
	var acct map[string]any
	adm.call(t, "GET", r+"/users/"+uid, nil, &acct, http.StatusOK)
	attrs, _ := acct["attributes"].(map[string]any)
	if acct["email"] != "test.user@acme.test" || acct["emailVerified"] != true || acct["firstName"] != "Test" ||
		attrs == nil || attrs["employeeNumber"].([]any)[0] != "701984" || attrs["department"].([]any)[0] != "Tour Operations" {
		t.Fatalf("account: %v", acct)
	}
	// a changed address in a verified domain moves the account's email (and, with email as username, its username)
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "path": `emails[type eq "work"].value`, "value": "renamed@acme.test"}}})
	adm.call(t, "GET", r+"/users/"+uid, nil, &acct, http.StatusOK)
	if acct["email"] != "renamed@acme.test" {
		t.Fatalf("email change: %v", acct)
	}

	// deactivation ends the person's Keycloak sessions; sign in first with a password set by the admin
	adm.call(t, "PUT", r+"/users/"+uid+"/reset-password", map[string]any{"type": "password",
		"value": "a-long-password-123", "temporary": false}, nil, http.StatusNoContent)
	adm.call(t, "POST", r+"/clients", map[string]any{"clientId": "it-cli", "enabled": true, "publicClient": true,
		"directAccessGrantsEnabled": true, "standardFlowEnabled": false}, nil, http.StatusCreated)
	res, err := http.PostForm(base+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"it-cli"}, "username": {"renamed@acme.test"},
		"password": {"a-long-password-123"}})
	if err != nil || res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("sign in: %v %s", err, body)
	}
	res.Body.Close()
	if s, err := kc.UserSessions(context.Background(), uid); err != nil || len(s) != 1 {
		t.Fatalf("sessions before: %v %v", s, err)
	}
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "okta", "deactivate_user", nil))
	if s, err := kc.UserSessions(context.Background(), uid); err != nil || len(s) != 0 {
		t.Fatalf("sessions after deactivation: %v %v", s, err)
	}

	// deprovisioning erases the account SCIM created, and keeps the linked one
	c.must(http.StatusNoContent, "DELETE", "/Users/"+uid, nil)
	adm.call(t, "GET", r+"/users/"+uid, nil, nil, http.StatusNotFound)
	c.must(http.StatusNoContent, "DELETE", "/Users/"+linked["id"].(string), nil)
	adm.call(t, "GET", r+"/users/"+linked["id"].(string), nil, nil, http.StatusOK)
}
