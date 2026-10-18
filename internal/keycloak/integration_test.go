package keycloak_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
)

// TestAgainstKeycloak runs the admin client against a real Keycloak 26.4 (MATURA_TEST_KEYCLOAK_URL, e.g.
// http://localhost:8180, with the master admin from MATURA_TEST_KEYCLOAK_ADMIN / _PASSWORD, default admin/admin).
// It works in a throwaway realm that gets the repository's matura-admin client and service account, so the
// realm-management roles listed there are proven sufficient, and deletes the realm at the end.
func TestAgainstKeycloak(t *testing.T) {
	base := os.Getenv("MATURA_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("MATURA_TEST_KEYCLOAK_URL is not set")
	}
	base = strings.TrimRight(base, "/")
	ctx := context.Background()
	adm := masterAdmin(t, base)

	export := realmExport(t)
	realm := "matura-it-" + randomHex(4)
	const secret = "integration-test-secret-0123456789"
	var adminClient map[string]any
	for _, c := range export["clients"].([]any) {
		if c.(map[string]any)["clientId"] == "matura-admin" {
			adminClient = c.(map[string]any)
		}
	}
	if adminClient == nil {
		t.Fatal("keycloak/realm/matura-realm.json has no matura-admin client")
	}
	adminClient["secret"] = secret
	rep := map[string]any{
		"realm": realm, "enabled": true,
		"clients": []any{adminClient, map[string]any{"clientId": "it-cli", "enabled": true, "publicClient": true,
			"directAccessGrantsEnabled": true, "standardFlowEnabled": false}},
		"users": append(export["users"].([]any), map[string]any{"username": "ana@acme.test", "email": "ana@acme.test",
			"emailVerified": true, "enabled": true, "firstName": "Ana", "lastName": "Test",
			"credentials": []any{map[string]any{"type": "password", "value": "ana-password-123", "temporary": false}}}),
	}
	adm.call(t, "POST", "/admin/realms", rep, nil, http.StatusCreated)
	t.Cleanup(func() { adm.call(t, "DELETE", "/admin/realms/"+realm, nil, nil, http.StatusNoContent) })

	c, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, ClientID: "matura-admin", ClientSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	var users []struct{ ID string }
	adm.call(t, "GET", "/admin/realms/"+realm+"/users?exact=true&username=ana@acme.test", nil, &users, 200)
	uid := users[0].ID

	signIn := func() {
		res, err := http.PostForm(base+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{
			"grant_type": {"password"}, "client_id": {"it-cli"}, "username": {"ana@acme.test"},
			"password": {"ana-password-123"}})
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("sign in: %v %v", err, res)
		}
		res.Body.Close()
	}
	signIn()
	signIn()
	sessions, err := c.UserSessions(ctx, uid)
	if err != nil || len(sessions) != 2 || sessions[0].IPAddress == "" || sessions[0].Clients[0] != "it-cli" {
		t.Fatalf("sessions: %+v %v", sessions, err)
	}
	if err := c.DeleteSession(ctx, sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteSession(ctx, sessions[0].ID); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("deleting it again: %v", err)
	}
	if err := c.LogoutUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.UserSessions(ctx, uid); len(s) != 0 {
		t.Fatalf("after logout: %+v", s)
	}
	creds, err := c.Credentials(ctx, uid)
	if err != nil || len(creds) != 1 || creds[0].Type != keycloak.CredentialPassword {
		t.Fatalf("credentials: %+v %v", creds, err)
	}
	if n, err := c.ResetSecondFactors(ctx, uid); err != nil || n != 0 {
		t.Fatalf("reset: %d %v", n, err)
	}

	// identity providers, with configuration read by Keycloak from this realm's own discovery and SAML metadata
	oidc, err := c.ImportConfig(ctx, "oidc", base+"/realms/"+realm+"/.well-known/openid-configuration")
	if err != nil || oidc["tokenUrl"] == "" {
		t.Fatalf("oidc import: %v %v", oidc, err)
	}
	oidc["clientId"], oidc["clientSecret"] = "x", "y"
	idp := keycloak.IdentityProvider{Alias: "t-acme", DisplayName: "Acme", ProviderID: "oidc", Enabled: true,
		TrustEmail: true, HideOnLogin: true, Config: oidc}
	mappers := []keycloak.IdentityProviderMapper{{Name: "email", IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
		Config: map[string]string{"claim": "email", "user.attribute": "email", "syncMode": "INHERIT"}}}
	if err := c.PutIdentityProvider(ctx, idp, mappers); err != nil {
		t.Fatal(err)
	}
	if err := c.PutIdentityProvider(ctx, idp, mappers); err != nil {
		t.Fatalf("putting it again updates it: %v", err)
	}
	got, err := c.IdentityProvider(ctx, "t-acme")
	if err != nil || got.DisplayName != "Acme" || !got.TrustEmail {
		t.Fatalf("read back: %+v %v", got, err)
	}
	if ms, err := c.IdentityProviderMappers(ctx, "t-acme"); err != nil || len(ms) != 1 {
		t.Fatalf("mappers: %+v %v", ms, err)
	}
	saml, err := c.ImportConfig(ctx, "saml", base+"/realms/"+realm+"/protocol/saml/descriptor")
	if err != nil || saml["singleSignOnServiceUrl"] == "" {
		t.Fatalf("saml import: %v %v", saml, err)
	}
	if err := c.DeleteIdentityProvider(ctx, "t-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.IdentityProvider(ctx, "t-acme"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}

	// erasure deletes the account (api.UserDirectory)
	if err := c.DeleteUser(ctx, uuid.MustParse(uid)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Credentials(ctx, uid); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("after deleting the user: %v", err)
	}
}

// TestRealmExportImports loads keycloak/realm/matura-realm.json into a throwaway realm, when the Keycloak under test
// has Matura's extension (its authenticators are named in the flows).
func TestRealmExportImports(t *testing.T) {
	base := os.Getenv("MATURA_TEST_KEYCLOAK_URL")
	if base == "" {
		t.Skip("MATURA_TEST_KEYCLOAK_URL is not set")
	}
	base = strings.TrimRight(base, "/")
	adm := masterAdmin(t, base)
	var info struct {
		Providers map[string]struct {
			Providers map[string]any `json:"providers"`
		} `json:"providers"`
	}
	adm.call(t, "GET", "/admin/serverinfo", nil, &info, 200)
	auth := info.Providers["authenticator"].Providers
	if auth["matura-mfa-policy"] == nil || auth["matura-sso"] == nil {
		t.Skip("this Keycloak runs an older Matura extension (no matura-mfa-policy); run `make keycloak-ext` and deploy it")
	}
	export := realmExport(t)
	realm := "matura-it-" + randomHex(4)
	export["realm"] = realm
	raw, _ := json.Marshal(export)
	// the admin API does not resolve ${env.X:default} placeholders the startup import does
	var rep map[string]any
	_ = json.Unmarshal([]byte(strings.ReplaceAll(string(raw), "${env.", "$env-")), &rep)
	adm.call(t, "POST", "/admin/realms", rep, nil, http.StatusCreated)
	t.Cleanup(func() { adm.call(t, "DELETE", "/admin/realms/"+realm, nil, nil, http.StatusNoContent) })
	var got map[string]any
	adm.call(t, "GET", "/admin/realms/"+realm, nil, &got, 200)
	if got["browserFlow"] != "matura browser" {
		t.Fatalf("browser flow: %v", got["browserFlow"])
	}
	var execs []struct {
		ProviderID  string `json:"providerId"`
		Requirement string `json:"requirement"`
	}
	adm.call(t, "GET", "/admin/realms/"+realm+"/authentication/flows/"+url.PathEscape("matura sso first login")+
		"/executions", nil, &execs, 200)
	if len(execs) == 0 || execs[0].ProviderID != "matura-sso" || execs[0].Requirement != "REQUIRED" {
		t.Fatalf("sso first-login flow: %+v", execs)
	}
}

type adminAPI struct {
	base, token string
}

func masterAdmin(t *testing.T, base string) adminAPI {
	t.Helper()
	user, pass := os.Getenv("MATURA_TEST_KEYCLOAK_ADMIN"), os.Getenv("MATURA_TEST_KEYCLOAK_PASSWORD")
	if user == "" {
		user, pass = "admin", "admin"
	}
	res, err := http.PostForm(base+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {user}, "password": {pass}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("master admin sign-in: %d %v", res.StatusCode, err)
	}
	return adminAPI{base: base, token: tok.AccessToken}
}

func (a adminAPI) call(t *testing.T, method, path string, in, out any, want int) {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, a.base+path, body)
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
}

func realmExport(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../keycloak/realm/matura-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
