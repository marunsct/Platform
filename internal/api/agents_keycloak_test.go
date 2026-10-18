package api_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// TestAgentsAgainstKeycloak runs agent identity end to end against a real Keycloak 26.4 that has this repository's
// extension deployed (MATURA_TEST_KEYCLOAK_URL; master admin admin/admin or MATURA_TEST_KEYCLOAK_ADMIN/_PASSWORD).
// Keycloak's MATURA_URL must point at MATURA_TEST_KEYCLOAK_MATURA_ADDR, where this test serves maturad, and its
// MATURA_INTERNAL_TOKEN must be MATURA_TEST_KEYCLOAK_INTERNAL_TOKEN. It works in a throwaway realm: maturad creates
// an agent (a Keycloak client), the agent signs in with client credentials, and exchanges a person's token for a
// delegated one (standard token exchange, RFC 8693) whose permissions are the intersection of both.
func TestAgentsAgainstKeycloak(t *testing.T) {
	base := strings.TrimRight(os.Getenv("MATURA_TEST_KEYCLOAK_URL"), "/")
	addr, itok := os.Getenv("MATURA_TEST_KEYCLOAK_MATURA_ADDR"), os.Getenv("MATURA_TEST_KEYCLOAK_INTERNAL_TOKEN")
	if base == "" || addr == "" || itok == "" {
		t.Skip("needs MATURA_TEST_KEYCLOAK_URL, MATURA_TEST_KEYCLOAK_MATURA_ADDR and MATURA_TEST_KEYCLOAK_INTERNAL_TOKEN")
	}
	adm := kcMaster(t, base)
	realm := "matura-agents-" + hexOf(4)
	const adminSecret = "agents-integration-secret-0123456789"
	export := readRealmExport(t)
	var adminClient map[string]any
	for _, c := range export["clients"].([]any) {
		if c.(map[string]any)["clientId"] == "matura-admin" {
			adminClient = c.(map[string]any)
		}
	}
	adminClient["secret"] = adminSecret
	mapper := map[string]any{"name": "matura", "protocol": "openid-connect", "protocolMapper": keycloak.MapperID,
		"config": map[string]string{}}
	adm.call(t, "POST", "/admin/realms", map[string]any{
		"realm": realm, "enabled": true,
		"clients": []any{adminClient, map[string]any{"clientId": "itcanvas", "enabled": true, "publicClient": true,
			"directAccessGrantsEnabled": true, "standardFlowEnabled": false, "protocolMappers": []any{mapper}}},
		"users": append(export["users"].([]any), map[string]any{"username": "ana@acme.test", "email": "ana@acme.test",
			"emailVerified": true, "enabled": true, "firstName": "Ana", "lastName": "Test",
			"credentials": []any{map[string]any{"type": "password", "value": "ana-password-123", "temporary": false}}}),
	}, nil, http.StatusCreated)
	t.Cleanup(func() { adm.call(t, "DELETE", "/admin/realms/"+realm, nil, nil, http.StatusNoContent) })
	var users []struct{ ID string }
	adm.call(t, "GET", "/admin/realms/"+realm+"/users?exact=true&username=ana@acme.test", nil, &users, 200)
	anaID := users[0].ID

	// maturad on the address Keycloak's extension calls
	pool := testdb.New(t)
	keys, _ := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	kc, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, ClientID: "matura-admin", ClientSecret: adminSecret})
	if err != nil {
		t.Fatal(err)
	}
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	server := api.New(store.New(pool), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(logs, nil)))
	server.EnableInternal(itok)
	server.SetKeycloak(kc, base+"/realms/"+realm)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(server.Handler())
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	op := client{t: t, srv: srv, user: ids.New(), op: true}
	m := map[string]any{}
	for k, v := range agentCanvasManifest {
		m[k] = v
	}
	m["slug"], m["name"] = "itcanvas", "IT Canvas"
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/itcanvas", m)
	olga := client{t: t, srv: srv, user: ids.New()}
	ana := client{t: t, srv: srv, user: uuidOf(t, anaID)}
	ana.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := olga.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme-" + hexOf(3), "name": "Acme"})
	tb := "/v1/tenants/" + acme["id"].(string)
	olga.must(http.StatusOK, "PUT", tb+"/apps/itcanvas", nil)
	olga.must(http.StatusCreated, "POST", tb+"/members", map[string]any{"user_id": anaID}) // viewer: workflow.read

	ag := olga.must(http.StatusCreated, "POST", tb+"/agents", map[string]any{"kind": "agent", "name": "Report bot",
		"grants": []map[string]any{{"app": "itcanvas", "role": "runner"}}}) // workflow.read, run.start
	agentID, clientID, secret := ag["id"].(string), ag["client_id"].(string), ag["client_secret"].(string)
	tokenURL := base + "/realms/" + realm + "/protocol/openid-connect/token"

	// the agent's own token: client credentials
	code, tok := postForm(t, tokenURL, url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_secret": {secret}, "matura_app": {"itcanvas"}})
	if code != 200 {
		t.Fatalf("client credentials: %d %v", code, tok)
	}
	c := jwtClaims(t, tok["access_token"].(string))
	if c["sub"] != agentID || c["kind"] != "agent" || c["act"] != nil || c["tid"] != acme["id"] ||
		!audHas(c["aud"], "itcanvas") || !slices.Equal(strs(c["perms"]), []string{"run.start", "workflow.read"}) {
		t.Fatalf("agent token: %v", c)
	}

	// ana's token for the app lists the agent as an audience, so the agent may exchange it
	var apps []struct{ ID string }
	adm.call(t, "GET", "/admin/realms/"+realm+"/clients?clientId=itcanvas", nil, &apps, 200)
	adm.call(t, "POST", "/admin/realms/"+realm+"/clients/"+apps[0].ID+"/protocol-mappers/models", map[string]any{
		"name": "audience " + clientID, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{"included.client.audience": clientID, "access.token.claim": "true"}}, nil, 201)
	code, user := postForm(t, tokenURL, url.Values{"grant_type": {"password"}, "client_id": {"itcanvas"},
		"username": {"ana@acme.test"}, "password": {"ana-password-123"}})
	if code != 200 {
		t.Fatalf("ana's sign-in: %d %v", code, user)
	}
	uc := jwtClaims(t, user["access_token"].(string))
	if uc["sub"] != anaID || uc["kind"] != "human" || !audHas(uc["aud"], clientID) {
		t.Fatalf("ana's token: %v", uc)
	}
	exchange := func(secret string) (int, map[string]any) {
		return postForm(t, tokenURL, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"client_id": {clientID}, "client_secret": {secret}, "subject_token": {user["access_token"].(string)},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {"itcanvas"}})
	}
	code, del := exchange(secret)
	if code != 200 {
		t.Fatalf("token exchange: %d %v", code, del)
	}
	dc := jwtClaims(t, del["access_token"].(string))
	act, _ := dc["act"].(map[string]any)
	if dc["sub"] != anaID || dc["azp"] != clientID || act["sub"] != agentID || act["kind"] != "agent" ||
		dc["kind"] != "human" || !audHas(dc["aud"], "itcanvas") ||
		!slices.Equal(strs(dc["perms"]), []string{"workflow.read"}) {
		t.Fatalf("delegated token: %v", dc)
	}
	t.Logf("delegated token: sub=%v azp=%v aud=%v act=%v perms=%v", dc["sub"], dc["azp"], dc["aud"], dc["act"], dc["perms"])

	// rotation: the old secret stops working
	rot := olga.must(http.StatusOK, "POST", tb+"/agents/"+agentID+":rotate-secret", nil)
	if code, _ := postForm(t, tokenURL, url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_secret": {secret}}); code == 200 {
		t.Fatal("the old secret still works")
	}
	secret = rot["client_secret"].(string)
	// the kill switch: no own tokens, no exchanges
	olga.must(http.StatusOK, "PATCH", tb+"/agents/"+agentID, map[string]any{"status": "deactivated"})
	if code, out := postForm(t, tokenURL, url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_secret": {secret}}); code == 200 {
		t.Fatalf("deactivated agent got a token: %v", out)
	}
	if code, out := exchange(secret); code == 200 {
		t.Fatalf("deactivated agent exchanged a token: %v", out)
	}
	olga.must(http.StatusNoContent, "DELETE", tb+"/agents/"+agentID, nil)
	var left []any
	adm.call(t, "GET", "/admin/realms/"+realm+"/clients?clientId="+clientID, nil, &left, 200)
	if len(left) != 0 {
		t.Fatalf("client left after delete: %v", left)
	}
}

type kcAdmin struct{ base, token string }

func kcMaster(t *testing.T, base string) kcAdmin {
	t.Helper()
	u, p := os.Getenv("MATURA_TEST_KEYCLOAK_ADMIN"), os.Getenv("MATURA_TEST_KEYCLOAK_PASSWORD")
	if u == "" {
		u, p = "admin", "admin"
	}
	code, tok := postForm(t, base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
		"client_id": {"admin-cli"}, "username": {u}, "password": {p}})
	if code != 200 {
		t.Fatalf("master admin sign-in: %d %v", code, tok)
	}
	return kcAdmin{base: base, token: tok["access_token"].(string)}
}

func (a kcAdmin) call(t *testing.T, method, path string, in, out any, want int) {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.base+path, body)
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
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

func postForm(t *testing.T, u string, form url.Values) (int, map[string]any) {
	t.Helper()
	res, err := http.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// jwtClaims decodes a token's payload; Keycloak signed it and the test only reads it.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func audHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.Contains(a, any(want))
	}
	return false
}

func readRealmExport(t *testing.T) map[string]any {
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

func hexOf(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func uuidOf(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
