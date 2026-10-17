package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/keycloak/keycloaktest"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// fakeDNS answers TXT lookups from a map.
type fakeDNS struct {
	mu  sync.Mutex
	txt map[string][]string
}

func (d *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (d *fakeDNS) set(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txt[name] = append(d.txt[name], value)
}

// setupIdentity is setup with a fake Keycloak admin API and fake DNS.
func setupIdentity(t *testing.T) (*httptest.Server, *keycloaktest.Server, *fakeDNS) {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	fake := keycloaktest.New(t)
	kc, err := keycloak.New(keycloak.Config{BaseURL: fake.URL, Realm: keycloaktest.Realm,
		ClientID: keycloaktest.ClientID, ClientSecret: keycloaktest.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS{txt: map[string][]string{}}
	server := api.New(store.New(pool), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(logs, nil)))
	server.EnableInternal(internalToken)
	server.SetKeycloak(kc, "https://id.example.test/realms/matura")
	server.SetResolver(dns)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv, fake, dns
}

func internalCall(t *testing.T, base, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+internalToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// withSession calls as c with a token from the given Keycloak session.
func withSession(c client, sid, method, path string) (int, map[string]any) {
	req, _ := http.NewRequest(method, c.srv.URL+path, nil)
	req.Header.Set("X-Matura-Dev-User", c.user.String())
	req.Header.Set("X-Matura-Dev-Session", sid)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// TestMySessionsAndMFA: people see and end their own Keycloak sessions and see their second factors and whether a
// tenant requires one (TS12).
func TestMySessionsAndMFA(t *testing.T) {
	srv, fake, _ := setupIdentity(t)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	s1 := fake.AddSession(alice.user.String(), "203.0.113.1", "agentcanvas")
	s2 := fake.AddSession(alice.user.String(), "203.0.113.2", "matura-console")
	s3 := fake.AddSession(alice.user.String(), "203.0.113.3")
	bobs := fake.AddSession(bob.user.String(), "198.51.100.9")

	code, out := withSession(alice, s1, "GET", "/v1/me/sessions")
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 3 {
		t.Fatalf("sessions: %d %v", code, out)
	}
	current := 0
	for _, it := range items {
		if it.(map[string]any)["current"] == true {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("exactly one session is the current one: %v", items)
	}
	alice.must(http.StatusNotFound, "DELETE", "/v1/me/sessions/"+bobs, nil)
	alice.must(http.StatusNoContent, "DELETE", "/v1/me/sessions/"+s2, nil)
	alice.must(http.StatusUnprocessableEntity, "DELETE", "/v1/me/sessions?keep_current=true", nil) // no sid
	if code, _ := withSession(alice, s1, "DELETE", "/v1/me/sessions?keep_current=true"); code != 204 {
		t.Fatalf("sign out elsewhere: %d", code)
	}
	fake.Lock()
	left := fake.Sessions[alice.user.String()]
	fake.Unlock()
	if len(left) != 1 || left[0].ID != s1 {
		t.Fatalf("left %v, want only %s (and %s gone)", left, s1, s3)
	}
	alice.must(http.StatusNoContent, "DELETE", "/v1/me/sessions", nil)
	fake.Lock()
	if len(fake.Sessions[alice.user.String()]) != 0 || len(fake.Sessions[bob.user.String()]) != 1 {
		t.Fatal("signing out everywhere ends only the caller's sessions")
	}
	fake.Unlock()

	fake.AddCredential(alice.user.String(), keycloak.CredentialPassword, "")
	fake.AddCredential(alice.user.String(), keycloak.CredentialOTP, "phone")
	mfa := alice.must(http.StatusOK, "GET", "/v1/me/mfa", nil)
	if mfa["configured"] != true || mfa["required"] != false || len(mfa["factors"].([]any)) != 1 {
		t.Fatalf("mfa: %v", mfa)
	}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+acme["id"].(string)+"/security-policy", map[string]any{"require_mfa": true})
	mfa = alice.must(http.StatusOK, "GET", "/v1/me/mfa", nil)
	if mfa["required"] != true || strs(mfa["required_by"])[0] != "acme" {
		t.Fatalf("mfa after the policy: %v", mfa)
	}
	if code, out := internalCall(t, srv.URL, "/internal/v1/mfa-policy", map[string]any{"user_id": alice.user}); code != 200 || out["required"] != true {
		t.Fatalf("mfa policy for a member: %d %v", code, out)
	}
	if code, out := internalCall(t, srv.URL, "/internal/v1/mfa-policy", map[string]any{"user_id": bob.user}); code != 200 || out["required"] != false {
		t.Fatalf("mfa policy for someone else: %d %v", code, out)
	}

	// without a Keycloak admin client the endpoints say so
	plain := client{t: t, srv: setup(t), user: ids.New()}
	plain.must(http.StatusServiceUnavailable, "GET", "/v1/me/sessions", nil)
}

// TestMemberSessionsAndMFAReset: owners and admins sign members out and reset their second factors, only for people
// their tenant governs (sole organisation, or an email domain the tenant verified), never an admin over an owner.
func TestMemberSessionsAndMFAReset(t *testing.T) {
	srv, fake, dns := setupIdentity(t)
	alice := client{t: t, srv: srv, user: ids.New()} // acme owner
	dave := client{t: t, srv: srv, user: ids.New()}  // acme admin
	bob := client{t: t, srv: srv, user: ids.New()}   // acme member only
	carol := client{t: t, srv: srv, user: ids.New()} // acme and globex member
	gina := client{t: t, srv: srv, user: ids.New()}  // globex owner
	for _, c := range []client{dave, bob, carol} {
		c.must(http.StatusOK, "GET", "/v1/me", nil)
	}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	globex := gina.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": dave.user, "tenant_role": "admin"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": carol.user})
	gina.must(http.StatusCreated, "POST", "/v1/tenants/"+globex["id"].(string)+"/members", map[string]any{"user_id": carol.user})
	fake.AddSession(bob.user.String(), "198.51.100.1", "agentcanvas")
	fake.AddCredential(bob.user.String(), keycloak.CredentialPassword, "")
	fake.AddCredential(bob.user.String(), keycloak.CredentialOTP, "phone")
	fake.AddCredential(bob.user.String(), keycloak.CredentialWebAuthn, "key")
	m := "/v1/tenants/" + aid + "/members/"

	got := alice.must(http.StatusOK, "GET", m+bob.user.String()+"/sessions", nil)
	if len(got["items"].([]any)) != 1 {
		t.Fatalf("bob's sessions: %v", got)
	}
	bob.must(http.StatusForbidden, "GET", m+alice.user.String()+"/sessions", nil)   // members do not manage
	gina.must(http.StatusNotFound, "GET", m+bob.user.String()+"/sessions", nil)     // other tenants see nothing
	alice.must(http.StatusNotFound, "GET", m+gina.user.String()+"/sessions", nil)   // not a member of acme
	dave.must(http.StatusForbidden, "POST", m+alice.user.String()+":sign-out", nil) // admin over owner
	alice.must(http.StatusNotFound, "POST", m+bob.user.String()+":explode", nil)

	alice.must(http.StatusNoContent, "POST", m+bob.user.String()+":sign-out", nil)
	fake.Lock()
	if !slices.Contains(fake.Logouts, bob.user.String()) {
		t.Fatal("bob was not signed out")
	}
	fake.Unlock()
	res := dave.must(http.StatusOK, "POST", m+bob.user.String()+":reset-mfa", nil)
	if res["removed"].(float64) != 2 {
		t.Fatalf("reset: %v", res)
	}
	fake.Lock()
	if n := len(fake.Credentials[bob.user.String()]); n != 1 {
		t.Fatalf("bob keeps %d credentials, want only the password", n)
	}
	fake.Unlock()
	alice.must(http.StatusUnprocessableEntity, "POST", m+alice.user.String()+":reset-mfa", nil)

	// carol also belongs to globex: acme may not touch her account until it verifies her email domain
	code, out := alice.do("POST", m+carol.user.String()+":reset-mfa", nil)
	if code != http.StatusForbidden || out["type"] != "https://matura.dev/problems/not-governed" {
		t.Fatalf("carol: %d %v", code, out)
	}
	d := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/domains", map[string]any{"domain": "example.test"})
	dns.set(d["record_name"].(string), d["record_value"].(string))
	alice.must(http.StatusOK, "POST", "/v1/tenants/"+aid+"/domains/example.test:verify", nil)
	alice.must(http.StatusNoContent, "POST", m+carol.user.String()+":sign-out", nil)

	// operators may act on anyone
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusNoContent, "POST", "/v1/tenants/"+globex["id"].(string)+"/members/"+carol.user.String()+":sign-out", nil)
}

// TestDomainsAndSSO: a tenant verifies a domain over DNS, connects an OIDC or SAML identity provider (created in
// Keycloak), home-realm discovery finds it, and sign-ins through it join the tenant only for verified domains (TS13).
func TestDomainsAndSSO(t *testing.T) {
	srv, fake, dns := setupIdentity(t)
	alice := client{t: t, srv: srv, user: ids.New()}
	gina := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	globex := gina.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	gid := globex["id"].(string)

	alice.must(http.StatusUnprocessableEntity, "POST", "/v1/tenants/"+aid+"/domains", map[string]any{"domain": "not a domain"})
	d := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/domains", map[string]any{"domain": "Acme.TEST"})
	if d["domain"] != "acme.test" || d["record_name"] != "_matura-challenge.acme.test" || d["verified"] != false {
		t.Fatalf("domain: %v", d)
	}
	alice.must(http.StatusConflict, "POST", "/v1/tenants/"+aid+"/domains", map[string]any{"domain": "acme.test"})
	alice.must(http.StatusUnprocessableEntity, "POST", "/v1/tenants/"+aid+"/domains/acme.test:verify", nil)
	dns.set("_matura-challenge.acme.test", "unrelated")
	dns.set("_matura-challenge.acme.test", d["record_value"].(string))
	v := alice.must(http.StatusOK, "POST", "/v1/tenants/"+aid+"/domains/acme.test:verify", nil)
	if v["verified"] != true {
		t.Fatalf("verify: %v", v)
	}
	// globex can claim acme.test but never verify it while acme holds it
	gd := gina.must(http.StatusCreated, "POST", "/v1/tenants/"+gid+"/domains", map[string]any{"domain": "acme.test"})
	dns.set("_matura-challenge.acme.test", gd["record_value"].(string))
	gina.must(http.StatusConflict, "POST", "/v1/tenants/"+gid+"/domains/acme.test:verify", nil)
	gina.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+gid+"/domains/acme.test", nil)

	oidc := map[string]any{"protocol": "oidc", "discovery_url": "https://login.acme.test/", "client_id": "matura",
		"client_secret": "s3cret-value"}
	gina.must(http.StatusUnprocessableEntity, "POST", "/v1/tenants/"+gid+"/sso", oidc) // no verified domain
	alice.must(http.StatusUnprocessableEntity, "POST", "/v1/tenants/"+aid+"/sso",
		map[string]any{"protocol": "oidc", "discovery_url": "http://login.acme.test/", "client_id": "m", "client_secret": "s"})
	alice.must(http.StatusUnprocessableEntity, "POST", "/v1/tenants/"+aid+"/sso", oidc) // Keycloak cannot read it
	fake.Lock()
	fake.Imports["https://login.acme.test/.well-known/openid-configuration"] = map[string]string{
		"issuer": "https://login.acme.test/", "authorizationUrl": "https://login.acme.test/authorize",
		"tokenUrl": "https://login.acme.test/token", "jwksUrl": "https://login.acme.test/jwks"}
	fake.Unlock()
	c := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/sso", oidc)
	if c["alias"] != "t-acme" || c["idp_hint"] != "t-acme" || c["has_client_secret"] != true ||
		c["redirect_uri"] != "https://id.example.test/realms/matura/broker/t-acme/endpoint" || c["client_secret"] != nil {
		t.Fatalf("connection: %v", c)
	}
	fake.Lock()
	idp := fake.IdPs["t-acme"]
	cfg := idp["config"].(map[string]any)
	if cfg["clientSecret"] != "s3cret-value" || cfg["tokenUrl"] != "https://login.acme.test/token" ||
		idp["firstBrokerLoginFlowAlias"] != "matura sso first login" || idp["trustEmail"] != true ||
		len(fake.Mappers["t-acme"]) != 3 {
		t.Fatalf("keycloak identity provider: %v", idp)
	}
	fake.Unlock()
	alice.must(http.StatusConflict, "POST", "/v1/tenants/"+aid+"/sso", oidc)
	got := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/sso", nil)
	if got["protocol"] != "oidc" || got["config"].(map[string]any)["client_id"] != "matura" {
		t.Fatalf("get: %v", got)
	}
	gina.must(http.StatusNotFound, "GET", "/v1/tenants/"+aid+"/sso", nil)

	// home-realm discovery is public
	anon := client{t: t, srv: srv}
	if out := anon.must(http.StatusOK, "GET", "/v1/sso/discover?email=Bob@ACME.test", nil); out["idp_hint"] != "t-acme" || out["tenant"] != "acme" {
		t.Fatalf("discover: %v", out)
	}
	if out := anon.must(http.StatusOK, "GET", "/v1/sso/discover?email=bob@globex.test", nil); out["sso"] != false {
		t.Fatalf("discover elsewhere: %v", out)
	}
	anon.must(http.StatusBadRequest, "GET", "/v1/sso/discover", nil)

	// sign-ins through the IdP: only verified domains, and the user joins with default roles
	code, out := internalCall(t, srv.URL, "/internal/v1/sso-login", map[string]any{"alias": "t-acme", "email": "ceo@globex.test"})
	if code != 403 || out["error_description"] != "domain_not_verified" {
		t.Fatalf("foreign address: %d %v", code, out)
	}
	if code, _ := internalCall(t, srv.URL, "/internal/v1/sso-login", map[string]any{"alias": "t-acme", "email": "new@acme.test"}); code != 200 {
		t.Fatalf("check before the account exists: %d", code)
	}
	newbie := uuid.New()
	code, out = internalCall(t, srv.URL, "/internal/v1/sso-login", map[string]any{"alias": "t-acme", "email": "new@acme.test",
		"user_id": newbie, "name": "New Person"})
	if code != 200 || out["joined"] != true || out["tenant"] != "acme" {
		t.Fatalf("jit: %d %v", code, out)
	}
	if _, out = internalCall(t, srv.URL, "/internal/v1/sso-login", map[string]any{"alias": "t-acme", "email": "new@acme.test",
		"user_id": newbie}); out["joined"] != false {
		t.Fatalf("second sign-in: %v", out)
	}
	members := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/members", nil)["items"].([]any)
	if len(members) != 2 {
		t.Fatalf("members: %v", members)
	}
	if code, out := internalCall(t, srv.URL, "/internal/v1/sso-login", map[string]any{"alias": "t-nope", "email": "a@acme.test"}); code != 403 || out["error_description"] != "unknown_identity_provider" {
		t.Fatalf("unknown alias: %d %v", code, out)
	}

	// SAML for globex
	gd = gina.must(http.StatusCreated, "POST", "/v1/tenants/"+gid+"/domains", map[string]any{"domain": "globex.test"})
	dns.set("_matura-challenge.globex.test", gd["record_value"].(string))
	gina.must(http.StatusOK, "POST", "/v1/tenants/"+gid+"/domains/globex.test:verify", nil)
	fake.Lock()
	fake.Imports["https://idp.globex.test/metadata"] = map[string]string{"idpEntityId": "https://idp.globex.test",
		"singleSignOnServiceUrl": "https://idp.globex.test/sso", "signingCertificate": "MIIC..."}
	fake.Unlock()
	sc := gina.must(http.StatusCreated, "POST", "/v1/tenants/"+gid+"/sso", map[string]any{"protocol": "saml",
		"metadata_url": "https://idp.globex.test/metadata", "email_attribute": "mail", "default_tenant_role": "billing"})
	if sc["entity_id"] != "https://id.example.test/realms/matura" || sc["metadata_url"] == nil || sc["default_tenant_role"] != "billing" {
		t.Fatalf("saml: %v", sc)
	}
	fake.Lock()
	if mp := fake.Mappers["t-globex"]; len(mp) != 3 || mp[0]["config"].(map[string]any)["attribute.name"] != "mail" {
		t.Fatalf("saml mappers: %v", mp)
	}
	fake.Unlock()

	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+aid+"/sso", nil)
	fake.Lock()
	if _, ok := fake.IdPs["t-acme"]; ok {
		t.Fatal("identity provider left in Keycloak")
	}
	fake.Unlock()
	if out := anon.must(http.StatusOK, "GET", "/v1/sso/discover?email=bob@acme.test", nil); out["sso"] != false {
		t.Fatalf("discover after delete: %v", out)
	}
	alice.must(http.StatusNotFound, "DELETE", "/v1/tenants/"+aid+"/sso", nil)
}

// TestSessionLimits: the token mapper's session times are checked against the tenant's session_max_age and
// idle_timeout (security policy).
func TestSessionLimits(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	appClient := op.must(http.StatusOK, "GET", "/v1/apps", nil)["items"].([]any)[0].(map[string]any)["client_id"].(string)
	ask := func(started, lastUse time.Duration) (int, map[string]any) {
		now := time.Now()
		body := map[string]any{"user_id": alice.user, "client_id": appClient, "tenant": "acme",
			"session_started": now.Add(-started).UnixMilli()}
		if lastUse > 0 {
			body["session_last_use"] = now.Add(-lastUse).UnixMilli()
		}
		return internalCall(t, srv.URL, "/internal/v1/token-context", body)
	}
	if code, _ := ask(48*time.Hour, 0); code != 200 {
		t.Fatalf("no policy: %d", code)
	}
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/security-policy", map[string]any{"session_max_age": 3600, "idle_timeout": 600})
	if code, out := ask(2*time.Hour, time.Minute); code != 403 || out["error_description"] != "session_expired" {
		t.Fatalf("too old: %d %v", code, out)
	}
	if code, out := ask(30*time.Minute, 20*time.Minute); code != 403 || out["error_description"] != "session_expired" {
		t.Fatalf("idle: %d %v", code, out)
	}
	if code, out := ask(30*time.Minute, time.Minute); code != 200 {
		t.Fatalf("within limits: %d %v", code, out)
	}
}
