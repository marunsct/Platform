package keycloak_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/keycloak/keycloaktest"
)

func newClient(t *testing.T, f *keycloaktest.Server) *keycloak.Client {
	t.Helper()
	c, err := keycloak.New(keycloak.Config{BaseURL: f.URL, Realm: keycloaktest.Realm,
		ClientID: keycloaktest.ClientID, ClientSecret: keycloaktest.ClientSecret, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSplitIssuer(t *testing.T) {
	base, realm, err := keycloak.SplitIssuer("https://id.example.com/auth/realms/matura/")
	if err != nil || base != "https://id.example.com/auth" || realm != "matura" {
		t.Fatalf("got %q %q %v", base, realm, err)
	}
	for _, bad := range []string{"", "not a url", "https://id.example.com/", "https://id.example.com/realms/",
		"https://id.example.com/realms/a/b"} {
		if _, _, err := keycloak.SplitIssuer(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestNewChecksConfig(t *testing.T) {
	if _, err := keycloak.New(keycloak.Config{BaseURL: "http://kc", Realm: "matura", ClientID: "x"}); err == nil {
		t.Fatal("a missing secret must be refused")
	}
	if _, err := keycloak.New(keycloak.Config{BaseURL: "::", Realm: "m", ClientID: "x", ClientSecret: "y"}); err == nil {
		t.Fatal("a bad URL must be refused")
	}
}

func TestTokenCachedAndRenewed(t *testing.T) {
	f := keycloaktest.New(t)
	c := newClient(t, f)
	ctx := context.Background()
	uid := "0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11"
	f.AddSession(uid, "203.0.113.7", "agentcanvas", "matura-console")
	for range 3 {
		s, err := c.UserSessions(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 1 || s[0].IPAddress != "203.0.113.7" || len(s[0].Clients) != 2 || s[0].Clients[0] != "agentcanvas" {
			t.Fatalf("sessions: %+v", s)
		}
	}
	if f.TokenCalls != 1 {
		t.Fatalf("signed in %d times, want 1 (cached)", f.TokenCalls)
	}
	f.ExpireTokens()
	if _, err := c.UserSessions(ctx, uid); err != nil {
		t.Fatalf("after a 401 the client signs in again: %v", err)
	}
	if f.TokenCalls != 2 {
		t.Fatalf("signed in %d times, want 2", f.TokenCalls)
	}
}

func TestTypedErrors(t *testing.T) {
	f := keycloaktest.New(t)
	c := newClient(t, f)
	ctx := context.Background()
	err := c.DeleteSession(ctx, "nope")
	var kerr *keycloak.Error
	if !errors.Is(err, keycloak.ErrNotFound) || !errors.As(err, &kerr) || kerr.Status != 404 {
		t.Fatalf("missing session: %v", err)
	}
	idp := keycloak.IdentityProvider{Alias: "t-acme", ProviderID: "oidc", Enabled: true, Config: map[string]string{}}
	if err := c.CreateIdentityProvider(ctx, idp); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateIdentityProvider(ctx, idp); !errors.Is(err, keycloak.ErrConflict) {
		t.Fatalf("taken alias: %v", err)
	}

	bad, _ := keycloak.New(keycloak.Config{BaseURL: f.URL, Realm: keycloaktest.Realm, ClientID: "x", ClientSecret: "y"})
	if _, err := bad.UserSessions(ctx, "u"); !errors.As(err, &kerr) || kerr.Status != 401 {
		t.Fatalf("wrong client secret: %v", err)
	}

	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	off, _ := keycloak.New(keycloak.Config{BaseURL: down.URL, Realm: "m", ClientID: "x", ClientSecret: "y"})
	if _, err := off.UserSessions(ctx, "u"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("unreachable: %v", err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()
	timed, _ := keycloak.New(keycloak.Config{BaseURL: slow.URL, Realm: "m", ClientID: "x", ClientSecret: "y",
		Timeout: 50 * time.Millisecond})
	if _, err := timed.UserSessions(ctx, "u"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("timeout: %v", err)
	}
}

func TestResetSecondFactors(t *testing.T) {
	f := keycloaktest.New(t)
	c := newClient(t, f)
	uid := "u1"
	f.AddCredential(uid, keycloak.CredentialPassword, "")
	f.AddCredential(uid, keycloak.CredentialOTP, "phone")
	f.AddCredential(uid, keycloak.CredentialPasskey, "laptop")
	f.AddSession(uid, "198.51.100.1")
	n, err := c.ResetSecondFactors(context.Background(), uid)
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v", n, err)
	}
	creds, _ := c.Credentials(context.Background(), uid)
	if len(creds) != 1 || creds[0].Type != keycloak.CredentialPassword {
		t.Fatalf("left: %+v", creds)
	}
	if len(f.Sessions[uid]) != 0 || len(f.Logouts) != 1 {
		t.Fatal("reset must sign the user out")
	}
}

func TestPutIdentityProviderReplaces(t *testing.T) {
	f := keycloaktest.New(t)
	c := newClient(t, f)
	ctx := context.Background()
	idp := keycloak.IdentityProvider{Alias: "t-acme", ProviderID: "saml", Enabled: true,
		Config: map[string]string{"entityId": "one"}}
	m := []keycloak.IdentityProviderMapper{{Name: "email", IdentityProviderMapper: "saml-user-attribute-idp-mapper",
		Config: map[string]string{"attribute.name": "email", "user.attribute": "email"}}}
	if err := c.PutIdentityProvider(ctx, idp, m); err != nil {
		t.Fatal(err)
	}
	idp.Config["entityId"] = "two"
	if err := c.PutIdentityProvider(ctx, idp, m); err != nil {
		t.Fatal(err)
	}
	got, err := c.IdentityProvider(ctx, "t-acme")
	if err != nil || got.Config["entityId"] != "two" {
		t.Fatalf("got %+v %v", got, err)
	}
	if ms, _ := c.IdentityProviderMappers(ctx, "t-acme"); len(ms) != 1 {
		t.Fatalf("mappers are replaced, not added: %d", len(ms))
	}
	if err := c.DeleteIdentityProvider(ctx, "t-acme"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteIdentityProvider(ctx, "t-acme"); err != nil {
		t.Fatalf("deleting a missing provider is fine: %v", err)
	}
}
