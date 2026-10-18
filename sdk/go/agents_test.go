package matura_test

import (
	"context"
	"testing"
	"time"

	matura "github.com/marunsct/Platform/sdk/go"
	"github.com/marunsct/Platform/sdk/go/maturatest"
)

const agentID = "0192b7a4-0000-7000-8000-00000000a6e7"

// TestAgentPrincipals: Kind and Actor come from the kind and act claims (TS15).
func TestAgentPrincipals(t *testing.T) {
	iss, err := maturatest.NewIssuer("https://matura.test/realms/matura", "agentcanvas")
	if err != nil {
		t.Fatal(err)
	}
	v := iss.Verifier()
	tok, _ := iss.Token(maturatest.TokenOptions{UserID: agentID, TenantID: "t1", Perms: []string{"run.start"},
		Extra: map[string]any{"kind": "agent"}})
	own, err := v.Verify(context.Background(), tok)
	if err != nil || own.Kind != "agent" || own.Actor != nil || own.IsDelegated() || !own.IsService {
		t.Fatalf("own: %+v %v", own, err)
	}
	act := map[string]any{"sub": agentID, "kind": "agent", "client_id": "agent-3f9c2a1b7d4e"}
	tok, _ = iss.Token(maturatest.TokenOptions{UserID: "u1", TenantID: "t1", Perms: []string{"workflow.read"},
		Extra: map[string]any{"kind": "human", "act": act}})
	d, err := v.Verify(context.Background(), tok)
	if err != nil || d.Kind != "human" || !d.IsDelegated() || d.IsService ||
		*d.Actor != (matura.Actor{Sub: agentID, Kind: "agent", ClientID: "agent-3f9c2a1b7d4e"}) ||
		!d.Has("workflow.read") || d.Has("run.start") {
		t.Fatalf("delegated: %+v %v", d, err)
	}
	raw := func(extra map[string]any) *matura.Principal {
		claims := map[string]any{"iss": "https://matura.test/realms/matura", "aud": "agentcanvas",
			"exp": time.Now().Add(time.Minute).Unix()}
		for k, v := range extra {
			claims[k] = v
		}
		tok, err := iss.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		p, err := v.Verify(context.Background(), tok)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		raw  map[string]any
		kind string
	}{
		{map[string]any{"sub": "u", "email": "a@b.c"}, "human"},
		{map[string]any{"sub": "u", "client_id": "worker"}, "service"},
		{map[string]any{"sub": "u", "kind": "robot"}, "human"},
	} {
		if got := raw(c.raw).Kind; got != c.kind {
			t.Errorf("%v: kind %q, want %q", c.raw, got, c.kind)
		}
	}
	if p := raw(map[string]any{"sub": "u", "act": "x"}); p.Actor != nil {
		t.Errorf("malformed act: %+v", p.Actor)
	}
}

func TestResourceMetadata(t *testing.T) {
	for in, want := range map[string]string{
		"https://canvas.example.com":      "https://canvas.example.com/.well-known/oauth-protected-resource",
		"https://canvas.example.com/mcp/": "https://canvas.example.com/.well-known/oauth-protected-resource/mcp",
	} {
		if got, err := matura.MetadataURL(in); err != nil || got != want {
			t.Errorf("MetadataURL(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := matura.MetadataURL("/mcp"); err == nil {
		t.Error("a relative resource was accepted")
	}
	md, err := matura.NewResourceMetadata("https://canvas.example.com/mcp", "https://id.example.com/realms/matura")
	if err != nil || md.AuthorizationServers[0] != "https://id.example.com/realms/matura" || md.BearerMethodsSupported[0] != "header" {
		t.Fatalf("metadata: %+v %v", md, err)
	}
	if _, err := matura.NewResourceMetadata("https://canvas.example.com/mcp"); err == nil {
		t.Error("no authorization server was accepted")
	}
	h, _ := matura.WWWAuthenticate("https://canvas.example.com/mcp", matura.Challenge{})
	if h != `Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp"` {
		t.Errorf("challenge: %s", h)
	}
	h, _ = matura.WWWAuthenticate("https://canvas.example.com/mcp", matura.Challenge{Error: "insufficient_scope", Scope: `a "b"`})
	if h != `Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", scope="a \"b\""` {
		t.Errorf("challenge with error: %s", h)
	}
}
