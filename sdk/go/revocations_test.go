package matura_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	matura "github.com/marunsct/Platform/sdk/go"
	"github.com/marunsct/Platform/sdk/go/maturatest"
)

func TestRevocationsStopTokens(t *testing.T) {
	iss := newIssuer(t)
	revs := matura.NewRevocations()
	v, err := matura.NewVerifier(matura.VerifierOptions{Issuer: iss.Issuer, Audience: iss.Audience, JWKS: iss.JWKS(),
		Revocations: revs})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, agent, tid, other := "u-1", "a-1", "t-1", "t-2"
	old := time.Now().Add(-time.Minute)
	tok := func(sub, tenant string, at time.Time, extra map[string]any) string {
		return mustToken(t, iss, maturatest.TokenOptions{UserID: sub, TenantID: tenant, Now: at, Extra: extra})
	}
	oldToken := tok(user, tid, old, map[string]any{"sid": "s1"})
	if _, err := v.Verify(ctx, oldToken); err != nil {
		t.Fatal(err)
	}

	// a revocation for one session, from a webhook event
	ev := &matura.Event{Type: "matura.revocation.created", Data: matura.EventData{Object: "revocation", Version: 9}}
	ev.Data.Payload, _ = json.Marshal(map[string]any{"id": "r1", "user_id": user, "tenant_id": nil, "session_id": "s2",
		"not_before": time.Now().UTC().Format(time.RFC3339Nano), "reason": "session_ended"})
	if !revs.Apply(ev) {
		t.Fatal("revocation event not applied")
	}
	if _, err := v.Verify(ctx, oldToken); err != nil {
		t.Fatalf("another session's revocation stopped this token: %v", err)
	}

	// a revocation for the tenant
	revs.Add(matura.Revocation{ID: "r2", UserID: user, TenantID: tid, NotBefore: time.Now()})
	if _, err := v.Verify(ctx, oldToken); !errors.Is(err, matura.ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	if _, err := v.Verify(ctx, tok(user, other, old, nil)); err != nil {
		t.Fatalf("another tenant's token stopped: %v", err)
	}
	if _, err := v.Verify(ctx, tok(user, tid, time.Now().Add(2*time.Second), nil)); err != nil {
		t.Fatalf("a token issued after the revocation is refused: %v", err)
	}

	// an agent's revocation stops its own tokens and the ones it got for people
	revs.Add(matura.Revocation{ID: "r3", UserID: agent, NotBefore: time.Now()})
	if _, err := v.Verify(ctx, tok(agent, tid, old, map[string]any{"kind": "agent"})); err == nil {
		t.Fatal("agent's own token accepted")
	}
	delegated := tok("u-9", tid, old, map[string]any{"act": map[string]any{"sub": agent, "kind": "agent"}})
	if _, err := v.Verify(ctx, delegated); err == nil {
		t.Fatal("delegated token of a revoked agent accepted")
	}

	// old revocations are forgotten; other events are ignored
	revs.Add(matura.Revocation{ID: "ancient", UserID: "u-x", NotBefore: time.Now().Add(-time.Hour)})
	if revs.Len() != 3 {
		t.Fatalf("held %d revocations", revs.Len())
	}
	if revs.Apply(&matura.Event{Type: "matura.user.updated", Data: matura.EventData{Object: "user"}}) {
		t.Fatal("a user event was taken for a revocation")
	}
}

func TestRevocationsLoad(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, sec, ok := r.BasicAuth(); !ok || id != "notes" || sec != "secret" || r.URL.Path != "/v1/apps/notes/revocations" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "r1", "user_id": "u-1",
			"tenant_id": nil, "session_id": nil, "not_before": time.Now().UTC(), "reason": "requested"}}})
	}))
	defer srv.Close()
	revs := matura.NewRevocations()
	if err := revs.Load(context.Background(), matura.NewClient(srv.URL, "notes", "secret"), "notes"); err != nil {
		t.Fatal(err)
	}
	c := &matura.Claims{Subject: "u-1", TenantID: "any", IssuedAt: time.Now().Add(-time.Minute).Unix()}
	if revs.Len() != 1 || !revs.Revoked(c) {
		t.Fatalf("loaded %d; revoked %v", revs.Len(), revs.Revoked(c))
	}
	if err := revs.Load(context.Background(), matura.NewClient(srv.URL, "notes", "wrong"), "notes"); err == nil {
		t.Fatal("bad credentials accepted")
	}
}
