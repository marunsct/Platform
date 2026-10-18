package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Instant revocation (technical specification §21). maturad refuses a bearer token a revocation covers within a
// second of the revocation being committed on any replica: it re-reads the recent revocations at most once a second.

type revocationCache struct {
	mu     sync.Mutex
	list   []store.Revocation
	loaded time.Time
}

const revocationTTL = time.Second

func (c *revocationCache) get(ctx context.Context, st *store.Store) ([]store.Revocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loaded) < revocationTTL {
		return c.list, nil
	}
	list, err := st.RecentRevocations(ctx)
	if err != nil {
		return nil, err
	}
	c.list, c.loaded = list, time.Now()
	return list, nil
}

// forget makes the next check read the database again (after this replica wrote a revocation).
func (c *revocationCache) forget() {
	c.mu.Lock()
	c.loaded = time.Time{}
	c.mu.Unlock()
}

// revoked says whether a revocation covers the caller's token. A token without iat is never covered: maturad only
// accepts tokens from its realm, which always sets iat.
func (s *Server) revoked(ctx context.Context, p Principal) (bool, error) {
	if p.IssuedAt.IsZero() {
		return false, nil
	}
	list, err := s.revocations.get(ctx, s.store)
	if err != nil {
		return false, err
	}
	var actor uuid.UUID
	if p.Actor != nil {
		actor = p.Actor.ID
	}
	for _, r := range list {
		if r.Revokes(p.UserID, actor, p.TokenTenant, p.SessionID, p.IssuedAt) {
			return true, nil
		}
	}
	return false, nil
}

// revokeTokens records a revocation and makes this replica see it at once.
func (s *Server) revokeTokens(ctx context.Context, sc store.Scope, tenantID, userID uuid.UUID, sessionID, reason string) error {
	_, err := s.store.RevokeTokens(ctx, sc, tenantID, userID, sessionID, reason)
	s.revocations.forget()
	return err
}

// --- API ---------------------------------------------------------------------------------------------------------

// GET /v1/apps/{app}/revocations: the revocations an app's SDK loads at start (and may poll); webhooks and the
// change feed carry each new one as matura.revocation.created.
func (s *Server) appRevocations(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	list, err := s.store.AppRevocations(r.Context(), app)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(list), "window_seconds": int(store.RevocationWindow.Seconds())})
}

// POST /v1/tenants/{tid}/members/{uid}:revoke-tokens: owners and admins make every token of a member for this
// tenant stop at once (their sessions elsewhere are not touched).
func (s *Server) revokeMemberTokens(w http.ResponseWriter, r *http.Request, tid, uid uuid.UUID) {
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.store.MembershipOf(r.Context(), tid, uid); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.revokeTokens(r.Context(), sc, tid, uid, "", store.RevokeRequested); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /admin/v1/users/{uid}:revoke-tokens: operators make every token of a user stop at once, everywhere.
func (s *Server) userAction(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutSuffix(r.PathValue("uid"), ":revoke-tokens")
	id, err := uuid.Parse(raw)
	if !ok || err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	if !principalFrom(r.Context()).Operator {
		problem(w, http.StatusForbidden, "forbidden", "operators only")
		return
	}
	if _, err := s.store.GetUser(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.revokeTokens(r.Context(), store.Scope{Operator: true}, uuid.Nil, id, "", store.RevokeRequested); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/me/tokens:revoke: a person stops every token of their own, everywhere (a lost device).
func (s *Server) revokeMyTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.Actor != nil || p.Kind != "human" {
		problem(w, http.StatusForbidden, "forbidden", "only people revoke their own tokens")
		return
	}
	if err := s.revokeTokens(r.Context(), store.Scope{Operator: true}, uuid.Nil, p.UserID, "", store.RevokeRequested); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
