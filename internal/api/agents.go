package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// Tenant service accounts and AI agents (TS15, technical specification §18). Owners and admins manage them; each is
// a Keycloak confidential client created here, whose secret is shown once, on creation and on rotation.

type agentGrantIn struct {
	App         string     `json:"app"`
	Role        string     `json:"role"`
	WorkspaceID *uuid.UUID `json:"workspace_id"`
}

// agentOut is an agent, with its client secret only right after creation or rotation.
type agentOut struct {
	store.Agent
	ClientSecret  string `json:"client_secret,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
}

func (s *Server) agentOut(a store.Agent, secret string) agentOut {
	out := agentOut{Agent: a, ClientSecret: secret}
	if secret != "" && s.issuer != "" {
		out.TokenEndpoint = s.issuer + "/protocol/openid-connect/token"
	}
	return out
}

func newAgentClientID(kind string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	prefix := "agent-"
	if kind == "service" {
		prefix = "svc-"
	}
	return prefix + hex.EncodeToString(b)
}

func agentClient(a store.Agent) keycloak.AgentClient {
	desc := ""
	if a.Description != nil {
		desc = *a.Description
	}
	return keycloak.AgentClient{ClientID: a.ClientID, Name: a.Name, Description: desc, TenantID: a.TenantID.String(),
		Kind: a.Kind}
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListAgents(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.store.GetAgent(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(a.Version))
	writeJSON(w, http.StatusOK, s.agentOut(a, ""))
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Kind        string         `json:"kind"`
		Name        string         `json:"name"`
		Description string         `json:"description"`
		OwnerID     uuid.UUID      `json:"owner_id"`
		ExpiresAt   *time.Time     `json:"expires_at"`
		Grants      []agentGrantIn `json:"grants"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.OwnerID == uuid.Nil {
		in.OwnerID = principalFrom(r.Context()).UserID
	}
	na := store.NewAgent{Kind: in.Kind, Name: in.Name, Description: in.Description, OwnerID: in.OwnerID,
		ExpiresAt: in.ExpiresAt}
	for _, g := range in.Grants {
		na.Grants = append(na.Grants, store.NewGrant{App: g.App, Role: g.Role, WorkspaceID: g.WorkspaceID})
	}
	if err := na.Check(time.Now()); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.CheckNewAgent(r.Context(), sc, tid, na); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	kc := keycloak.AgentClient{ClientID: newAgentClientID(na.Kind), Name: na.Name, Description: na.Description,
		TenantID: tid.String(), Kind: na.Kind}
	created, err := s.kc.CreateAgentClient(r.Context(), kc)
	if err != nil {
		if created.UUID != "" {
			s.dropClient(r, created.UUID)
		}
		s.kcFail(w, r, err)
		return
	}
	userID, err := uuid.Parse(created.ServiceUserID)
	if err != nil {
		s.dropClient(r, created.UUID)
		s.fail(w, r, err)
		return
	}
	a, err := s.store.CreateAgent(r.Context(), sc, tid, na, kc.ClientID, created.UUID, userID)
	if err != nil {
		s.dropClient(r, created.UUID)
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, s.agentOut(a, created.Secret))
}

// dropClient removes a Keycloak client created for an agent that could not be saved.
func (s *Server) dropClient(r *http.Request, uuid string) {
	if err := s.kc.DeleteClient(context.WithoutCancel(r.Context()), uuid); err != nil {
		s.log.ErrorContext(r.Context(), "removing an agent's Keycloak client after a failed save", "client", uuid,
			"err", err)
	}
}

func (s *Server) patchAgent(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Name        *string         `json:"name"`
		Description *string         `json:"description"`
		OwnerID     *uuid.UUID      `json:"owner_id"`
		ExpiresAt   json.RawMessage `json:"expires_at"` // null clears it
		Status      *string         `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	want, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	p := store.AgentPatch{Name: in.Name, Description: in.Description, OwnerID: in.OwnerID, Status: in.Status}
	switch raw := bytes.TrimSpace(in.ExpiresAt); {
	case len(raw) == 0:
	case string(raw) == "null":
		p.ClearExpiry = true
	default:
		var t time.Time
		if err := json.Unmarshal(raw, &t); err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "expires_at must be an RFC 3339 time or null")
			return
		}
		p.ExpiresAt = &t
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.store.GetAgent(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if want != 0 && cur.Version != want {
		s.fail(w, r, store.ErrVersion)
		return
	}
	a, err := s.store.UpdateAgent(r.Context(), sc, tid, id, p, want)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Keycloak follows the saved state, so a deactivation is never lost to a failed Keycloak call: maturad already
	// refuses the agent's tokens, and repeating the PATCH retries the client update.
	if s.kc != nil && (a.Name != cur.Name || !strEq(a.Description, cur.Description) || a.Status != cur.Status) {
		if err := s.kc.UpdateAgentClient(r.Context(), a.ClientUUID, agentClient(a), a.Status == "active"); err != nil {
			s.kcFail(w, r, err)
			return
		}
	}
	w.Header().Set("ETag", etag(a.Version))
	writeJSON(w, http.StatusOK, s.agentOut(a, ""))
}

func strEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.store.GetAgent(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	if err := s.kc.DeleteClient(r.Context(), a.ClientUUID); err != nil {
		s.kcFail(w, r, err)
		return
	}
	if err := s.store.DeleteAgent(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// agentAction serves POST …/agents/{id}:rotate-secret.
func (s *Server) agentAction(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	raw, found := strings.CutSuffix(r.PathValue("id"), ":rotate-secret")
	id, err := uuid.Parse(raw)
	if !found || err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.store.GetAgent(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	secret, err := s.kc.RotateClientSecret(r.Context(), a.ClientUUID)
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	if a, err = s.store.AgentSecretRotated(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.agentOut(a, secret))
}
