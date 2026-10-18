package api

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Consent for agents acting on a person's behalf (technical specification §20.5).

// person refuses agents and delegated calls: only people give or withdraw their own consent.
func person(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	p := principalFrom(r.Context())
	if p.Actor != nil || p.Kind != "human" {
		problem(w, http.StatusForbidden, "forbidden", "only people give or withdraw consent, not agents")
		return p, false
	}
	return p, true
}

// GET /v1/me/consent-request?client_id=agent-…: what the consent screen shows.
func (s *Server) consentRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := person(w, r)
	if !ok {
		return
	}
	client := r.URL.Query().Get("client_id")
	if client == "" {
		problem(w, http.StatusBadRequest, "bad-request", "client_id is required")
		return
	}
	out, err := s.store.ConsentRequestFor(r.Context(), client, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /v1/me/consents {client_id, permissions?, expires_at?}: approve an agent (replaces an earlier consent).
func (s *Server) grantConsent(w http.ResponseWriter, r *http.Request) {
	p, ok := person(w, r)
	if !ok {
		return
	}
	var in struct {
		ClientID    string     `json:"client_id"`
		Permissions *[]string  `json:"permissions"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ClientID == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid", "client_id is required")
		return
	}
	var perms []string
	if in.Permissions != nil {
		perms = append([]string{}, *in.Permissions...)
	}
	out, err := s.store.GrantConsent(r.Context(), in.ClientID, p.UserID, perms, in.ExpiresAt)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// GET /v1/me/consents: the agents I let act for me.
func (s *Server) myConsents(w http.ResponseWriter, r *http.Request) {
	p, ok := person(w, r)
	if !ok {
		return
	}
	out, err := s.store.MyConsents(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// DELETE /v1/me/consents/{id}: withdraw; the agent's tokens for me stop at once (§21).
func (s *Server) withdrawMyConsent(w http.ResponseWriter, r *http.Request) {
	p, ok := person(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	tid, err := s.store.ConsentTenant(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.store.WithdrawConsent(r.Context(), store.Scope{TenantID: tid, UserID: p.UserID}, tid, uuid.Nil, id,
		&p.UserID, p.UserID); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/tenants/{tid}/agents/{id}/consents: owners and admins see who approved an agent.
func (s *Server) agentConsents(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	aid, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.AgentConsents(r.Context(), sc, tid, aid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// DELETE /v1/tenants/{tid}/agents/{id}/consents/{cid}: owners and admins withdraw a person's consent.
func (s *Server) withdrawAgentConsent(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	aid, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	cid, ok := pathUUID(w, r, "cid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.store.WithdrawConsent(r.Context(), sc, tid, aid, cid, nil, principalFrom(r.Context()).UserID); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

//go:embed consent.html
var consentHTML string

var consentPage = template.Must(template.New("consent").Parse(consentHTML))

// GET /agents/consent?client_id=agent-…: the consent screen. It signs the person in with Keycloak (authorization
// code with PKCE, the portal's public client), shows the agent and what it could do for them, and records the answer.
func (s *Server) consentPageHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := newInvitationToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cfg, _ := json.Marshal(map[string]string{"issuer": s.invites.Issuer, "client_id": s.invites.ClientID,
		"product": s.invites.Product})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
		"connect-src 'self' "+originOf(s.invites.Issuer)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_ = consentPage.Execute(w, map[string]any{"Config": template.JS(cfg), "Product": s.invites.Product, "Nonce": nonce})
}
