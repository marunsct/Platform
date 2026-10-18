package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// SCIM setup in a tenant (TS14): owners manage the bearer tokens their identity provider uses; owners and admins
// map SCIM group names to app roles.

func (s *Server) listSCIMTokens(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.store.ListSCIMTokens(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "scim_base_url": s.scimBase(r, tid)})
}

// createSCIMToken makes a token and shows it once; only its SHA-256 is kept. Rotation: create a new token, put it
// in the identity provider, then revoke the old one.
func (s *Server) createSCIMToken(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		s.fail(w, r, err)
		return
	}
	token := "scim_" + base64.RawURLEncoding.EncodeToString(b)
	t, err := s.store.CreateSCIMToken(r.Context(), sc, tid, in.Name, hashSCIMToken(token), token[:12], in.ExpiresAt)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"id": t.ID, "tenant_id": t.TenantID, "name": t.Name,
		"prefix": t.Prefix, "created_by": t.CreatedBy, "created_at": t.CreatedAt, "expires_at": t.ExpiresAt,
		"last_used_at": t.LastUsedAt, "token": token, "scim_base_url": s.scimBase(r, tid)})
}

func (s *Server) revokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.RevokeSCIMToken(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSCIMGroupMappings(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.store.ListSCIMGroupMappings(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (s *Server) createSCIMGroupMapping(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Group string `json:"group"`
		App   string `json:"app"`
		Role  string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.store.CreateSCIMGroupMapping(r.Context(), sc, tid, in.Group, in.App, in.Role)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) deleteSCIMGroupMapping(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.DeleteSCIMGroupMapping(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
