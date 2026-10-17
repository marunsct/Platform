package api

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Data placement (technical specification §7): tenants read where their data lives; app backends register their own
// storage, confirm migrations (:ready) and deletion (:deleted), and fetch credentials for platform-managed storage.

func (s *Server) listPlacements(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListPlacements(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

// appTenant returns the calling app and the tenant a placement path names ("{tid}" or "{tid}:<action>").
func appTenant(w http.ResponseWriter, r *http.Request) (store.App, uuid.UUID, string, bool) {
	app, ok := ownApp(w, r)
	if !ok {
		return app, uuid.Nil, "", false
	}
	raw, action, _ := strings.Cut(r.PathValue("tid"), ":")
	tid, err := uuid.Parse(raw)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return app, uuid.Nil, "", false
	}
	return app, tid, action, true
}

func (s *Server) appGetPlacement(w http.ResponseWriter, r *http.Request) {
	app, tid, action, ok := appTenant(w, r)
	if !ok {
		return
	}
	if action != "" {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	p, err := s.store.AppPlacement(r.Context(), app, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// appPutPlacement registers storage the app created itself (manager: app).
func (s *Server) appPutPlacement(w http.ResponseWriter, r *http.Request) {
	app, tid, action, ok := appTenant(w, r)
	if !ok {
		return
	}
	if action != "" {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	var in store.AppStorage
	if !decode(w, r, &in) {
		return
	}
	p, err := s.store.RegisterPlacement(r.Context(), app, tid, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// appPlacementAction handles POST {tid}:ready and {tid}:deleted.
func (s *Server) appPlacementAction(w http.ResponseWriter, r *http.Request) {
	app, tid, action, ok := appTenant(w, r)
	if !ok {
		return
	}
	var p store.Placement
	var err error
	switch action {
	case "ready":
		p, err = s.store.PlacementReady(r.Context(), app, tid)
	case "deleted":
		p, err = s.store.PlacementDataDeleted(r.Context(), app, tid)
	default:
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// appPlacementCredentials returns the connection for a platform-managed placement. {"purpose": "migrate"} returns the
// role that owns the tables (in shared mode a different role from the runtime one).
func (s *Server) appPlacementCredentials(w http.ResponseWriter, r *http.Request) {
	app, tid, action, ok := appTenant(w, r)
	if !ok {
		return
	}
	if action != "" {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	var in struct {
		Purpose string `json:"purpose"`
	}
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	if in.Purpose != "" && in.Purpose != "runtime" && in.Purpose != "migrate" {
		problem(w, http.StatusUnprocessableEntity, "invalid", "purpose is runtime (default) or migrate")
		return
	}
	c, err := s.store.PlacementCredentials(r.Context(), s.keys, app, tid, in.Purpose == "migrate")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, c)
}
