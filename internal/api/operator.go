package api

import (
	"encoding/json"
	"net/http"

	"github.com/marunsct/Platform/internal/store"
)

// Operator endpoints for plans and database servers (technical specification §5). /admin/ is operator-only.

func (s *Server) listPlans(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListPlans(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) putPlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name             string          `json:"name"`
		DataModeRequired *string         `json:"data_mode_required"`
		DataModeDefault  string          `json:"data_mode_default"`
		Limits           json.RawMessage `json:"limits"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.PutPlan(r.Context(), operatorScope(r), store.Plan{ID: r.PathValue("id"), Name: in.Name,
		DataModeRequired: in.DataModeRequired, DataModeDefault: in.DataModeDefault, Limits: in.Limits})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listDBServers(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListDBServers(r.Context(), operatorScope(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) createDBServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string          `json:"name"`
		Host          string          `json:"host"`
		Port          int             `json:"port"`
		AdminUser     string          `json:"admin_user"`
		AdminPassword string          `json:"admin_password"`
		SSLMode       string          `json:"sslmode"`
		Region        string          `json:"region"`
		Dedicated     bool            `json:"dedicated"`
		Labels        json.RawMessage `json:"labels"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.CreateDBServer(r.Context(), operatorScope(r), s.keys, store.NewDBServer{Name: in.Name,
		Host: in.Host, Port: in.Port, AdminUser: in.AdminUser, AdminPassword: in.AdminPassword, SSLMode: in.SSLMode,
		Region: in.Region, Dedicated: in.Dedicated, Labels: in.Labels})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) patchDBServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Status        *string         `json:"status"`
		Region        *string         `json:"region"`
		Dedicated     *bool           `json:"dedicated"`
		Labels        json.RawMessage `json:"labels"`
		AdminPassword *string         `json:"admin_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.UpdateDBServer(r.Context(), operatorScope(r), s.keys, id, store.DBServerPatch{
		Status: in.Status, Region: in.Region, Dedicated: in.Dedicated, Labels: in.Labels, AdminPassword: in.AdminPassword})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteDBServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteDBServer(r.Context(), operatorScope(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testDBServer connects with the stored admin credentials and reports whether provisioning can use the server.
func (s *Server) testDBServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := s.store.CheckDBServer(r.Context(), operatorScope(r), s.keys, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
