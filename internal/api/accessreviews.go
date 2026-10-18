package api

import (
	"net/http"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

// Access reviews (TS11, technical specification §18.4): owners and admins.

func (s *Server) listAccessReviews(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListAccessReviews(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) startAccessReview(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Name        string    `json:"name"`
		DueAt       time.Time `json:"due_at"`
		OnPending   string    `json:"on_pending"`
		Apps        []string  `json:"apps"`
		TenantRoles *bool     `json:"tenant_roles"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.StartAccessReview(r.Context(), sc, tid, store.NewAccessReview{Name: in.Name, DueAt: in.DueAt,
		OnPending: in.OnPending, Apps: in.Apps, NoRoles: in.TenantRoles != nil && !*in.TenantRoles})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getAccessReview(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.store.GetAccessReview(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /v1/tenants/{tid}/access-reviews/{id}: {id}:complete or {id}:cancel.
func (s *Server) accessReviewAction(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	raw, action := r.PathValue("id"), ""
	for _, a := range []string{":complete", ":cancel"} {
		if len(raw) > len(a) && raw[len(raw)-len(a):] == a {
			raw, action = raw[:len(raw)-len(a)], a
		}
	}
	r.SetPathValue("id", raw)
	id, ok := pathUUID(w, r, "id")
	if !ok || action == "" {
		if ok {
			problem(w, http.StatusNotFound, "not-found", "not found")
		}
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if action == ":cancel" {
		if err := s.store.CancelAccessReview(r.Context(), sc, tid, id); err != nil {
			s.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	me := principalFrom(r.Context()).UserID
	out, err := s.store.CompleteAccessReview(r.Context(), sc, tid, id, &me)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// PATCH /v1/tenants/{tid}/access-reviews/{id}/items/{item} {decision, note}.
func (s *Server) decideAccessReviewItem(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	item, ok := pathUUID(w, r, "item")
	if !ok {
		return
	}
	var in struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.DecideAccessReviewItem(r.Context(), sc, tid, id, item, principalFrom(r.Context()).UserID, in.Decision, in.Note)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
