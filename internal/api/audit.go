package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Audit log (TS9, technical specification §13): tenant owners and admins read, export and verify their tenant's
// chain; operators read every chain.

// auditQuery reads ?actor, ?action (prefix), ?from, ?to (RFC 3339), ?cursor and ?limit.
func auditQuery(w http.ResponseWriter, r *http.Request) (store.AuditQuery, bool) {
	q := r.URL.Query()
	out := store.AuditQuery{Actor: q.Get("actor"), Action: q.Get("action")}
	out.Limit, _ = strconv.Atoi(q.Get("limit"))
	for name, dst := range map[string]**time.Time{"from": &out.From, "to": &out.To} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				problem(w, http.StatusBadRequest, "bad-request", name+" must be an RFC 3339 time")
				return out, false
			}
			*dst = &t
		}
	}
	if v := q.Get("cursor"); v != "" {
		c, err := strconv.ParseInt(v, 10, 64)
		if err != nil || c <= 0 {
			problem(w, http.StatusBadRequest, "bad-request", "cursor is not one this list returned")
			return out, false
		}
		out.Before = c
	}
	return out, true
}

func (s *Server) writeAuditPage(w http.ResponseWriter, r *http.Request, sc store.Scope, q store.AuditQuery) {
	items, err := s.store.ListAudit(r.Context(), sc, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"items": nonNil(items), "next_cursor": nil}
	if len(items) == store.AuditLimit(q.Limit) {
		out["next_cursor"] = strconv.FormatInt(items[len(items)-1].ID, 10)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	q, ok := auditQuery(w, r)
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q.Tenant = &tid
	s.writeAuditPage(w, r, sc, q)
}

// exportAudit streams the tenant's chain oldest first as NDJSON, one event per line with its hashes, so the
// receiver can check the chain itself. ?from and ?to narrow it by time.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	q, ok := auditQuery(w, r)
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.RecordAudit(r.Context(), sc, tid, "audit.exported", "tenants/"+tid.String()+"/audit",
		map[string]any{"from": q.From, "to": q.To}); err != nil {
		s.fail(w, r, err)
		return
	}
	s.streamChain(w, r, sc, tid, q)
}

func (s *Server) streamChain(w http.ResponseWriter, r *http.Request, sc store.Scope, tid uuid.UUID, q store.AuditQuery) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.ndjson"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	rc := http.NewResponseController(w)
	var after int64
	for {
		page, err := s.store.AuditChain(r.Context(), sc, tid, after, 1000, q.From, q.To)
		if err != nil {
			// the status line has gone; a cut-off stream is how the client learns
			s.log.ErrorContext(r.Context(), "audit export failed", "err", err)
			return
		}
		for _, e := range page {
			if err := enc.Encode(e); err != nil {
				return
			}
			after = e.Seq
		}
		if flusher != nil {
			flusher.Flush()
		}
		if len(page) < 1000 {
			return
		}
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.VerifyAudit(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// adminTenant reads ?tenant: a tenant id, "installation" for events with no tenant, or nothing for every event.
func adminTenant(w http.ResponseWriter, r *http.Request, q *store.AuditQuery) bool {
	switch v := r.URL.Query().Get("tenant"); v {
	case "":
	case "installation":
		q.Installation = true
	default:
		id, err := uuid.Parse(v)
		if err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "tenant must be a tenant id or installation")
			return false
		}
		q.Tenant = &id
	}
	return true
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	q, ok := auditQuery(w, r)
	if !ok || !adminTenant(w, r, &q) {
		return
	}
	s.writeAuditPage(w, r, operatorScope(r), q)
}

// adminVerifyAudit verifies one chain: ?tenant=<id>, or the installation chain without it.
func (s *Server) adminVerifyAudit(w http.ResponseWriter, r *http.Request) {
	var q store.AuditQuery
	if !adminTenant(w, r, &q) {
		return
	}
	tid := uuid.Nil
	if q.Tenant != nil {
		tid = *q.Tenant
	}
	out, err := s.store.VerifyAudit(r.Context(), operatorScope(r), tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- streaming destinations ---------------------------------------------------------------------------------------

func (s *Server) listAuditSinks(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListAuditSinks(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) createAuditSink(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Kind     string `json:"kind"`
		URL      string `json:"url"`
		Backfill bool   `json:"backfill"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Kind != "" && in.Kind != "webhook" {
		problem(w, http.StatusUnprocessableEntity, "invalid", "kind must be webhook")
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.CreateAuditSink(r.Context(), sc, s.keys, tid, in.URL, in.Backfill)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) patchAuditSink(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		URL    *string `json:"url"`
		Status *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.UpdateAuditSink(r.Context(), sc, tid, id, store.WebhookPatch{URL: in.URL, Status: in.Status})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteAuditSink(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.DeleteAuditSink(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
