package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Operator console (TS10): tenant lifecycle and listing, plans per tenant, entitlements and support access.

// adminListTenants pages through every tenant: ?q= matches slug or name, ?status= takes one or more statuses
// (comma-separated; default every status but deleted), ?cursor= continues from next_cursor.
func (s *Server) adminListTenants(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tq := store.TenantQuery{Q: q.Get("q"), Cursor: q.Get("cursor")}
	if st := q.Get("status"); st != "" {
		tq.Statuses = strings.Split(st, ",")
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "limit must be a number")
			return
		}
		tq.Limit = n
	}
	items, next, err := s.store.ListTenantsAdmin(r.Context(), operatorScope(r), tq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"items": nonNil(items)}
	if next != "" {
		out["next_cursor"] = next
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.Stats(r.Context(), operatorScope(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// adminTenantAction serves POST /admin/v1/tenants/{tid}:suspend {reason}, :resume and :restore.
func (s *Server) adminTenantAction(w http.ResponseWriter, r *http.Request) {
	raw, action, _ := strings.Cut(r.PathValue("tid"), ":")
	tid, err := uuid.Parse(raw)
	if err != nil || (action != "suspend" && action != "resume" && action != "restore") {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !decodeOptional(w, r, &in) {
		return
	}
	ver, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	t, err := s.store.ChangeTenantStatus(r.Context(), operatorScope(r), tid,
		store.TenantAction{Do: action, Reason: in.Reason, IfVersion: ver})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, t)
}

// adminDeleteTenant is DELETE /v1/tenants/{tid} for operators: ?grace_days= and ?reason= are optional.
func (s *Server) adminDeleteTenant(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	s.startDeletion(w, r, operatorScope(r).InTenant(tid), tid)
}

// decodeOptional is decode for bodies that may be empty.
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "could not read the body")
		return false
	}
	if strings.TrimSpace(string(body)) == "" {
		return true
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// --- entitlements -------------------------------------------------------------------------------------------------

func (s *Server) getEntitlements(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.TenantEntitlements(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// putTenantPlan sets a tenant's plan ("" or null: none) and, when given, replaces its overrides.
func (s *Server) putTenantPlan(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Plan      *string         `json:"plan"`
		Overrides json.RawMessage `json:"overrides"`
	}
	if !decode(w, r, &in) {
		return
	}
	plan := ""
	if in.Plan != nil {
		plan = *in.Plan
	}
	out, err := s.store.SetTenantPlan(r.Context(), operatorScope(r), tid, plan, in.Overrides)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- support access -----------------------------------------------------------------------------------------------

func (s *Server) requestSupportAccess(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Reason          string `json:"reason"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	out, err := s.store.RequestSupportAccess(r.Context(), operatorScope(r), tid, p.UserID, in.Reason, in.DurationMinutes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) adminListSupportAccess(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	out, err := s.store.ListSupportAccess(r.Context(), operatorScope(r), tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

// endSupportAccess serves POST /admin/v1/tenants/{tid}/support-access/{id}:end, for the operator who asked.
func (s *Server) endSupportAccess(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	raw, found := strings.CutSuffix(r.PathValue("id"), ":end")
	id, err := uuid.Parse(raw)
	if !found || err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	p := principalFrom(r.Context())
	out, err := s.store.EndSupportAccess(r.Context(), operatorScope(r), tid, id, p.UserID, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// listSupportAccess shows a tenant's owners and admins every support access request, decision and use.
func (s *Server) listSupportAccess(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListSupportAccess(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

// supportAccessDecision serves POST /v1/tenants/{tid}/support-access/{id}:approve, :deny and :revoke (owners).
func (s *Server) supportAccessDecision(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	raw, action, _ := strings.Cut(r.PathValue("id"), ":")
	id, err := uuid.Parse(raw)
	if err != nil || (action != "approve" && action != "deny" && action != "revoke") {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	p := principalFrom(r.Context())
	var out store.SupportAccess
	if action == "revoke" {
		out, err = s.store.EndSupportAccess(r.Context(), sc, tid, id, p.UserID, true)
	} else {
		out, err = s.store.DecideSupportAccess(r.Context(), sc, tid, id, p.UserID, action == "approve")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
