package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	u, err := s.store.GetUser(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "operator": p.Operator})
}

// --- tenants ------------------------------------------------------------------------------------------------------

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	ts, err := s.store.ListTenants(r.Context(), store.Scope{UserID: p.UserID, Operator: p.Operator})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ts)})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Slug    string     `json:"slug"`
		Name    string     `json:"name"`
		Kind    string     `json:"kind"`
		Plan    string     `json:"plan"`
		OwnerID *uuid.UUID `json:"owner_id"` // operators only: create on someone's behalf
	}
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	owner := p.UserID
	if !p.Operator && (in.Plan != "" || in.OwnerID != nil || (in.Kind != "" && in.Kind != "company")) {
		s.fail(w, r, errForbidden)
		return
	}
	if in.OwnerID != nil {
		owner = *in.OwnerID
	}
	t, err := s.store.CreateTenant(r.Context(), store.Scope{UserID: p.UserID, Operator: p.Operator},
		store.NewTenant{Slug: in.Slug, Name: in.Name, Kind: in.Kind, Plan: in.Plan}, owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.store.GetTenant(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, tenantFor(sc, t))
}

func etag(v int64) string { return `"` + strconv.FormatInt(v, 10) + `"` }

func (s *Server) patchTenant(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Name          *string `json:"name"`
		Plan          *string `json:"plan"`
		Status        *string `json:"status"`
		Reason        string  `json:"reason"`
		SupportAccess *string `json:"support_access"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if (in.Plan != nil || in.Status != nil) && !sc.Operator ||
		in.SupportAccess != nil && !sc.Operator && m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	ver, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	var t store.Tenant
	if in.Name != nil || in.Plan != nil || in.SupportAccess != nil || in.Status == nil {
		t, err = s.store.UpdateTenant(r.Context(), sc, tid, store.TenantPatch{Name: in.Name, Plan: in.Plan,
			SupportAccess: in.SupportAccess}, ver)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		ver = 0
	}
	if in.Status != nil { // the same as :suspend and :resume
		act := map[string]string{"suspended": "suspend", "active": "resume"}[*in.Status]
		if act == "" {
			problem(w, http.StatusUnprocessableEntity, "invalid",
				"status can be set to active or suspended; delete a tenant with DELETE")
			return
		}
		t, err = s.store.ChangeTenantStatus(r.Context(), sc, tid, store.TenantAction{Do: act, Reason: in.Reason,
			IfVersion: ver})
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	w.Header().Set("ETag", etag(t.Version))
	writeJSON(w, http.StatusOK, tenantFor(sc, t))
}

// tenantFor hides the operator's status reason from everyone else.
func tenantFor(sc store.Scope, t store.Tenant) store.Tenant {
	if !sc.Operator {
		t.StatusReason = nil
	}
	return t
}

// deleteTenant starts the grace period (TN-3): the tenant is pending deletion and can be restored until
// purge_after, when the purger deletes it (TN-5). Owners and operators.
func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.Operator && m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	s.startDeletion(w, r, sc, tid)
}

// startDeletion reads the deletion options (operators: grace_days and reason) and marks the tenant pending deletion.
func (s *Server) startDeletion(w http.ResponseWriter, r *http.Request, sc store.Scope, tid uuid.UUID) {
	ver, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	q := r.URL.Query()
	grace := s.deleteGrace
	if g := q.Get("grace_days"); g != "" {
		days, err := strconv.Atoi(g)
		if err != nil || days < 0 || days > 365 {
			problem(w, http.StatusBadRequest, "bad-request", "grace_days must be a whole number from 0 to 365")
			return
		}
		if !sc.Operator {
			s.fail(w, r, errForbidden)
			return
		}
		grace = time.Duration(days) * 24 * time.Hour
	}
	reason := q.Get("reason")
	if reason != "" && !sc.Operator {
		reason = ""
	}
	t, err := s.store.ChangeTenantStatus(r.Context(), sc, tid, store.TenantAction{Do: "delete", Grace: grace,
		Reason: reason, IfVersion: ver})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, tenantFor(sc, t))
}

// tenantAction serves POST /v1/tenants/{tid}:restore (owners and operators).
func (s *Server) tenantAction(w http.ResponseWriter, r *http.Request) {
	raw, found := strings.CutSuffix(r.PathValue("tid"), ":restore")
	tid, err := uuid.Parse(raw)
	if !found || err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.Operator && m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	t, err := s.store.ChangeTenantStatus(r.Context(), sc, tid, store.TenantAction{Do: "restore"})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantFor(sc, t))
}

// --- workspaces ---------------------------------------------------------------------------------------------------

func (s *Server) listWorkspaces(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ws, err := s.store.ListWorkspaces(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ws)})
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ws, err := s.store.CreateWorkspace(r.Context(), sc, tid, in.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, ws)
}

func (s *Server) patchWorkspace(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	wid, ok := pathUUID(w, r, "wid")
	if !ok {
		return
	}
	var in struct {
		Name   *string `json:"name"`
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
	ws, err := s.store.UpdateWorkspace(r.Context(), sc, tid, wid, store.WorkspacePatch{Name: in.Name, Status: in.Status})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

// --- members ------------------------------------------------------------------------------------------------------

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ms, err := s.store.ListMembers(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ms)})
}

// addMember adds someone who already has an account. People without one are invited instead (TS6).
func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		UserID     *uuid.UUID `json:"user_id"`
		Email      string     `json:"email"`
		TenantRole string     `json:"tenant_role"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.TenantRole == "" {
		in.TenantRole = "member"
	}
	if in.TenantRole == "owner" && !sc.Operator && m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	var uid uuid.UUID
	switch {
	case in.UserID != nil:
		uid = *in.UserID
	case in.Email != "":
		u, err := s.store.FindUserByEmail(r.Context(), in.Email)
		if err != nil {
			problem(w, http.StatusUnprocessableEntity, "invalid",
				"no account uses this email yet; invite the person instead")
			return
		}
		uid = u.ID
	default:
		problem(w, http.StatusUnprocessableEntity, "invalid", "give user_id or email")
		return
	}
	out, err := s.store.AddMember(r.Context(), sc, tid, uid, in.TenantRole)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) patchMember(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var in struct {
		TenantRole *string `json:"tenant_role"`
		Status     *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.Operator && m.TenantRole != "owner" {
		// only owners make or unmake owners
		target, err := s.store.MembershipOf(r.Context(), tid, uid)
		if err == nil && target.TenantRole == "owner" || in.TenantRole != nil && *in.TenantRole == "owner" {
			s.fail(w, r, errForbidden)
			return
		}
	}
	out, err := s.store.UpdateMember(r.Context(), sc, tid, uid, store.MemberPatch{TenantRole: in.TenantRole, Status: in.Status})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	// anyone may leave a tenant; removing others needs owner or admin
	sc, m, err := s.tenantAccess(r, tid, uid != p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.Operator && m.TenantRole != "owner" && uid != p.UserID {
		if target, err := s.store.MembershipOf(r.Context(), tid, uid); err == nil && target.TenantRole == "owner" {
			s.fail(w, r, errForbidden)
			return
		}
	}
	if err := s.store.RemoveMember(r.Context(), sc, tid, uid); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- apps ---------------------------------------------------------------------------------------------------------

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(apps)})
}

func (s *Server) applyApp(w http.ResponseWriter, r *http.Request) {
	var m store.Manifest
	if !decode(w, r, &m) {
		return
	}
	if m.Slug == "" {
		m.Slug = r.PathValue("slug")
	}
	if m.Slug != r.PathValue("slug") {
		problem(w, http.StatusUnprocessableEntity, "invalid", "manifest slug and URL differ")
		return
	}
	p := principalFrom(r.Context())
	app, changed, err := s.store.ApplyApp(r.Context(), store.Scope{UserID: p.UserID, Operator: true}, m)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": app, "changed": changed})
}

func (s *Server) listTenantApps(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListTenantApps(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) enableApp(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.EnableApp(r.Context(), sc, tid, r.PathValue("app"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) disableApp(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DisableApp(r.Context(), sc, tid, r.PathValue("app")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- grants -------------------------------------------------------------------------------------------------------

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := store.GrantFilter{App: r.URL.Query().Get("app")}
	if u := r.URL.Query().Get("user_id"); u != "" {
		if f.UserID, err = uuid.Parse(u); err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "user_id must be a UUID")
			return
		}
	}
	out, err := s.store.ListGrants(r.Context(), sc, tid, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		App         string     `json:"app"`
		UserID      uuid.UUID  `json:"user_id"`
		Role        string     `json:"role"`
		WorkspaceID *uuid.UUID `json:"workspace_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.CreateGrant(r.Context(), sc, tid, store.NewGrant{App: in.App, UserID: in.UserID, Role: in.Role,
		WorkspaceID: in.WorkspaceID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.RevokeGrant(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- app roles (ADR 0008) ----------------------------------------------------------------------------------------

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListRoles(r.Context(), r.PathValue("slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func operatorScope(r *http.Request) store.Scope {
	return store.Scope{UserID: principalFrom(r.Context()).UserID, Operator: true}
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.CreateRole(r.Context(), operatorScope(r), r.PathValue("slug"),
		store.NewRole{Name: in.Name, Description: in.Description, Permissions: in.Permissions})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) patchRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Permissions *[]string `json:"permissions"`
		IsDefault   *bool     `json:"is_default"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.UpdateRole(r.Context(), operatorScope(r), r.PathValue("slug"), r.PathValue("name"),
		store.RolePatch{Name: in.Name, Description: in.Description, Permissions: in.Permissions, IsDefault: in.IsDefault})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRole(r.Context(), operatorScope(r), r.PathValue("slug"), r.PathValue("name")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
