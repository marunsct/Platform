package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Privacy (TS17, technical specification §14): tenant data export, a user's own export and erasure, audit
// retention and legal hold.

// UserDirectory deletes an erased user's account in the identity provider. Nil skips it (the account then only
// stops working in maturad). A Keycloak admin client is meant to implement it.
type UserDirectory interface {
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

// SetUserDirectory configures where erased users' sign-in accounts are deleted.
func (s *Server) SetUserDirectory(d UserDirectory) { s.directory = d }

// ownerAccess is tenantAccess for actions only owners and operators may take.
func (s *Server) ownerAccess(r *http.Request, tid uuid.UUID) (store.Scope, error) {
	sc, m, err := s.tenantAccess(r, tid, true)
	if err == nil && !sc.Operator && m.TenantRole != "owner" {
		err = errForbidden
	}
	return sc, err
}

// --- tenant export ------------------------------------------------------------------------------------------------

func (s *Server) createExport(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.CreateExport(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tenants/"+tid.String()+"/exports/"+out.ID.String())
	writeJSON(w, http.StatusAccepted, out)
}

func (s *Server) listExports(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListExports(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.store.GetExport(r.Context(), sc, tid, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// downloadExport serves a ready bundle while it lasts (store.ExportTTL); each download is audited.
func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request) {
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
	e, bundle, err := s.store.ExportBundle(r.Context(), sc, tid, id)
	if errors.Is(err, store.ErrExportExpired) {
		problem(w, http.StatusGone, "export-expired", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="tenant-`+tid.String()+`-export.json"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(bundle)))
	w.Header().Set("Cache-Control", "no-store")
	if e.SHA256 != nil {
		w.Header().Set("Matura-Export-SHA256", *e.SHA256)
	}
	_, _ = w.Write(bundle)
}

// --- the signed-in user's data ------------------------------------------------------------------------------------

func (s *Server) exportMe(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ExportUserData(r.Context(), principalFrom(r.Context()).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="matura-my-data.json"`)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// deleteMe erases the signed-in user's account (GDPR Art. 17), the same way an operator's DELETE does.
func (s *Server) deleteMe(w http.ResponseWriter, r *http.Request) {
	s.eraseUser(w, r, principalFrom(r.Context()).UserID)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	s.eraseUser(w, r, id)
}

// eraseUser runs the erasure with installation scope (it spans the user's tenants), then deletes the sign-in
// account through the UserDirectory when one is configured. A directory failure is logged and audited; the
// erasure in Matura stands and the account can no longer use maturad.
func (s *Server) eraseUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	sc := store.Scope{UserID: principalFrom(r.Context()).UserID, Operator: true}
	if err := s.store.DeleteUser(r.Context(), sc, id); err != nil {
		var lo *store.LastOwnerError
		if errors.As(err, &lo) {
			writeProblem(w, http.StatusConflict, "last-owner", err.Error(), map[string]any{"tenants": lo.Tenants})
			return
		}
		s.fail(w, r, err)
		return
	}
	s.seen.Delete(id)
	if s.directory != nil {
		if err := s.directory.DeleteUser(r.Context(), id); err != nil {
			s.log.ErrorContext(r.Context(), "deleting the user in the identity provider failed", "user", id, "err", err)
			_ = s.store.RecordAudit(r.Context(), sc, uuid.Nil, "user.directory_delete_failed", "users/"+id.String(),
				map[string]any{"error": err.Error()})
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- audit retention ----------------------------------------------------------------------------------------------

func (s *Server) getRetention(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.Retention(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(out.Version))
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putRetention(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		RetentionDays   int     `json:"retention_days"`
		LegalHold       bool    `json:"legal_hold"`
		LegalHoldReason *string `json:"legal_hold_reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	ver, err := ifMatch(r)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.RetentionDays == 0 {
		in.RetentionDays = store.DefaultRetentionDays
	}
	out, err := s.store.PutRetention(r.Context(), sc, tid, store.Retention{RetentionDays: in.RetentionDays,
		LegalHold: in.LegalHold, LegalHoldReason: in.LegalHoldReason}, ver)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(out.Version))
	writeJSON(w, http.StatusOK, out)
}
