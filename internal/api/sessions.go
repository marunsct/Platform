package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// Sessions and second factors (TS12) live in Keycloak; maturad reads and changes them through the admin API.

// SetKeycloak gives the server Keycloak's admin API and the realm's public issuer URL.
func (s *Server) SetKeycloak(c *keycloak.Client, issuer string) {
	s.kc, s.issuer = c, strings.TrimRight(issuer, "/")
}

// needKeycloak answers 503 when no admin client is configured.
func (s *Server) needKeycloak(w http.ResponseWriter) bool {
	if s.kc == nil {
		problem(w, http.StatusServiceUnavailable, "keycloak-not-configured",
			"this installation has not configured Keycloak's admin API (MATURA_KEYCLOAK_CLIENT_SECRET)")
		return false
	}
	return true
}

// kcFail turns a Keycloak error into a problem.
func (s *Server) kcFail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, keycloak.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "not found")
	case errors.Is(err, keycloak.ErrUnavailable):
		s.log.WarnContext(r.Context(), "keycloak unavailable", "err", err)
		problem(w, http.StatusServiceUnavailable, "keycloak-unavailable", "the identity service is not answering; try again")
	default:
		var kerr *keycloak.Error
		if errors.As(err, &kerr) {
			s.log.ErrorContext(r.Context(), "keycloak refused", "err", err)
			problem(w, http.StatusBadGateway, "keycloak-error", "the identity service refused: "+kerr.Body)
			return
		}
		s.fail(w, r, err)
	}
}

type sessionOut struct {
	ID           string    `json:"id"`
	IPAddress    string    `json:"ip_address"`
	StartedAt    time.Time `json:"started_at"`
	LastAccessAt time.Time `json:"last_access_at"`
	RememberMe   bool      `json:"remember_me"`
	Clients      []string  `json:"clients"`
	Current      bool      `json:"current"`
}

func (s *Server) sessionsOf(ctx context.Context, userID uuid.UUID, current string) ([]sessionOut, error) {
	list, err := s.kc.UserSessions(ctx, userID.String())
	if err != nil {
		return nil, err
	}
	out := make([]sessionOut, 0, len(list))
	for _, x := range list {
		out = append(out, sessionOut{ID: x.ID, IPAddress: x.IPAddress, StartedAt: x.Started, LastAccessAt: x.LastAccess,
			RememberMe: x.RememberMe, Clients: x.Clients, Current: current != "" && x.ID == current})
	}
	return out, nil
}

func (s *Server) mySessions(w http.ResponseWriter, r *http.Request) {
	if !s.needKeycloak(w) {
		return
	}
	p := principalFrom(r.Context())
	out, err := s.sessionsOf(r.Context(), p.UserID, p.SessionID)
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// audit records an action taken in Keycloak in the tenant's audit log (uuid.Nil: the installation's).
func (s *Server) auditKeycloak(r *http.Request, tid uuid.UUID, action, target string, data any) {
	p := principalFrom(r.Context())
	ctx := context.WithoutCancel(r.Context())
	if err := s.store.RecordAudit(ctx, store.Scope{UserID: p.UserID, Operator: p.Operator}, tid, action, target,
		data); err != nil {
		s.log.ErrorContext(ctx, "recording an identity action", "action", action, "err", err)
	}
}

func (s *Server) deleteMySession(w http.ResponseWriter, r *http.Request) {
	if !s.needKeycloak(w) {
		return
	}
	p := principalFrom(r.Context())
	id := r.PathValue("id")
	list, err := s.kc.UserSessions(r.Context(), p.UserID.String())
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	found := false
	for _, x := range list {
		found = found || x.ID == id
	}
	if !found { // someone else's session is reported like a missing one
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	if err := s.kc.DeleteSession(r.Context(), id); err != nil {
		s.kcFail(w, r, err)
		return
	}
	s.auditKeycloak(r, uuid.Nil, "session.revoked", "users/"+p.UserID.String()+"/sessions/"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// signOutEverywhere ends every session of the caller; ?keep_current=true keeps the one the request's token is from.
func (s *Server) signOutEverywhere(w http.ResponseWriter, r *http.Request) {
	if !s.needKeycloak(w) {
		return
	}
	p := principalFrom(r.Context())
	keep := r.URL.Query().Get("keep_current") == "true"
	if keep && p.SessionID == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid", "this token names no session (sid) to keep")
		return
	}
	n := 0
	if keep {
		list, err := s.kc.UserSessions(r.Context(), p.UserID.String())
		if err != nil {
			s.kcFail(w, r, err)
			return
		}
		for _, x := range list {
			if x.ID == p.SessionID {
				continue
			}
			if err := s.kc.DeleteSession(r.Context(), x.ID); err != nil && !errors.Is(err, keycloak.ErrNotFound) {
				s.kcFail(w, r, err)
				return
			}
			n++
		}
	} else if err := s.kc.LogoutUser(r.Context(), p.UserID.String()); err != nil {
		s.kcFail(w, r, err)
		return
	}
	s.auditKeycloak(r, uuid.Nil, "session.revoked_all", "users/"+p.UserID.String()+"/sessions",
		map[string]any{"kept_current": keep})
	w.WriteHeader(http.StatusNoContent)
}

type factorOut struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// myMFA lists the caller's second factors and whether a tenant of theirs requires one.
func (s *Server) myMFA(w http.ResponseWriter, r *http.Request) {
	if !s.needKeycloak(w) {
		return
	}
	p := principalFrom(r.Context())
	creds, err := s.kc.Credentials(r.Context(), p.UserID.String())
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	factors := []factorOut{}
	for _, c := range creds {
		if keycloak.IsSecondFactor(c.Type) {
			factors = append(factors, factorOut{ID: c.ID, Type: c.Type, Label: c.Label, CreatedAt: c.Created})
		}
	}
	tenants, err := s.store.TenantsRequiringMFA(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"factors": factors, "configured": len(factors) > 0,
		"required": len(tenants) > 0, "required_by": tenants})
}

var errNotGoverned = errors.New("this person also belongs to other organisations and their email domain is not " +
	"verified by yours, so only they (or the installation's operators) can change their sign-in")

// governedMember checks a tenant owner or admin may act on a member's Keycloak account: the target is a member,
// admins do not act on owners, and the tenant governs the person (store.GovernsUser). Operators (with approved support access) skip the governance rule.
func (s *Server) governedMember(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, store.Scope, bool) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return tid, uuid.Nil, store.Scope{}, false
	}
	raw := r.PathValue("uid")
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		raw = raw[:i]
	}
	uid, err := uuid.Parse(raw)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return tid, uid, store.Scope{}, false
	}
	sc, me, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return tid, uid, sc, false
	}
	if !s.needKeycloak(w) {
		return tid, uid, sc, false
	}
	target, err := s.store.MembershipOf(r.Context(), tid, uid)
	if err != nil {
		s.fail(w, r, err)
		return tid, uid, sc, false
	}
	if me.TenantRole == "admin" && target.TenantRole == "owner" {
		s.fail(w, r, errForbidden)
		return tid, uid, sc, false
	}
	if !sc.Operator {
		governs, err := s.store.GovernsUser(r.Context(), tid, uid)
		if err != nil {
			s.fail(w, r, err)
			return tid, uid, sc, false
		}
		if !governs {
			problem(w, http.StatusForbidden, "not-governed", errNotGoverned.Error())
			return tid, uid, sc, false
		}
	}
	return tid, uid, sc, true
}

func (s *Server) memberSessions(w http.ResponseWriter, r *http.Request) {
	_, uid, _, ok := s.governedMember(w, r)
	if !ok {
		return
	}
	out, err := s.sessionsOf(r.Context(), uid, "")
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// memberAction serves POST …/members/{uid}:sign-out and …/members/{uid}:reset-mfa.
func (s *Server) memberAction(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("uid")
	var action string
	switch {
	case strings.HasSuffix(raw, ":sign-out"):
		action = "sign-out"
	case strings.HasSuffix(raw, ":reset-mfa"):
		action = "reset-mfa"
	default:
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	tid, uid, _, ok := s.governedMember(w, r)
	if !ok {
		return
	}
	target := "tenants/" + tid.String() + "/members/" + uid.String()
	switch action {
	case "sign-out":
		if err := s.kc.LogoutUser(r.Context(), uid.String()); err != nil {
			s.kcFail(w, r, err)
			return
		}
		s.auditKeycloak(r, tid, "member.signed_out", target, nil)
		w.WriteHeader(http.StatusNoContent)
	case "reset-mfa":
		if uid == principalFrom(r.Context()).UserID {
			problem(w, http.StatusUnprocessableEntity, "invalid",
				"change your own second factors on your account page, not through your organisation")
			return
		}
		n, err := s.kc.ResetSecondFactors(r.Context(), uid.String())
		if err != nil {
			s.kcFail(w, r, err)
			return
		}
		s.auditKeycloak(r, tid, "member.mfa_reset", target, map[string]any{"removed": n})
		writeJSON(w, http.StatusOK, map[string]any{"removed": n})
	}
}
