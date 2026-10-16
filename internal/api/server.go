// Package api is maturad's HTTP API (technical specification §5).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

type Server struct {
	store *store.Store
	auth  Authenticator
	log   *slog.Logger
	seen  sync.Map // user id -> seenProfile, so unchanged profiles skip the database
}

// seenProfile remembers a profile already written; it is re-checked after a minute so a deactivated account stops
// working without waiting for its profile to change.
type seenProfile struct {
	profile store.UserProfile
	at      time.Time
}

func New(st *store.Store, auth Authenticator, log *slog.Logger) *Server {
	return &Server{store: st, auth: auth, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz/live", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /healthz/ready", s.ready)

	api := http.NewServeMux()
	api.HandleFunc("GET /v1/me", s.getMe)
	api.HandleFunc("GET /v1/tenants", s.listTenants)
	api.HandleFunc("POST /v1/tenants", s.createTenant)
	api.HandleFunc("GET /v1/tenants/{tid}", s.getTenant)
	api.HandleFunc("PATCH /v1/tenants/{tid}", s.patchTenant)
	api.HandleFunc("DELETE /v1/tenants/{tid}", s.deleteTenant)
	api.HandleFunc("GET /v1/tenants/{tid}/workspaces", s.listWorkspaces)
	api.HandleFunc("POST /v1/tenants/{tid}/workspaces", s.createWorkspace)
	api.HandleFunc("PATCH /v1/tenants/{tid}/workspaces/{wid}", s.patchWorkspace)
	api.HandleFunc("GET /v1/tenants/{tid}/members", s.listMembers)
	api.HandleFunc("POST /v1/tenants/{tid}/members", s.addMember)
	api.HandleFunc("PATCH /v1/tenants/{tid}/members/{uid}", s.patchMember)
	api.HandleFunc("DELETE /v1/tenants/{tid}/members/{uid}", s.removeMember)
	api.HandleFunc("GET /v1/tenants/{tid}/apps", s.listTenantApps)
	api.HandleFunc("PUT /v1/tenants/{tid}/apps/{app}", s.enableApp)
	api.HandleFunc("DELETE /v1/tenants/{tid}/apps/{app}", s.disableApp)
	api.HandleFunc("GET /v1/tenants/{tid}/grants", s.listGrants)
	api.HandleFunc("POST /v1/tenants/{tid}/grants", s.createGrant)
	api.HandleFunc("DELETE /v1/tenants/{tid}/grants/{id}", s.revokeGrant)
	api.HandleFunc("GET /v1/apps", s.listApps)
	api.HandleFunc("PUT /admin/v1/apps/{slug}", s.applyApp)
	api.HandleFunc("GET /v1/apps/{slug}/roles", s.listRoles)
	api.HandleFunc("POST /admin/v1/apps/{slug}/roles", s.createRole)
	api.HandleFunc("PATCH /admin/v1/apps/{slug}/roles/{name}", s.patchRole)
	api.HandleFunc("DELETE /admin/v1/apps/{slug}/roles/{name}", s.deleteRole)

	authed := s.authenticate(api)
	mux.Handle("/v1/", authed)
	mux.Handle("/admin/v1/", authed)
	return mux
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		problem(w, http.StatusServiceUnavailable, "not-ready", "database unreachable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authenticate verifies the caller and records their profile (first sight, or when the token shows a change).
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.auth.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="matura"`)
			problem(w, http.StatusUnauthorized, "unauthenticated", err.Error())
			return
		}
		profile := store.UserProfile{ID: p.UserID, Email: p.Email, EmailVerified: p.EmailVerified,
			DisplayName: p.Name, Locale: p.Locale}
		if last, ok := s.seen.Load(p.UserID); !ok || last.(seenProfile).profile != profile ||
			time.Since(last.(seenProfile).at) > time.Minute {
			u, err := s.store.UpsertUser(r.Context(), profile)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if u.Status != "active" {
				problem(w, http.StatusForbidden, "user-inactive", "this account is deactivated")
				return
			}
			s.seen.Store(p.UserID, seenProfile{profile: profile, at: time.Now()})
		}
		if strings.HasPrefix(r.URL.Path, "/admin/") && !p.Operator {
			problem(w, http.StatusForbidden, "operator-only", "this endpoint is for installation operators")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// --- helpers ------------------------------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://matura.dev/problems/" + typ,
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var inv *store.InvalidError
	switch {
	case errors.As(err, &inv):
		problem(w, http.StatusUnprocessableEntity, "invalid", inv.Msg)
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "not found")
	case errors.Is(err, store.ErrConflict):
		problem(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrVersion):
		problem(w, http.StatusPreconditionFailed, "version-mismatch", "changed since you read it; reload and retry")
	case errors.Is(err, errForbidden):
		problem(w, http.StatusForbidden, "forbidden", err.Error())
	default:
		s.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		problem(w, http.StatusInternalServerError, "internal", "something went wrong")
	}
}

var errForbidden = errors.New("you do not have permission to do this")

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		// an id that cannot exist is reported like one that does not: no hint either way
		problem(w, http.StatusNotFound, "not-found", "not found")
		return uuid.Nil, false
	}
	return id, true
}

func ifMatch(r *http.Request) (int64, error) {
	h := strings.Trim(strings.TrimPrefix(r.Header.Get("If-Match"), "W/"), `"`)
	if h == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(h, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("If-Match must be the resource's version")
	}
	return v, nil
}

// tenantAccess returns the scope for acting in a tenant. Members may read; owners and admins may manage.
// Non-members get ErrNotFound so tenant ids cannot be probed. Operators may do everything.
func (s *Server) tenantAccess(r *http.Request, tid uuid.UUID, manage bool) (store.Scope, store.Membership, error) {
	p := principalFrom(r.Context())
	sc := store.Scope{UserID: p.UserID, Operator: p.Operator}.InTenant(tid)
	if p.Operator {
		return sc, store.Membership{TenantRole: "operator"}, nil
	}
	m, err := s.store.MembershipOf(r.Context(), tid, p.UserID)
	if err != nil {
		return sc, m, err
	}
	if manage && m.TenantRole != "owner" && m.TenantRole != "admin" {
		return sc, m, errForbidden
	}
	return sc, m, nil
}
