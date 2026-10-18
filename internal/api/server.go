// Package api is maturad's HTTP API (technical specification §5).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/portal"
	"github.com/marunsct/Platform/internal/readiness"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

type Server struct {
	store *store.Store
	auth  Authenticator
	keys  secrets.KeyManager
	log   *slog.Logger
	seen  sync.Map // user id -> seenProfile, so unchanged profiles skip the database

	source         string      // CloudEvents source of this installation
	internalRoutes []route     // /internal/v1 routes for Keycloak (TS5)
	routes         []string    // patterns registered by the last Handler call, for Routes
	invites        Invitations // invitation links and accept page (TS6)
	deleteGrace    time.Duration
	trustedProxies []netip.Prefix
	policies       sync.Map         // tenant id -> cachedPolicy, for the IP allow-list
	kc             *keycloak.Client // admin API of the realm (TS12, TS13); nil: those endpoints answer 503
	issuer         string           // public realm URL, for the SSO details shown to tenant admins
	resolver       TXTResolver      // DNS for domain verification
	portal         *portal.Portal
	directory      UserDirectory     // identity provider accounts of erased users (TS17); nil skips
	install        readiness.Install // this installation's configuration, for readiness (TS24)
	trust          trustCache        // rendered trust page (TS25)
}

// seenProfile remembers a profile already written; it is re-checked after a minute so a deactivated account stops
// working without waiting for its profile to change.
type seenProfile struct {
	profile store.UserProfile
	at      time.Time
}

func New(st *store.Store, auth Authenticator, keys secrets.KeyManager, log *slog.Logger) *Server {
	return &Server{store: st, auth: auth, keys: keys, log: log, source: "matura://installation/main",
		deleteGrace: 30 * 24 * time.Hour, install: readiness.Install{Product: "Matura"}}
}

// SetDeletionGrace sets how long a deleted tenant can be restored before the purger deletes it (default 30 days).
func (s *Server) SetDeletionGrace(d time.Duration) {
	if d >= 0 {
		s.deleteGrace = d
	}
}

// SetSource sets the CloudEvents source this installation puts on events.
func (s *Server) SetSource(src string) {
	if src != "" {
		s.source = src
	}
}

// SetPortal configures the customer portal served at /portal/ (TS8).
func (s *Server) SetPortal(c portal.Config) {
	s.portal = portal.New(c)
}

func (s *Server) Handler() http.Handler {
	s.routes = nil
	if s.portal == nil {
		s.portal = portal.New(portal.Config{})
	}
	mux := http.NewServeMux()
	s.handle(mux, "GET /healthz/live", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.handle(mux, "GET /healthz/ready", s.ready)
	s.handle(mux, "GET /invitations/accept", s.acceptPageHandler)
	s.handle(mux, "GET /invitations/preview", s.previewInvitation)
	s.handle(mux, "GET /v1/sso/discover", s.discoverSSO) // public: home-realm discovery for sign-in pages
	s.handle(mux, "GET /portal/config.json", s.portal.ConfigJSON)
	s.handle(mux, "GET /portal/", s.portal.Files)
	s.handle(mux, "GET /trust", s.trustPage(false))
	s.handle(mux, "GET /trust.json", s.trustPage(true))
	// SCIM 2.0 per tenant, authenticated with the tenant's SCIM tokens (TS14)
	s.handle(mux, "GET /scim/v2/tenants/{tid}/ServiceProviderConfig", s.scim(s.scimServiceProviderConfig))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/ResourceTypes", s.scim(s.scimResourceTypes))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/Schemas", s.scim(s.scimSchemas))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/Users", s.scim(s.scimListUsers))
	s.handle(mux, "POST /scim/v2/tenants/{tid}/Users", s.scim(s.scimCreateUser))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/Users/{id}", s.scim(s.scimGetUser))
	s.handle(mux, "PUT /scim/v2/tenants/{tid}/Users/{id}", s.scim(s.scimReplaceUser))
	s.handle(mux, "PATCH /scim/v2/tenants/{tid}/Users/{id}", s.scim(s.scimPatchUser))
	s.handle(mux, "DELETE /scim/v2/tenants/{tid}/Users/{id}", s.scim(s.scimDeleteUser))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/Groups", s.scim(s.scimListGroups))
	s.handle(mux, "POST /scim/v2/tenants/{tid}/Groups", s.scim(s.scimCreateGroup))
	s.handle(mux, "GET /scim/v2/tenants/{tid}/Groups/{id}", s.scim(s.scimGetGroup))
	s.handle(mux, "PUT /scim/v2/tenants/{tid}/Groups/{id}", s.scim(s.scimReplaceGroup))
	s.handle(mux, "PATCH /scim/v2/tenants/{tid}/Groups/{id}", s.scim(s.scimPatchGroup))
	s.handle(mux, "DELETE /scim/v2/tenants/{tid}/Groups/{id}", s.scim(s.scimDeleteGroup))

	api := http.NewServeMux()
	s.handle(api, "GET /v1/me", s.getMe)
	s.handle(api, "GET /v1/tenants", s.listTenants)
	s.handle(api, "POST /v1/tenants", s.createTenant)
	s.handle(api, "GET /v1/tenants/{tid}", s.getTenant)
	s.handle(api, "PATCH /v1/tenants/{tid}", s.patchTenant)
	s.handle(api, "DELETE /v1/tenants/{tid}", s.deleteTenant)
	s.handle(api, "POST /v1/tenants/{tid}", s.tenantAction) // {tid}:restore
	s.handle(api, "GET /v1/tenants/{tid}/entitlements", s.getEntitlements)
	s.handle(api, "GET /v1/tenants/{tid}/support-access", s.listSupportAccess)
	s.handle(api, "POST /v1/tenants/{tid}/support-access/{id}", s.supportAccessDecision) // {id}:approve, :deny, :revoke
	s.handle(api, "GET /v1/tenants/{tid}/workspaces", s.listWorkspaces)
	s.handle(api, "POST /v1/tenants/{tid}/workspaces", s.createWorkspace)
	s.handle(api, "PATCH /v1/tenants/{tid}/workspaces/{wid}", s.patchWorkspace)
	s.handle(api, "GET /v1/tenants/{tid}/members", s.listMembers)
	s.handle(api, "POST /v1/tenants/{tid}/members", s.addMember)
	s.handle(api, "PATCH /v1/tenants/{tid}/members/{uid}", s.patchMember)
	s.handle(api, "DELETE /v1/tenants/{tid}/members/{uid}", s.removeMember)
	s.handle(api, "GET /v1/tenants/{tid}/apps", s.listTenantApps)
	s.handle(api, "PUT /v1/tenants/{tid}/apps/{app}", s.enableApp)
	s.handle(api, "DELETE /v1/tenants/{tid}/apps/{app}", s.disableApp)
	s.handle(api, "GET /v1/tenants/{tid}/grants", s.listGrants)
	s.handle(api, "POST /v1/tenants/{tid}/grants", s.createGrant)
	s.handle(api, "DELETE /v1/tenants/{tid}/grants/{id}", s.revokeGrant)
	s.handle(api, "GET /v1/tenants/{tid}/placements", s.listPlacements)
	s.handle(api, "GET /v1/tenants/{tid}/invitations", s.listInvitations)
	s.handle(api, "POST /v1/tenants/{tid}/invitations", s.createInvitation)
	s.handle(api, "POST /v1/tenants/{tid}/invitations/{id}", s.invitationAction) // {id}:resend
	s.handle(api, "DELETE /v1/tenants/{tid}/invitations/{id}", s.revokeInvitation)
	s.handle(api, "POST /v1/invitations:accept", s.acceptInvitation)
	s.handle(api, "GET /v1/tenants/{tid}/audit", s.listAudit)
	s.handle(api, "GET /v1/tenants/{tid}/audit/export", s.exportAudit)
	s.handle(api, "GET /v1/tenants/{tid}/audit:verify", s.verifyAudit)
	s.handle(api, "GET /v1/tenants/{tid}/audit/sinks", s.listAuditSinks)
	s.handle(api, "POST /v1/tenants/{tid}/audit/sinks", s.createAuditSink)
	s.handle(api, "PATCH /v1/tenants/{tid}/audit/sinks/{id}", s.patchAuditSink)
	s.handle(api, "DELETE /v1/tenants/{tid}/audit/sinks/{id}", s.deleteAuditSink)
	s.handle(api, "GET /v1/tenants/{tid}/security-policy", s.getSecurityPolicy)
	s.handle(api, "PUT /v1/tenants/{tid}/security-policy", s.putSecurityPolicy)
	s.handle(api, "GET /admin/v1/audit", s.adminListAudit)
	s.handle(api, "GET /admin/v1/audit:verify", s.adminVerifyAudit)
	s.handle(api, "GET /v1/apps", s.listApps)
	s.handle(api, "PUT /admin/v1/apps/{slug}", s.applyApp)
	s.handle(api, "GET /v1/apps/{slug}/roles", s.listRoles)
	s.handle(api, "POST /admin/v1/apps/{slug}/roles", s.createRole)
	s.handle(api, "PATCH /admin/v1/apps/{slug}/roles/{name}", s.patchRole)
	s.handle(api, "DELETE /admin/v1/apps/{slug}/roles/{name}", s.deleteRole)
	s.handle(api, "GET /admin/v1/plans", s.listPlans)
	s.handle(api, "PUT /admin/v1/plans/{id}", s.putPlan)
	s.handle(api, "GET /admin/v1/db-servers", s.listDBServers)
	s.handle(api, "POST /admin/v1/db-servers", s.createDBServer)
	s.handle(api, "PATCH /admin/v1/db-servers/{id}", s.patchDBServer)
	s.handle(api, "DELETE /admin/v1/db-servers/{id}", s.deleteDBServer)
	s.handle(api, "POST /admin/v1/db-servers/{id}/test", s.testDBServer)

	s.handle(api, "GET /v1/me/tenants", s.myTenants)
	s.handle(api, "GET /v1/me/sessions", s.mySessions)
	s.handle(api, "DELETE /v1/me/sessions", s.signOutEverywhere)
	s.handle(api, "DELETE /v1/me/sessions/{id}", s.deleteMySession)
	s.handle(api, "GET /v1/me/mfa", s.myMFA)
	s.handle(api, "GET /v1/tenants/{tid}/members/{uid}/sessions", s.memberSessions)
	s.handle(api, "POST /v1/tenants/{tid}/members/{uid}", s.memberAction) // {uid}:sign-out, {uid}:reset-mfa
	s.handle(api, "GET /v1/tenants/{tid}/sso", s.getSSO)
	s.handle(api, "POST /v1/tenants/{tid}/sso", s.createSSO)
	s.handle(api, "DELETE /v1/tenants/{tid}/sso", s.deleteSSO)
	s.handle(api, "GET /v1/tenants/{tid}/domains", s.listDomains)
	s.handle(api, "POST /v1/tenants/{tid}/domains", s.addDomain)
	s.handle(api, "POST /v1/tenants/{tid}/domains/{domain}", s.verifyDomain) // {domain}:verify
	s.handle(api, "DELETE /v1/tenants/{tid}/domains/{domain}", s.deleteDomain)
	s.handle(api, "GET /v1/tenants/{tid}/scim/tokens", s.listSCIMTokens)
	s.handle(api, "POST /v1/tenants/{tid}/scim/tokens", s.createSCIMToken)
	s.handle(api, "DELETE /v1/tenants/{tid}/scim/tokens/{id}", s.revokeSCIMToken)
	s.handle(api, "GET /v1/tenants/{tid}/scim/group-mappings", s.listSCIMGroupMappings)
	s.handle(api, "POST /v1/tenants/{tid}/scim/group-mappings", s.createSCIMGroupMapping)
	s.handle(api, "DELETE /v1/tenants/{tid}/scim/group-mappings/{id}", s.deleteSCIMGroupMapping)
	s.handle(api, "GET /v1/me/export", s.exportMe)
	s.handle(api, "DELETE /v1/me", s.deleteMe)
	s.handle(api, "GET /v1/tenants/{tid}/exports", s.listExports)
	s.handle(api, "POST /v1/tenants/{tid}/exports", s.createExport)
	s.handle(api, "GET /v1/tenants/{tid}/exports/{id}", s.getExport)
	s.handle(api, "GET /v1/tenants/{tid}/exports/{id}/download", s.downloadExport)
	s.handle(api, "GET /v1/tenants/{tid}/retention", s.getRetention)
	s.handle(api, "PUT /v1/tenants/{tid}/retention", s.putRetention)
	s.handle(api, "GET /admin/v1/users", s.listUsers)
	s.handle(api, "GET /admin/v1/users/{uid}", s.getUser)
	s.handle(api, "PATCH /admin/v1/users/{uid}", s.patchUser)
	s.handle(api, "DELETE /admin/v1/users/{uid}", s.deleteUser)
	s.handle(api, "GET /admin/v1/apps/{slug}/secrets", s.listAppSecrets)
	s.handle(api, "POST /admin/v1/apps/{slug}/secrets", s.createAppSecret)
	s.handle(api, "DELETE /admin/v1/apps/{slug}/secrets/{id}", s.revokeAppSecret)
	s.handle(api, "GET /admin/v1/apps/{slug}/webhooks", s.listWebhooks)
	s.handle(api, "POST /admin/v1/apps/{slug}/webhooks", s.createWebhook)
	s.handle(api, "PATCH /admin/v1/apps/{slug}/webhooks/{id}", s.patchWebhook)
	s.handle(api, "DELETE /admin/v1/apps/{slug}/webhooks/{id}", s.deleteWebhook)
	s.handle(api, "POST /admin/v1/apps/{slug}/webhooks/{id}/test", s.testWebhook)
	s.handle(api, "GET /admin/v1/tenants", s.adminListTenants)
	s.handle(api, "POST /admin/v1/tenants/{tid}", s.adminTenantAction) // {tid}:suspend, :resume, :restore
	s.handle(api, "DELETE /admin/v1/tenants/{tid}", s.adminDeleteTenant)
	s.handle(api, "PUT /admin/v1/tenants/{tid}/plan", s.putTenantPlan)
	s.handle(api, "GET /admin/v1/tenants/{tid}/support-access", s.adminListSupportAccess)
	s.handle(api, "POST /admin/v1/tenants/{tid}/support-access", s.requestSupportAccess)
	s.handle(api, "POST /admin/v1/tenants/{tid}/support-access/{id}", s.endSupportAccess) // {id}:end
	s.handle(api, "GET /admin/v1/stats", s.stats)
	s.handle(api, "GET /admin/v1/readiness", s.getReadiness)
	s.handle(api, "GET /admin/v1/evidence", s.listEvidence)
	s.handle(api, "POST /admin/v1/evidence", s.recordEvidence)

	// app backends, authenticated with their client id and secret (contract §7, technical specification §4)
	appAPI := http.NewServeMux()
	s.handle(appAPI, "GET /v1/apps/{app}/changes", s.appChanges)
	s.handle(appAPI, "GET /v1/apps/{app}/snapshot", s.appSnapshot)
	s.handle(appAPI, "GET /v1/apps/{app}/placements/{tid}", s.appGetPlacement)
	s.handle(appAPI, "PUT /v1/apps/{app}/placements/{tid}", s.appPutPlacement)
	s.handle(appAPI, "POST /v1/apps/{app}/placements/{tid}", s.appPlacementAction) // {tid}:ready, {tid}:deleted
	s.handle(appAPI, "POST /v1/apps/{app}/placements/{tid}/credentials", s.appPlacementCredentials)

	authed := s.authenticate(s.idempotent(api), s.idempotent(appAPI))
	mux.Handle("/v1/", authed)
	mux.Handle("/admin/v1/", authed)
	for _, rt := range s.internalRoutes {
		s.handle(mux, rt.pattern, rt.handler)
	}
	return mux
}

type route struct {
	pattern string
	handler http.HandlerFunc
}

// handle registers h on mux and records the pattern for Routes.
func (s *Server) handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	s.routes = append(s.routes, pattern)
	mux.HandleFunc(pattern, h)
}

// Routes returns every "METHOD /path" pattern maturad serves, as registered with http.ServeMux. The /internal/v1
// routes are listed even when EnableInternal has not turned them on. It builds the handler to find them.
func (s *Server) Routes() []string {
	s.Handler()
	out := append([]string(nil), s.routes...)
	if len(s.internalRoutes) == 0 {
		for _, rt := range s.internalHandlers() {
			out = append(out, rt.pattern)
		}
	}
	return out
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		problem(w, http.StatusServiceUnavailable, "not-ready", "database unreachable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authenticate verifies the caller. App backends (HTTP Basic with client id and secret) go to appNext; users and
// operators (bearer tokens) go to next, after their profile is recorded on first sight or when it changed. The
// caller, request id and client address go into the context for the audit log.
func (s *Server) authenticate(next, appNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := store.Actor{RequestID: requestID(r), IP: s.clientIP(r).String(), UserAgent: r.UserAgent()}
		w.Header().Set("X-Request-Id", actor.RequestID)
		if id, secret, ok := r.BasicAuth(); ok {
			app, err := s.store.AuthenticateApp(r.Context(), id, secret)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="matura-apps"`)
				problem(w, http.StatusUnauthorized, "unauthenticated", "unknown client id or secret")
				return
			}
			actor.Kind, actor.ID = "app", app.ID
			ctx := store.WithActor(withPrincipal(r.Context(), Principal{AppID: app.ID}), actor)
			appNext.ServeHTTP(w, r.WithContext(withApp(ctx, app)))
			return
		}
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
		actor.Kind, actor.ID, actor.Email = "user", p.UserID, p.Email
		if p.Operator {
			actor.Kind = "operator"
		}
		r = r.WithContext(store.WithActor(withPrincipal(r.Context(), p), actor))
		if strings.HasPrefix(r.URL.Path, "/admin/") && !p.Operator {
			s.auditDenied(r, "operator-only")
			problem(w, http.StatusForbidden, "operator-only", "this endpoint is for installation operators")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- helpers ------------------------------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	problemWith(w, status, typ, detail, nil)
}

// problemWith adds extension members to the problem (RFC 9457 §3.2).
func problemWith(w http.ResponseWriter, status int, typ, detail string, ext map[string]any) {
	body := map[string]any{
		"type":   "https://matura.dev/problems/" + typ,
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	}
	for k, v := range ext {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// apiProblem is an error with its own problem type.
type apiProblem struct {
	status      int
	typ, detail string
}

func (e *apiProblem) Error() string { return e.detail }

var (
	errTenantSuspended = &apiProblem{http.StatusForbidden, "tenant-suspended",
		"this organisation is suspended; contact the installation's operators"}
	errTenantPendingDeletion = &apiProblem{http.StatusForbidden, "tenant-pending-deletion",
		"this organisation is scheduled for deletion; an owner can restore it"}
	errSupportAccessRequired = &apiProblem{http.StatusForbidden, "support-access-required",
		"operators see a tenant's admin views only with support access the tenant approved"}
	errSupportReadOnly = &apiProblem{http.StatusForbidden, "support-access-read-only",
		"support access is read-only; change tenants through /admin/v1"}
)

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var inv *store.InvalidError
	var lim *store.LimitError
	var ap *apiProblem
	switch {
	case errors.As(err, &ap):
		if ap == errSupportAccessRequired || ap == errSupportReadOnly {
			s.auditDenied(r, ap.typ)
		}
		problem(w, ap.status, ap.typ, ap.detail)
	case errors.As(err, &lim):
		ext := map[string]any{"limit": lim.Limit}
		if lim.Max != nil {
			ext["max"], ext["used"] = *lim.Max, lim.Used
		}
		problemWith(w, http.StatusPaymentRequired, "plan-limit", lim.Msg, ext)
	case errors.Is(err, store.ErrSupportAccessOff):
		s.auditDenied(r, "support-access-off")
		problem(w, http.StatusForbidden, "support-access-off", err.Error())
	case errors.As(err, &inv):
		problem(w, http.StatusUnprocessableEntity, "invalid", inv.Msg)
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "not found")
	case errors.Is(err, store.ErrConflict):
		problem(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrVersion):
		problem(w, http.StatusPreconditionFailed, "version-mismatch", "changed since you read it; reload and retry")
	case errors.Is(err, errForbidden):
		s.auditDenied(r, "forbidden")
		problem(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, errIPNotAllowed):
		s.auditDenied(r, "ip-not-allowed")
		problem(w, http.StatusForbidden, "ip-not-allowed", err.Error())
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

// operatorTenantRoutes are the tenant routes where operators act with operator scope: the tenant record, its
// lifecycle, its placements, its entitlements and its security policy. Everything else in a tenant is the tenant's own business:
// operators see it only through support access (read-only).
var operatorTenantRoutes = map[string]bool{
	"GET /v1/tenants/{tid}": true, "PATCH /v1/tenants/{tid}": true, "DELETE /v1/tenants/{tid}": true,
	"POST /v1/tenants/{tid}": true, "GET /v1/tenants/{tid}/placements": true,
	"GET /v1/tenants/{tid}/entitlements": true,
	// an operator can lift an IP allow-list that locked a tenant out
	"GET /v1/tenants/{tid}/security-policy": true, "PUT /v1/tenants/{tid}/security-policy": true,
}

// pendingDeletionRoutes are what members may still do while a deleted tenant can be restored: read it, restore it,
// and repeat the deletion (no change).
var pendingDeletionRoutes = map[string]bool{"GET /v1/tenants/{tid}": true, "POST /v1/tenants/{tid}": true,
	"DELETE /v1/tenants/{tid}": true}

// tenantAccess returns the scope for acting in a tenant. Members may read; owners and admins may manage.
// Non-members get ErrNotFound so tenant ids cannot be probed. A suspended tenant refuses its members
// (tenant-suspended), as does one pending deletion except to read it and restore it. Operators have operator scope
// on operatorTenantRoutes; elsewhere they act as members of tenants they belong to, and otherwise need active
// support access, which allows reads only, in the tenant's own scope.
func (s *Server) tenantAccess(r *http.Request, tid uuid.UUID, manage bool) (store.Scope, store.Membership, error) {
	p := principalFrom(r.Context())
	if p.Operator && operatorTenantRoutes[r.Pattern] {
		return store.Scope{UserID: p.UserID, Operator: true}.InTenant(tid), store.Membership{TenantRole: "operator"}, nil
	}
	sc := store.Scope{UserID: p.UserID}.InTenant(tid)
	m, status, err := s.store.TenantAccessOf(r.Context(), tid, p.UserID)
	if errors.Is(err, store.ErrNotFound) && p.Operator {
		if _, err := s.store.UseSupportAccess(r.Context(), tid, p.UserID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return sc, m, errSupportAccessRequired
			}
			return sc, m, err
		}
		if r.Method != http.MethodGet {
			return sc, m, errSupportReadOnly
		}
		return sc, store.Membership{TenantRole: "support"}, nil
	}
	if err != nil {
		return sc, m, err
	}
	switch status {
	case "active":
	case "suspended":
		return sc, m, errTenantSuspended
	case "pending_deletion":
		if !pendingDeletionRoutes[r.Pattern] {
			return sc, m, errTenantPendingDeletion
		}
	default:
		return sc, m, store.ErrNotFound
	}
	if err := s.checkIP(r, tid); err != nil {
		return sc, m, err
	}
	if manage && m.TenantRole != "owner" && m.TenantRole != "admin" {
		return sc, m, errForbidden
	}
	return sc, m, nil
}
