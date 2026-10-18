package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/access"
	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/store"
)

// Fine-grained permissions (TS11, technical specification §18): app backends write relationship tuples for their
// own resource types and ask OpenFGA whether a user may act on a resource, always inside one tenant that enabled
// the app. maturad translates names (internal/fga.Namespace), so an app can never reach another tenant's or another
// app's tuples.

// SetAccess turns the permission endpoints on; without it they answer 501.
func (s *Server) SetAccess(a *access.Service) { s.access = a }

// tupleIn is a relationship as the app names it: user "user:<id>", "group:<id>#member" or "type:*".
type tupleIn struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// fgaCall is everything a permission handler needs once the caller and tenant are checked.
type fgaCall struct {
	app     store.App
	ns      fga.Namespace
	storeID string
	model   string
}

// permissionTarget checks the app, the tenant (it must have enabled the app) and OpenFGA, and returns the action
// after "{tid}:" ("" for the /relations route).
func (s *Server) permissionTarget(w http.ResponseWriter, r *http.Request) (fgaCall, string, bool) {
	var c fgaCall
	app, ok := ownApp(w, r)
	if !ok {
		return c, "", false
	}
	if s.access == nil {
		problem(w, http.StatusNotImplemented, "permissions-not-configured",
			"fine-grained permissions need OpenFGA; this installation has not set MATURA_OPENFGA_URL")
		return c, "", false
	}
	raw, action, _ := strings.Cut(r.PathValue("tid"), ":")
	tid, err := uuid.Parse(raw)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return c, "", false
	}
	status, err := s.store.AppTenantStatus(r.Context(), app, tid)
	switch {
	case err != nil:
		s.fail(w, r, err)
		return c, "", false
	case status == "suspended":
		s.fail(w, r, errTenantSuspended)
		return c, "", false
	case status == "pending_deletion":
		s.fail(w, r, errTenantPendingDeletion)
		return c, "", false
	case status != "active":
		s.fail(w, r, store.ErrNotFound)
		return c, "", false
	}
	storeID, model, types, err := s.access.AppModel(r.Context(), app)
	if errors.Is(err, access.ErrNoModel) {
		problem(w, http.StatusConflict, "no-authorization-model",
			"add an authorization model to the app's manifest (docs/guide/designing-apps-for-matura.md §6.1)")
		return c, "", false
	}
	if err != nil {
		s.fgaFail(w, r, err)
		return c, "", false
	}
	return fgaCall{app: app, ns: fga.Namespace{App: app.Slug, Tenant: tid, Types: types}, storeID: storeID,
		model: model}, action, true
}

// fgaFail reports an OpenFGA error: content it refused is the app's to fix (422); anything else is temporary (503).
func (s *Server) fgaFail(w http.ResponseWriter, r *http.Request, err error) {
	err = s.access.Checked(r.Context(), err)
	var fe *fga.Error
	if errors.As(err, &fe) && fe.Invalid() {
		problem(w, http.StatusUnprocessableEntity, "invalid", "OpenFGA refused the request: "+fe.Message)
		return
	}
	var se *store.InvalidError
	if errors.As(err, &se) {
		s.fail(w, r, err)
		return
	}
	s.log.WarnContext(r.Context(), "OpenFGA call failed", "err", err)
	w.Header().Set("Retry-After", "1")
	problem(w, http.StatusServiceUnavailable, "permissions-unavailable", "the permission service is not reachable; retry")
}

func invalidTuple(w http.ResponseWriter, err error) {
	problem(w, http.StatusUnprocessableEntity, "invalid", err.Error())
}

// appRelations writes and deletes the app's tuples in one tenant, all or nothing.
func (s *Server) appRelations(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.permissionTarget(w, r)
	if !ok {
		return
	}
	var in struct {
		Writes  []tupleIn `json:"writes"`
		Deletes []tupleIn `json:"deletes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if n := len(in.Writes) + len(in.Deletes); n == 0 || n > fga.MaxWrite {
		problem(w, http.StatusUnprocessableEntity, "invalid", "send 1 to 100 writes and deletes together")
		return
	}
	writes, deletes := make([]fga.TupleKey, len(in.Writes)), make([]fga.TupleKey, len(in.Deletes))
	for i, t := range in.Writes {
		k, err := c.ns.Key(t.User, t.Relation, t.Object, true)
		if err != nil {
			invalidTuple(w, err)
			return
		}
		writes[i] = k
	}
	for i, t := range in.Deletes {
		k, err := c.ns.Key(t.User, t.Relation, t.Object, true)
		if err != nil {
			invalidTuple(w, err)
			return
		}
		deletes[i] = k
	}
	if err := s.access.Client.Write(r.Context(), c.storeID, c.model, writes, deletes); err != nil {
		s.fgaFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"written": len(writes), "deleted": len(deletes)})
}

// permissionQuery is what check, batch-check and list-objects share.
type permissionQuery struct {
	Contextual  []tupleIn `json:"contextual_tuples"`
	Consistency string    `json:"consistency"` // "" or "minimize_latency" (default), "higher" (read your writes)
}

func (q permissionQuery) build(c fgaCall) (fga.Query, error) {
	out := fga.Query{Model: c.model}
	switch q.Consistency {
	case "", "minimize_latency":
	case "higher":
		out.Higher = true
	default:
		return out, errors.New(`consistency must be "minimize_latency" or "higher"`)
	}
	for _, t := range q.Contextual {
		k, err := c.ns.Key(t.User, t.Relation, t.Object, false)
		if err != nil {
			return out, err
		}
		out.Contextual = append(out.Contextual, k)
	}
	if len(out.Contextual) > 20 {
		return out, errors.New("at most 20 contextual tuples")
	}
	return out, nil
}

// appPermissionAction handles POST {tid}:check, {tid}:batch-check, {tid}:list-objects and {tid}:list-users.
func (s *Server) appPermissionAction(w http.ResponseWriter, r *http.Request) {
	c, action, ok := s.permissionTarget(w, r)
	if !ok {
		return
	}
	switch action {
	case "check":
		s.permissionCheck(w, r, c)
	case "batch-check":
		s.permissionBatchCheck(w, r, c)
	case "list-objects":
		s.permissionListObjects(w, r, c)
	case "list-users":
		s.permissionListUsers(w, r, c)
	default:
		problem(w, http.StatusNotFound, "not-found", "not found")
	}
}

func (s *Server) permissionCheck(w http.ResponseWriter, r *http.Request, c fgaCall) {
	var in struct {
		tupleIn
		permissionQuery
	}
	if !decode(w, r, &in) {
		return
	}
	q, err := in.build(c)
	if err != nil {
		invalidTuple(w, err)
		return
	}
	k, err := c.ns.Key(in.User, in.Relation, in.Object, false)
	if err != nil {
		invalidTuple(w, err)
		return
	}
	allowed, err := s.access.Client.Check(r.Context(), c.storeID, q, k)
	if err != nil {
		s.fgaFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": allowed})
}

type checkResult struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) permissionBatchCheck(w http.ResponseWriter, r *http.Request, c fgaCall) {
	var in struct {
		Checks []tupleIn `json:"checks"`
		permissionQuery
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Checks) == 0 || len(in.Checks) > fga.MaxBatchCheck {
		problem(w, http.StatusUnprocessableEntity, "invalid", "send 1 to 50 checks")
		return
	}
	q, err := in.build(c)
	if err != nil {
		invalidTuple(w, err)
		return
	}
	results := make([]checkResult, len(in.Checks))
	var keys []fga.TupleKey
	var at []int
	for i, t := range in.Checks {
		k, err := c.ns.Key(t.User, t.Relation, t.Object, false)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		keys, at = append(keys, k), append(at, i)
	}
	if len(keys) > 0 {
		res, err := s.access.Client.BatchCheck(r.Context(), c.storeID, q, keys)
		if err != nil {
			s.fgaFail(w, r, err)
			return
		}
		for j, i := range at {
			results[i] = checkResult{Allowed: res[j].Allowed, Error: res[j].Error}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) permissionListObjects(w http.ResponseWriter, r *http.Request, c fgaCall) {
	var in struct {
		User     string `json:"user"`
		Relation string `json:"relation"`
		Type     string `json:"type"`
		permissionQuery
	}
	if !decode(w, r, &in) {
		return
	}
	q, err := in.build(c)
	if err != nil {
		invalidTuple(w, err)
		return
	}
	user, err := c.ns.User(in.User)
	if err == nil {
		err = fga.Relation(in.Relation)
	}
	typ := ""
	if err == nil {
		typ, err = c.ns.Type(in.Type)
	}
	if err != nil {
		invalidTuple(w, err)
		return
	}
	objs, err := s.access.Client.ListObjects(r.Context(), c.storeID, q, user, in.Relation, typ)
	if err != nil {
		s.fgaFail(w, r, err)
		return
	}
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		if v, ok := c.ns.FromObject(o); ok {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": out})
}

// permissionListUsers answers who has relation on an object, the "who has access" view (technical specification
// §18): only this tenant's users (or groups, or the type:* wildcard), by the names the app uses.
func (s *Server) permissionListUsers(w http.ResponseWriter, r *http.Request, c fgaCall) {
	var in struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		UserType string `json:"user_type"` // default user
		permissionQuery
	}
	if !decode(w, r, &in) {
		return
	}
	if in.UserType == "" {
		in.UserType = "user"
	}
	q, err := in.build(c)
	if err != nil {
		invalidTuple(w, err)
		return
	}
	object, err := c.ns.Object(in.Object)
	if err == nil {
		err = fga.Relation(in.Relation)
	}
	userType := ""
	if err == nil {
		userType, err = c.ns.Type(in.UserType)
	}
	if err != nil {
		invalidTuple(w, err)
		return
	}
	users, err := s.access.Client.ListUsers(r.Context(), c.storeID, q, object, in.Relation, userType)
	if err != nil {
		s.fgaFail(w, r, err)
		return
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		if strings.HasSuffix(u, ":*") {
			out = append(out, in.UserType+":*")
		} else if v, ok := c.ns.FromObject(u); ok {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}
