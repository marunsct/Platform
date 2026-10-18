package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/events"
	"github.com/marunsct/Platform/internal/store"
)

// --- profile ------------------------------------------------------------------------------------------------------

func (s *Server) myTenants(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListMyTenants(r.Context(), principalFrom(r.Context()).UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

// --- operator: users ----------------------------------------------------------------------------------------------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var after uuid.UUID
	if v := q.Get("after"); v != "" {
		var err error
		if after, err = uuid.Parse(v); err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "after must be a user id")
			return
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	out, err := s.store.ListUsers(r.Context(), operatorScope(r), q.Get("q"), after, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := s.store.SetUserStatus(r.Context(), operatorScope(r), id, in.Status)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.seen.Delete(id) // the next request re-checks the status
	writeJSON(w, http.StatusOK, u)
}

// --- operator: app secrets and webhooks ---------------------------------------------------------------------------

func (s *Server) listAppSecrets(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListAppSecrets(r.Context(), operatorScope(r), r.PathValue("slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) createAppSecret(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label string `json:"label"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.CreateAppSecret(r.Context(), operatorScope(r), r.PathValue("slug"), in.Label)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) revokeAppSecret(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.RevokeAppSecret(r.Context(), operatorScope(r), r.PathValue("slug"), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListWebhooks(r.Context(), operatorScope(r), r.PathValue("slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.CreateWebhook(r.Context(), operatorScope(r), s.keys, r.PathValue("slug"), in.URL)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) patchWebhook(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.store.UpdateWebhook(r.Context(), operatorScope(r), r.PathValue("slug"), id,
		store.WebhookPatch{URL: in.URL, Status: in.Status})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteWebhook(r.Context(), operatorScope(r), r.PathValue("slug"), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// testWebhook sends a signed matura.ping event to the endpoint now and reports what the receiver answered.
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	hooks, err := s.store.ListWebhooks(r.Context(), operatorScope(r), r.PathValue("slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var hook *store.Webhook
	for i := range hooks {
		if hooks[i].ID == id {
			hook = &hooks[i]
		}
	}
	if hook == nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	key, err := s.store.WebhookKey(r.Context(), s.keys, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	payload, _ := json.Marshal(map[string]any{"endpoint_id": id})
	e := events.Envelope{SpecVersion: "1.0", ID: "evt_ping_" + uuid.NewString(), Source: s.source, Type: "matura.ping",
		Time: time.Now().UTC(), Subject: "apps/" + hook.App + "/webhooks/" + id.String(), Sequence: "0",
		DataContentType: "application/json", Data: events.Data{Object: "ping", Payload: payload}}
	body, _ := json.Marshal(e)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, err := events.Post(ctx, webhookClient, hook.URL, key, e.ID, body)
	res := map[string]any{"ok": err == nil, "status": status}
	if err != nil {
		res["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, res)
}

var webhookClient = &http.Client{Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// --- app backends: change feed and snapshot (contract §7) ----------------------------------------------------------

// ownApp returns the calling app if the path names it; any other app is reported as not found.
func ownApp(w http.ResponseWriter, r *http.Request) (store.App, bool) {
	a := appFrom(r.Context())
	if a.Slug == "" || r.PathValue("app") != a.Slug {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return a, false
	}
	return a, true
}

func (s *Server) appChanges(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var after int64
	if c := q.Get("cursor"); c != "" {
		var err error
		if after, err = strconv.ParseInt(c, 10, 64); err != nil || after < 0 {
			problem(w, http.StatusBadRequest, "bad-request", "cursor is not one this feed returned")
			return
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	changes, next, err := s.store.Changes(r.Context(), app, after, limit)
	if errors.Is(err, store.ErrGone) {
		problem(w, http.StatusGone, "cursor-expired", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]events.Envelope, len(changes))
	for i, c := range changes {
		items[i] = events.FromChange(s.source, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": strconv.FormatInt(next, 10),
		"has_more": len(changes) == store.FeedLimit(limit)})
}

func (s *Server) appSnapshot(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	var tid uuid.UUID
	if v := r.URL.Query().Get("tenant"); v != "" {
		var err error
		if tid, err = uuid.Parse(v); err != nil {
			problem(w, http.StatusNotFound, "not-found", "not found")
			return
		}
	}
	snap, err := s.store.AppSnapshot(r.Context(), app, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cursor": strconv.FormatInt(snap.Cursor, 10), "tenant": snap.Tenant,
		"workspaces": nonNil(snap.Workspaces), "users": nonNil(snap.Users), "memberships": nonNil(snap.Members),
		"grants": nonNil(snap.Grants), "placement": snap.Placement, "roles": nonNil(snap.Roles),
		"tenants": snap.Tenants})
}
