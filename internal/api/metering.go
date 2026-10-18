package api

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Metering, quotas and billing links (TS18, technical specification §22).

func (s *Server) appTenant(w http.ResponseWriter, r *http.Request) (store.App, uuid.UUID, bool) {
	app, ok := ownApp(w, r)
	if !ok {
		return app, uuid.Nil, false
	}
	tid, ok := pathUUID(w, r, "tid")
	return app, tid, ok
}

// POST /v1/apps/{app}/tenants/{tid}/usage {events: [{id, meter, quantity, time}]}: report usage (idempotent by id).
func (s *Server) recordUsage(w http.ResponseWriter, r *http.Request) {
	app, tid, ok := s.appTenant(w, r)
	if !ok {
		return
	}
	var in struct {
		Events []store.UsageEvent `json:"events"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.RecordUsage(r.Context(), app, tid, in.Events)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

// POST /v1/apps/{app}/tenants/{tid}/quota:consume {id, meter, quantity}: take quantity of a meter if the plan
// allows it, atomically. 200 with allowed true or false; a retry with the same id gets the first answer.
func (s *Server) consumeQuota(w http.ResponseWriter, r *http.Request) {
	app, tid, ok := s.appTenant(w, r)
	if !ok {
		return
	}
	var in store.UsageEvent
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.ConsumeQuota(r.Context(), app, tid, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /v1/apps/{app}/tenants/{tid}/entitlements: features, and this app's meters with their use, for SDK caches.
func (s *Server) appEntitlements(w http.ResponseWriter, r *http.Request) {
	app, tid, ok := s.appTenant(w, r)
	if !ok {
		return
	}
	out, err := s.store.AppEntitlementsFor(r.Context(), app, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(out.Version, 10)+`"`)
	writeJSON(w, http.StatusOK, out)
}

// GET and PUT /admin/v1/tenants/{tid}/billing: operators link a tenant to its billing customer.
func (s *Server) getBillingCustomer(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	out, err := s.store.GetBillingCustomer(r.Context(), store.Scope{Operator: true}, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putBillingCustomer(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Provider       string `json:"provider"`
		CustomerID     string `json:"customer_id"`
		SubscriptionID string `json:"subscription_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.store.SetBillingCustomer(r.Context(), store.Scope{Operator: true}, tid, in.Provider, in.CustomerID, in.SubscriptionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /admin/v1/billing/exports: how far usage reached each billing provider.
func (s *Server) billingExports(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.BillingExports(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
