package api

import (
	"net/http"
	"time"

	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

// Keys (TS17, technical specification §9): tenant keys, customer-managed keys, data keys for apps, and rewrapping
// stored secrets after a key-encryption key rotation.

// EnableTenantKeys turns on per-tenant keys over ring; customer (may be nil) allows tenants to bring their own key.
func (s *Server) EnableTenantKeys(ring *secrets.Ring, customer *secrets.CustomerKeys) {
	s.EnableTenantKeysTTL(ring, customer, 0)
}

// EnableTenantKeysTTL is EnableTenantKeys with how long unwrapped tenant keys are cached (default one minute; a
// tenant's revoked own key stops working within it).
func (s *Server) EnableTenantKeysTTL(ring *secrets.Ring, customer *secrets.CustomerKeys, ttl time.Duration) {
	s.ring = ring
	var cw store.CustomerWrapper
	if customer != nil && len(customer.Providers) > 0 {
		cw = customer.Wrapper
	}
	s.store.EnableTenantKeys(ring, cw, ttl)
}

func (s *Server) tenantKeys(w http.ResponseWriter) *store.TenantKeys {
	tk := s.store.TenantKeys()
	if tk == nil {
		problem(w, http.StatusNotImplemented, "tenant-keys-off", "tenant keys are not enabled on this server")
	}
	return tk
}

// GET /v1/tenants/{tid}/keys: owners see the tenant key versions and whether their own key seals them.
func (s *Server) getTenantKeys(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := tk.Info(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /v1/tenants/{tid}/keys:rotate: owners start a new tenant key version.
func (s *Server) rotateTenantKey(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := tk.Rotate(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v})
}

// PUT /v1/tenants/{tid}/keys/provider {provider, config}: owners make their own key seal the tenant keys (BYOK).
func (s *Server) putKeyProvider(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	var in struct {
		Provider string            `json:"provider"`
		Config   map[string]string `json:"config"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := tk.SetProvider(r.Context(), sc, tid, in.Provider, secrets.KeyRef(in.Provider, in.Config), in.Config); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := tk.Info(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /v1/tenants/{tid}/keys/provider: owners go back to the installation's key (their own key must still work).
func (s *Server) deleteKeyProvider(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	sc, err := s.ownerAccess(r, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := tk.ClearProvider(r.Context(), sc, tid); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/apps/{app}/tenants/{tid}/data-keys: a fresh data key for field encryption, plain and sealed under the
// tenant key. The app keeps the sealed form next to the data.
func (s *Server) newDataKey(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	dk, err := tk.NewDataKey(r.Context(), app, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, dk)
}

// POST /v1/apps/{app}/tenants/{tid}/data-keys:unwrap {wrapped}: the plain data key again. 410 once the tenant is
// deleted and its keys destroyed; 503 when the tenant's own key refuses.
func (s *Server) unwrapDataKey(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	tk := s.tenantKeys(w)
	if tk == nil {
		return
	}
	var in struct {
		Wrapped []byte `json:"wrapped"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, err := tk.UnwrapDataKey(r.Context(), app, tid, in.Wrapped)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"plaintext": key})
}

// POST /admin/v1/keys:rewrap: operators re-seal every stored secret under the current key-encryption key, after
// which earlier keys can be dropped from the configuration.
func (s *Server) rewrapKeys(w http.ResponseWriter, r *http.Request) {
	if s.ring == nil {
		problem(w, http.StatusNotImplemented, "keys-not-a-ring", "this server's keys cannot be rewrapped")
		return
	}
	res, err := s.store.RewrapSecrets(r.Context(), s.ring)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
