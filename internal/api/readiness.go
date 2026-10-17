package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/readiness"
	"github.com/marunsct/Platform/internal/store"
)

// Readiness (TS24, technical specification §14): operators read the readiness report and record evidence.

// SetReadiness tells the server about its own configuration, which installation controls are evaluated against.
func (s *Server) SetReadiness(in readiness.Install) {
	if in.Product == "" {
		in.Product = "Matura"
	}
	s.install = in
	s.trust.reset()
}

// readinessFacts gathers the installation's real state: tenant policies and audit destinations, every audit chain
// recomputed, webhook health and the newest evidence of each kind.
func (s *Server) readinessFacts(ctx context.Context) (readiness.Facts, error) {
	op := store.Scope{Operator: true}
	f := readiness.Facts{Now: time.Now().UTC(), Install: s.install,
		Latest: map[string]*readiness.Evidence{}, Recent: map[string]int{}}
	v, err := s.store.VerifyAudit(ctx, op, uuid.Nil)
	if err != nil {
		return f, err
	}
	f.Installation = chain(v)
	postures, err := s.store.TenantPostures(ctx)
	if err != nil {
		return f, err
	}
	for _, p := range postures {
		t := readiness.Tenant{ID: p.Tenant.ID, Slug: p.Tenant.Slug, Kind: p.Tenant.Kind, Status: p.Tenant.Status,
			PolicySet: p.Policy.Version > 0, RequireMFA: p.Policy.RequireMFA, SessionMaxAge: p.Policy.SessionMaxAge,
			IdleTimeout: p.Policy.IdleTimeout, AllowedEmailDomains: len(p.Policy.AllowedEmailDomains),
			IPAllowlist: len(p.Policy.IPAllowlist), SinksActive: p.SinksActive, SinksFailing: p.SinksFailing}
		if t.Status == "active" {
			v, err := s.store.VerifyAudit(ctx, op, t.ID)
			if err != nil {
				return f, err
			}
			t.Audit = chain(v)
		}
		f.Tenants = append(f.Tenants, t)
	}
	w, err := s.store.WebhookHealth(ctx)
	if err != nil {
		return f, err
	}
	f.Webhooks = readiness.Webhooks{Active: w.Active, Failing: w.Failing, Disabled: w.Disabled, Dropped: w.Dropped}
	since := f.Now.Add(-90 * 24 * time.Hour)
	for kind := range readiness.EvidenceKinds {
		latest, err := s.store.ListEvidence(ctx, op, kind, nil, 1)
		if err != nil {
			return f, err
		}
		if len(latest) == 0 {
			continue
		}
		e := evidenceOut(latest[0])
		f.Latest[kind] = &e
		recent, err := s.store.ListEvidence(ctx, op, kind, &since, 1000)
		if err != nil {
			return f, err
		}
		f.Recent[kind] = len(recent)
	}
	return f, nil
}

func chain(v store.AuditVerification) readiness.Chain {
	c := readiness.Chain{OK: v.OK, Events: v.Events}
	if v.FirstBreak != nil {
		c.Reason = "seq " + strconv.FormatInt(v.FirstBreak.Seq, 10) + ": " + v.FirstBreak.Reason
	}
	return c
}

func evidenceOut(e store.EvidenceRecord) readiness.Evidence {
	return readiness.Evidence{ID: e.ID, Kind: e.Kind, Passed: e.Passed, Details: e.Details, RecordedAt: e.RecordedAt,
		RecordedBy: e.RecordedBy, Seq: e.Seq, Hash: e.Hash}
}

func (s *Server) report(ctx context.Context) (readiness.Report, error) {
	f, err := s.readinessFacts(ctx)
	if err != nil {
		return readiness.Report{}, err
	}
	return readiness.Evaluate(f), nil
}

func (s *Server) getReadiness(w http.ResponseWriter, r *http.Request) {
	rep, err := s.report(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, rep)
}

func evidenceKinds() []string {
	out := make([]string, 0, len(readiness.EvidenceKinds))
	for k := range readiness.EvidenceKinds {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (s *Server) recordEvidence(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind    string          `json:"kind"`
		Passed  *bool           `json:"passed"`
		Details json.RawMessage `json:"details"`
	}
	if !decode(w, r, &in) {
		return
	}
	if _, ok := readiness.EvidenceKinds[in.Kind]; !ok {
		problem(w, http.StatusUnprocessableEntity, "invalid", "kind must be one of "+joinQuoted(evidenceKinds()))
		return
	}
	if in.Passed == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid", "passed is required")
		return
	}
	if d := bytes.TrimSpace(in.Details); len(d) > 0 && (d[0] != '{' || len(d) > 16<<10) {
		problem(w, http.StatusUnprocessableEntity, "invalid", "details must be a JSON object of at most 16 KiB")
		return
	}
	rec, err := s.store.RecordEvidence(r.Context(), operatorScope(r), in.Kind, *in.Passed, in.Details)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.trust.reset()
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if _, ok := readiness.EvidenceKinds[kind]; kind != "" && !ok {
		problem(w, http.StatusBadRequest, "bad-request", "kind must be one of "+joinQuoted(evidenceKinds()))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListEvidence(r.Context(), operatorScope(r), kind, nil, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func joinQuoted(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += strconv.Quote(x)
	}
	return out
}
