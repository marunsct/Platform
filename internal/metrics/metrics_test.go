package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/store"
)

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/tenants/0b4d1a52-6a0e-4f43-9a3e-2b8f1c9a7d10/members":                                                 "/v1/tenants/{id}/members",
		"/v1/tenants/0b4d1a52-6a0e-4f43-9a3e-2b8f1c9a7d10/invitations/0b4d1a52-6a0e-4f43-9a3e-2b8f1c9a7d10:resend": "/v1/tenants/{id}/invitations/{id}:resend",
		"/admin/v1/apps/agentcanvas/roles/builder":                                                                 "/admin/v1/apps/{name}/roles/{name}",
		"/v1/invitations:accept":      "/v1/invitations:accept",
		"/portal/assets/index-abc.js": "/portal/*",
	} {
		if got := Route(in); got != want {
			t.Errorf("Route(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExposition(t *testing.T) {
	m := New()
	m.Backlog = func(context.Context) (store.Backlog, error) {
		return store.Backlog{EmailsPending: 3, WebhookLag: 7}, nil
	}
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	for _, p := range []string{"/v1/me", "/v1/me", "/missing"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`matura_http_requests_total{method="GET",route="/v1/me",code="2xx"} 2`,
		`matura_http_requests_total{method="GET",route="/missing",code="4xx"} 1`,
		`matura_http_request_duration_seconds_bucket{method="GET",route="/v1/me",code="2xx",le="+Inf"} 2`,
		"matura_emails_pending 3", "matura_webhook_lag_events 7", "matura_database_up 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
