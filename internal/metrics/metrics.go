// Package metrics exposes maturad's request and queue metrics in the Prometheus text format (TS20).
//
// It is a small implementation on purpose: request counts and latency histograms by method, route and status class,
// plus queue gauges read from the database on each scrape. Serve it on a separate listener (MATURA_METRICS_ADDR) so
// it is not reachable from the internet.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

var buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type key struct{ method, route, class string }

type series struct {
	count  uint64
	sum    float64
	bucket []uint64
}

// Registry collects request metrics.
type Registry struct {
	mu    sync.Mutex
	reqs  map[key]*series
	start time.Time
	// Backlog reads queue sizes; nil leaves the queue gauges out.
	Backlog func(context.Context) (store.Backlog, error)
}

func New() *Registry { return &Registry{reqs: map[key]*series{}, start: time.Now()} }

var (
	idSegment  = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	slugParent = map[string]bool{"apps": true, "roles": true, "plans": true}
)

// Route turns a request path into a label with bounded values: ids become {id}, and names after apps/, roles/
// and plans/ become {name}; an action suffix such as :resend stays.
func Route(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		base, action, _ := strings.Cut(p, ":")
		switch {
		case idSegment.MatchString(base):
			base = "{id}"
		case i > 0 && slugParent[parts[i-1]] && base != "":
			base = "{name}"
		}
		if action != "" {
			parts[i] = base + ":" + action
		} else {
			parts[i] = base
		}
	}
	if strings.HasPrefix(path, "/portal/") {
		return "/portal/*"
	}
	return strings.Join(parts, "/")
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Wrap counts and times every request next serves.
func (m *Registry) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		m.observe(key{r.Method, Route(r.URL.Path), fmt.Sprintf("%dxx", rec.status/100)}, time.Since(start).Seconds())
	})
}

func (m *Registry) observe(k key, secs float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.reqs[k]
	if s == nil {
		s = &series{bucket: make([]uint64, len(buckets))}
		m.reqs[k] = s
	}
	s.count++
	s.sum += secs
	for i, b := range buckets {
		if secs <= b {
			s.bucket[i]++
		}
	}
}

// ServeHTTP writes the metrics.
func (m *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	m.mu.Lock()
	keys := make([]key, 0, len(m.reqs))
	for k := range m.reqs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		return a.route+a.method+a.class < c.route+c.method+c.class
	})
	b.WriteString("# HELP matura_http_requests_total HTTP requests served.\n# TYPE matura_http_requests_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "matura_http_requests_total{%s} %d\n", k.labels(), m.reqs[k].count)
	}
	b.WriteString("# HELP matura_http_request_duration_seconds Time to serve a request.\n" +
		"# TYPE matura_http_request_duration_seconds histogram\n")
	for _, k := range keys {
		s := m.reqs[k]
		for i, le := range buckets {
			fmt.Fprintf(&b, "matura_http_request_duration_seconds_bucket{%s,le=\"%g\"} %d\n", k.labels(), le, s.bucket[i])
		}
		fmt.Fprintf(&b, "matura_http_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", k.labels(), s.count)
		fmt.Fprintf(&b, "matura_http_request_duration_seconds_sum{%s} %g\n", k.labels(), s.sum)
		fmt.Fprintf(&b, "matura_http_request_duration_seconds_count{%s} %d\n", k.labels(), s.count)
	}
	m.mu.Unlock()
	gauge(&b, "matura_uptime_seconds", "Seconds since maturad started.", time.Since(m.start).Seconds())
	if m.Backlog != nil {
		bl, err := m.Backlog(r.Context())
		up := 1.0
		if err != nil {
			up = 0
		}
		gauge(&b, "matura_database_up", "1 when the last metrics query reached the database.", up)
		if err == nil {
			gauge(&b, "matura_events_unsequenced", "Changes not yet given a change-feed position.", float64(bl.UnsequencedEvents))
			gauge(&b, "matura_webhook_lag_events", "Events the furthest-behind active webhook endpoint has not received.", float64(bl.WebhookLag))
			gauge(&b, "matura_webhooks_failing", "Webhook endpoints in the failing state.", float64(bl.WebhooksFailing))
			gauge(&b, "matura_emails_pending", "Emails waiting to be sent.", float64(bl.EmailsPending))
			gauge(&b, "matura_email_oldest_pending_seconds", "Age of the oldest email waiting to be sent.", bl.OldestEmailAge)
		}
	}
	_, _ = w.Write([]byte(b.String()))
}

func gauge(b *strings.Builder, name, help string, v float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
}

func (k key) labels() string {
	return fmt.Sprintf(`method=%q,route=%q,code=%q`, k.method, k.route, k.class)
}
