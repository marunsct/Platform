// Package billing exports metered usage to a billing system (TS18, technical specification §22.3): Stripe Billing
// meter events, Lago events or OpenMeter CloudEvents. Matura never handles payment data; the billing system prices
// usage, invoices and collects. Each adapter is a plain HTTP client; the exporter sends usage in order from a cursor
// with one leader, so each event reaches the provider at least once and the event id makes it count once there.
package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

// Adapter sends usage to one billing system.
type Adapter interface {
	Name() string // stripe, lago or openmeter: billing_customer.provider
	// Send delivers records in order; it returns how many were delivered before the first failure.
	Send(ctx context.Context, records []store.BillableUsage) (int, error)
}

// Error is a provider's refusal or failure.
type Error struct {
	Provider string
	Status   int
	Body     string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.Provider, e.Status, e.Body)
}

func send(ctx context.Context, c *http.Client, provider string, req *http.Request) error {
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("%s: %w", provider, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode/100 != 2 {
		return &Error{Provider: provider, Status: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return nil
}

// --- Stripe Billing -----------------------------------------------------------------------------------------------

// Stripe sends each record as a billing meter event (POST /v1/billing/meter_events): event_name is the Stripe
// meter's event name, payload[stripe_customer_id] the tenant's customer, identifier the record's id, so Stripe
// counts a retried event once.
type Stripe struct {
	APIKey  string            // sk_live_… or sk_test_… (a restricted key with meter-event write is enough)
	BaseURL string            // default https://api.stripe.com
	Events  map[string]string // Matura meter (devflow.runs) → Stripe event name; default: the meter with . as _
	Client  *http.Client
	Version string // Stripe-Version header, optional
}

func (s *Stripe) Name() string { return "stripe" }

func (s *Stripe) eventName(meter string) string {
	if n, ok := s.Events[meter]; ok {
		return n
	}
	return strings.ReplaceAll(meter, ".", "_")
}

func (s *Stripe) Send(ctx context.Context, records []store.BillableUsage) (int, error) {
	base := strings.TrimRight(orDefault(s.BaseURL, "https://api.stripe.com"), "/")
	for i, r := range records {
		form := url.Values{
			"event_name":                  {s.eventName(r.Meter)},
			"payload[stripe_customer_id]": {r.CustomerID},
			"payload[value]":              {strconv.FormatInt(r.Quantity, 10)},
			"identifier":                  {stripeIdentifier(r.EventID)},
			"timestamp":                   {strconv.FormatInt(r.Time.Unix(), 10)},
		}
		req, err := http.NewRequest(http.MethodPost, base+"/v1/billing/meter_events", strings.NewReader(form.Encode()))
		if err != nil {
			return i, err
		}
		req.Header.Set("Authorization", "Bearer "+s.APIKey)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Idempotency-Key", stripeIdentifier(r.EventID))
		if s.Version != "" {
			req.Header.Set("Stripe-Version", s.Version)
		}
		if err := send(ctx, s.Client, "stripe", req); err != nil {
			var e *Error
			// Stripe answers 400 for an identifier it already has: the event was counted
			if errors.As(err, &e) && e.Status == http.StatusBadRequest && strings.Contains(e.Body, "identifier") &&
				strings.Contains(strings.ToLower(e.Body), "already") {
				continue
			}
			return i, err
		}
	}
	return len(records), nil
}

// stripeIdentifier fits Stripe's 100-character identifier.
func stripeIdentifier(id string) string {
	if len(id) <= 100 {
		return id
	}
	return id[len(id)-100:]
}

// --- Lago ---------------------------------------------------------------------------------------------------------

// Lago sends records in batches of 100 (POST /api/v1/events/batch): code is the billable metric code,
// external_subscription_id the tenant's subscription (or customer id when none is set), transaction_id the record's
// id, so Lago counts a retried event once.
type Lago struct {
	APIKey  string
	BaseURL string            // default https://api.getlago.com
	Codes   map[string]string // Matura meter → Lago billable metric code; default: the meter with . as _
	Client  *http.Client
}

func (l *Lago) Name() string { return "lago" }

func (l *Lago) Send(ctx context.Context, records []store.BillableUsage) (int, error) {
	base := strings.TrimRight(orDefault(l.BaseURL, "https://api.getlago.com"), "/")
	done := 0
	for start := 0; start < len(records); start += 100 {
		batch := records[start:min(start+100, len(records))]
		events := make([]map[string]any, 0, len(batch))
		for _, r := range batch {
			code, ok := l.Codes[r.Meter]
			if !ok {
				code = strings.ReplaceAll(r.Meter, ".", "_")
			}
			sub := r.SubscriptionID
			if sub == "" {
				sub = r.CustomerID
			}
			events = append(events, map[string]any{"transaction_id": r.EventID, "external_subscription_id": sub,
				"external_customer_id": r.CustomerID, "code": code, "timestamp": r.Time.Unix(),
				"properties": map[string]any{"value": r.Quantity}})
		}
		body, _ := json.Marshal(map[string]any{"events": events})
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/events/batch", bytes.NewReader(body))
		if err != nil {
			return done, err
		}
		req.Header.Set("Authorization", "Bearer "+l.APIKey)
		req.Header.Set("Content-Type", "application/json")
		if err := send(ctx, l.Client, "lago", req); err != nil {
			return done, err
		}
		done += len(batch)
	}
	return done, nil
}

// --- OpenMeter ----------------------------------------------------------------------------------------------------

// OpenMeter sends records as a CloudEvents batch (POST /api/v1/events, application/cloudevents-batch+json): type is
// the meter's event type, subject the tenant's customer (subject) key, id the record's id (OpenMeter de-duplicates
// by id and source).
type OpenMeter struct {
	APIKey  string // token for OpenMeter Cloud; empty for a self-hosted one without auth
	BaseURL string // default https://openmeter.cloud
	Source  string // CloudEvents source (default matura)
	Types   map[string]string
	Client  *http.Client
}

func (o *OpenMeter) Name() string { return "openmeter" }

func (o *OpenMeter) Send(ctx context.Context, records []store.BillableUsage) (int, error) {
	base := strings.TrimRight(orDefault(o.BaseURL, "https://openmeter.cloud"), "/")
	done := 0
	for start := 0; start < len(records); start += 500 {
		batch := records[start:min(start+500, len(records))]
		events := make([]map[string]any, 0, len(batch))
		for _, r := range batch {
			typ, ok := o.Types[r.Meter]
			if !ok {
				typ = r.Meter
			}
			events = append(events, map[string]any{"specversion": "1.0", "id": r.EventID,
				"source": orDefault(o.Source, "matura"), "type": typ, "subject": r.CustomerID,
				"time": r.Time.UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json",
				"data": map[string]any{"value": r.Quantity, "tenant_id": r.TenantID}})
		}
		body, _ := json.Marshal(events)
		req, err := http.NewRequest(http.MethodPost, base+"/api/v1/events", bytes.NewReader(body))
		if err != nil {
			return done, err
		}
		if o.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+o.APIKey)
		}
		req.Header.Set("Content-Type", "application/cloudevents-batch+json")
		if err := send(ctx, o.Client, "openmeter", req); err != nil {
			return done, err
		}
		done += len(batch)
	}
	return done, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// --- the exporter -------------------------------------------------------------------------------------------------

// Exporter moves usage to the adapter in rounds: one leader across replicas (advisory lock), in seq order, from the
// provider's cursor. Usage of tenants not linked to a customer of that provider is skipped (counted, not sent).
type Exporter struct {
	Store    *store.Store
	Adapter  Adapter
	Interval time.Duration // default 30s
	Batch    int           // default 500
	Log      *slog.Logger
}

const exportLock = 7351017

// Run exports until ctx ends.
func (e *Exporter) Run(ctx context.Context) {
	if e.Interval <= 0 {
		e.Interval = 30 * time.Second
	}
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		release, ok, err := e.Store.TryLeader(ctx, exportLock)
		if err == nil && ok {
			if _, err := e.Round(ctx); err != nil && ctx.Err() == nil && e.Log != nil {
				e.Log.Warn("billing export failed", "provider", e.Adapter.Name(), "err", err)
			}
			release()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round exports one batch and returns how many events reached the provider.
func (e *Exporter) Round(ctx context.Context) (int, error) {
	batch := e.Batch
	if batch <= 0 {
		batch = 500
	}
	items, cursor, err := e.Store.PendingUsage(ctx, e.Adapter.Name(), batch)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	var send []store.BillableUsage
	for _, it := range items {
		if it.CustomerID != "" {
			send = append(send, it)
		}
	}
	n, sendErr := e.Adapter.Send(ctx, send)
	// advance past everything up to the first unsent record (skipped ones before it included)
	next, exported, skipped := cursor, 0, 0
	sent := 0
	for _, it := range items {
		if it.CustomerID == "" {
			skipped++
			next = it.Seq
			continue
		}
		if sent >= n {
			break
		}
		sent++
		exported++
		next = it.Seq
	}
	if err := e.Store.UsageExported(ctx, e.Adapter.Name(), next, exported, skipped, sendErr); err != nil {
		return exported, err
	}
	return exported, sendErr
}
