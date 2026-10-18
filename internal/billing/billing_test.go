package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

func records(n int) []store.BillableUsage {
	out := make([]store.BillableUsage, n)
	tid := uuid.New()
	for i := range out {
		out[i] = store.BillableUsage{Seq: int64(i + 1), EventID: tid.String() + ":app:e" + string(rune('a'+i%26)) + strings.Repeat("x", i/26),
			TenantID: tid, CustomerID: "cus_1", Meter: "devflow.runs", Quantity: int64(i + 1), Time: time.Unix(1792140300, 0)}
	}
	return out
}

func TestStripeStopsAtTheFirstFailureAndSkipsDuplicates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		switch {
		case calls == 2:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"An event with identifier x already exists"}}`))
		case calls == 4:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Header.Get("Idempotency-Key") != r.PostForm.Get("identifier") || r.PostForm.Get("event_name") != "runs":
			w.WriteHeader(http.StatusBadRequest)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	s := &Stripe{APIKey: "k", BaseURL: srv.URL, Events: map[string]string{"devflow.runs": "runs"}}
	n, err := s.Send(context.Background(), records(5))
	var e *Error
	if n != 3 || !errors.As(err, &e) || e.Status != 503 {
		t.Fatalf("sent %d, %v", n, err)
	}
	if long := stripeIdentifier(strings.Repeat("a", 150)); len(long) != 100 {
		t.Fatalf("identifier length %d", len(long))
	}
}

func TestLagoBatches(t *testing.T) {
	var batches [][]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/batch" || r.Header.Get("Authorization") != "Bearer lago" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in struct{ Events []map[string]any }
		_ = json.NewDecoder(r.Body).Decode(&in)
		batches = append(batches, in.Events)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	rs := records(150)
	rs[0].SubscriptionID = "sub_9"
	n, err := (&Lago{APIKey: "lago", BaseURL: srv.URL}).Send(context.Background(), rs)
	if err != nil || n != 150 || len(batches) != 2 || len(batches[0]) != 100 {
		t.Fatalf("%d %v %d", n, err, len(batches))
	}
	e := batches[0][0]
	if e["code"] != "devflow_runs" || e["external_subscription_id"] != "sub_9" || e["external_customer_id"] != "cus_1" ||
		e["transaction_id"] != rs[0].EventID || e["properties"].(map[string]any)["value"] != 1.0 {
		t.Fatalf("event: %v", e)
	}
	if batches[0][1]["external_subscription_id"] != "cus_1" {
		t.Fatalf("without a subscription the customer id is used: %v", batches[0][1])
	}
}

func TestOpenMeterCloudEvents(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/cloudevents-batch+json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	n, err := (&OpenMeter{BaseURL: srv.URL}).Send(context.Background(), records(3))
	if err != nil || n != 3 || len(got) != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if e := got[2]; e["specversion"] != "1.0" || e["type"] != "devflow.runs" || e["subject"] != "cus_1" || e["source"] != "matura" ||
		e["data"].(map[string]any)["value"] != 3.0 {
		t.Fatalf("event: %v", e)
	}
}
