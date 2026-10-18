# Metering, quotas and billing

Matura counts what tenants use, enforces plan limits, and sends usage to your billing system. The billing system
can be Stripe Billing, Lago or OpenMeter, and it prices and invoices the usage. Matura never handles payment data.
Reference: [technical specification §22](../spec/02-technical-specification.md#22-metering-quotas-and-billing-ts18).

## 1. Put meters in a plan

```sh
curl -X PUT "$MATURA/admin/v1/plans/pro" -H "Authorization: Bearer $OPERATOR_TOKEN" -d '{
  "name": "Pro",
  "limits": {
    "features": {"pdf_export": true},
    "meters": {
      "devflow.runs":      {"limit": 1000, "period": "month", "hard": true},
      "devflow.api_calls": {"limit": 100000, "period": "day"}
    }
  }}'
curl -X PUT "$MATURA/admin/v1/tenants/$TID/plan" -H "Authorization: Bearer $OPERATOR_TOKEN" -d '{"plan": "pro"}'
```

A **hard** limit refuses quota beyond it. A **soft** limit only sends `matura.usage.threshold` at 80% and 100%.
Override a meter for one tenant with `entitlement_overrides`, using the same shape.

## 2. Count usage in the app

Before doing metered work, consume quota. The call is atomic, so concurrent requests never pass a hard limit:

```go
q, err := client.ConsumeQuota(ctx, "devflow", tenantID, matura.Usage{ID: runID, Meter: "runs", Quantity: 1})
if err == nil && !q.Allowed {
    return errors.New("your plan's runs for this month are used up")
}
```

For usage you only report afterwards, such as API calls, batch it with `RecordUsage`. In both calls the `ID` makes
a retry count once. Features come from a cache that keeps working while maturad is down:

```go
ents := &matura.EntitlementCache{Client: client, App: "devflow"}
if ents.Has(ctx, tenantID, "pdf_export") { … }
```

Without the Go SDK, call `POST /v1/apps/{app}/tenants/{tid}/quota:consume`, `…/usage` and
`GET …/entitlements` with the app's client id and secret (HTTP Basic).

## 3. Send usage to billing

| Provider | Settings | Link a tenant with |
|---|---|---|
| Stripe Billing | `MATURA_BILLING_PROVIDER=stripe`, `MATURA_BILLING_API_KEY=sk_…` (meter-event write), `MATURA_BILLING_METERS=devflow.runs=runs` (Stripe meter event names) | `customer_id: cus_…` |
| Lago | `MATURA_BILLING_PROVIDER=lago`, `MATURA_BILLING_API_KEY`, `MATURA_BILLING_URL` for self-hosted Lago, `MATURA_BILLING_METERS` (billable metric codes) | `customer_id`, `subscription_id` (external ids) |
| OpenMeter | `MATURA_BILLING_PROVIDER=openmeter`, `MATURA_BILLING_URL` (self-hosted) or `MATURA_BILLING_API_KEY` (cloud) | `customer_id`: the subject |

```sh
curl -X PUT "$MATURA/admin/v1/tenants/$TID/billing" -H "Authorization: Bearer $OPERATOR_TOKEN" \
     -d '{"provider": "stripe", "customer_id": "cus_NffrFeUfNV2Hib"}'
curl "$MATURA/admin/v1/billing/exports" -H "Authorization: Bearer $OPERATOR_TOKEN"
```

Usage from before a tenant is linked is not billed: it shows as `skipped`. If the provider is down, the exporter
resumes where it stopped.
