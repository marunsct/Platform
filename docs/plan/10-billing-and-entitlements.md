# 10 — Billing, metering and entitlements

Billing is an optional module: an operator running Matura for internal apps can switch it off and still use plans
and quotas.

## 1. Entitlements (always on)

- **Plans** (free, team, business, enterprise; operator-defined) bundle **features** (booleans, e.g. `sso`, `scim`,
  `audit_export`, `byok`, `silo_tier`) and **limits** (seats, workspaces, app-specific meters like runs per month).
- Per-tenant overrides and trials with end dates; grace periods; soft and hard limits with notifications at 80% and
  100%.
- SDK: `entitlements.has("sso")`, `entitlements.check("runs_per_month", 1)` (atomic consume with idempotency keys),
  cached per tenant and invalidated on change.
- Enterprise features in Matura itself are gated by the operator's plans, never by a Matura licence key: the
  software is fully open source.

## 2. Metering

- Apps emit usage events (CloudEvents) through the SDK to **OpenMeter** (Apache-2.0), which aggregates per tenant,
  meter and period; Matura adds seats and storage meters itself.
- Exactly-once semantics via event ids; late events accepted within a window; corrections as compensating events.
- Usage shown to tenants in the console and exported to billing.
- Watch item: OpenMeter was acquired by Kong in 2025 with an open-source future promised; the metering interface in
  Matura is pluggable so it can fall back to a built-in aggregator on Postgres/NATS if needed.

## 3. Billing (optional module)

- **Kill Bill** (Apache-2.0) for subscriptions, proration, invoices, dunning, credits, taxes (plug-ins), multiple
  currencies; payment gateways through Kill Bill plug-ins (Stripe, Adyen, PayPal, Braintree…), so card data never
  touches Matura (PCI scope stays with the gateway).
- Self-service checkout and plan changes in the tenant console; invoices and receipts emailed; enterprise invoicing
  with purchase orders and net terms.
- Revenue and churn reports in the platform console.
