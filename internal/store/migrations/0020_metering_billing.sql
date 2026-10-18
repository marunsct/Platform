-- Metering, quotas and billing export (TS18, technical specification §22).

-- Usage an app reports for a tenant. event_id makes reporting idempotent (a retry is a duplicate, not new usage).
-- meter is "<app slug>.<name>", e.g. devflow.runs.
CREATE TABLE usage_event (
    seq          bigserial UNIQUE,              -- export order
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    app_id       uuid NOT NULL REFERENCES app(id),
    meter        text NOT NULL,
    quantity     bigint NOT NULL CHECK (quantity >= 0),
    event_id     text NOT NULL,
    occurred_at  timestamptz NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, app_id, event_id)
);
CREATE INDEX usage_event_meter ON usage_event (tenant_id, meter, occurred_at);

-- Running totals per meter and period (month, day or total), updated in the transaction that records usage, so a
-- quota check reads one locked row.
CREATE TABLE usage_counter (
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    meter        text NOT NULL,
    period       text NOT NULL CHECK (period IN ('month','day','total')),
    period_start timestamptz NOT NULL,
    quantity     bigint NOT NULL DEFAULT 0,
    notified_pct integer NOT NULL DEFAULT 0,    -- highest threshold (80, 100) already announced this period
    PRIMARY KEY (tenant_id, meter, period, period_start)
);

-- The tenant's customer (and subscription) in the billing system.
CREATE TABLE billing_customer (
    tenant_id       uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('stripe','lago','openmeter')),
    customer_id     text NOT NULL,
    subscription_id text,
    version         bigint NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['usage_event','usage_counter','billing_customer'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;

-- How far usage was exported to each billing provider (installation-wide, operators only).
CREATE TABLE billing_export (
    provider     text PRIMARY KEY,
    cursor       bigint NOT NULL DEFAULT 0,
    exported     bigint NOT NULL DEFAULT 0,
    skipped      bigint NOT NULL DEFAULT 0,       -- usage of tenants without a billing customer
    last_error   text,
    last_run_at  timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
