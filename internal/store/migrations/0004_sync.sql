-- App credentials, change feed and webhooks (technical specification §8, contract §6–§7).

-- Outbox rows get a feed position when the sequencer sees them committed. bigserial ids follow insert order, not
-- commit order, so a reader using them could skip a row whose transaction commits late. The sequencer runs under
-- an advisory lock and only numbers committed rows, so `seq` grows in the order rows become visible.
CREATE SEQUENCE outbox_seq;
ALTER TABLE outbox ADD COLUMN seq bigint UNIQUE;
CREATE INDEX outbox_unsequenced ON outbox (id) WHERE seq IS NULL;

-- Everything up to pruned_through has been deleted; older cursors must take a snapshot (410).
CREATE TABLE outbox_horizon (
    only_row       boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    pruned_through bigint NOT NULL DEFAULT 0
);
INSERT INTO outbox_horizon DEFAULT VALUES;

-- Secrets an app backend uses to call /v1/apps/{app}/… (HTTP Basic: client id and secret). Only a SHA-256 of the
-- 32-byte random secret is stored.
CREATE TABLE app_secret (
    id           uuid PRIMARY KEY,
    app_id       uuid NOT NULL REFERENCES app(id) ON DELETE CASCADE,
    label        text NOT NULL DEFAULT '',
    secret_hash  bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX app_secret_app ON app_secret (app_id);

-- Webhook endpoints deliver the app's feed in order, one event per request, from their own cursor.
CREATE TABLE webhook_endpoint (
    id              uuid PRIMARY KEY,
    app_id          uuid NOT NULL REFERENCES app(id) ON DELETE CASCADE,
    url             text NOT NULL,
    secret          bytea NOT NULL,              -- sealed by the KeyManager; HMAC needs the secret itself
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','failing','disabled')),
    cursor          bigint NOT NULL,
    attempts        integer NOT NULL DEFAULT 0,  -- failed attempts for the event at the cursor
    first_failed_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_status     integer,
    last_error      text,
    delivered       bigint NOT NULL DEFAULT 0,
    dropped         bigint NOT NULL DEFAULT 0,  -- events given up on after 24 hours; the feed still has them
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoint_due ON webhook_endpoint (next_attempt_at) WHERE status <> 'disabled';
