-- Database servers keep a fingerprint of their admin secret for display, and an SSL mode for connecting.
ALTER TABLE db_server
    ADD COLUMN admin_secret_fingerprint text NOT NULL DEFAULT '',
    ADD COLUMN sslmode text NOT NULL DEFAULT 'require'
        CHECK (sslmode IN ('disable','allow','prefer','require','verify-ca','verify-full'));

-- Idempotency keys for POST requests (technical specification §2). A key is claimed before the handler runs, so a
-- retry that races the first attempt gets 409 instead of running twice; the response is kept for 24 hours.
CREATE TABLE idempotency_key (
    principal    uuid NOT NULL,
    key          text NOT NULL,
    request_hash bytea NOT NULL,
    status       integer,                 -- NULL while the first attempt is running
    response     bytea,
    content_type text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, key)
);
CREATE INDEX idempotency_key_created ON idempotency_key (created_at);
