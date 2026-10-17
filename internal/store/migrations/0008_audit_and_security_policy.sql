-- Audit log, audit streaming and tenant security policies (TS9, technical specification §13).

-- One hash chain per tenant, and one for installation events (tenant_id NULL). seq is the position in the chain;
-- hash is SHA-256 over the event's canonical JSON, which includes prev_hash (store/audit.go). The runtime role may
-- insert and read but never update or delete (no policy for either, and Migrate revokes the grants).
CREATE TABLE audit_event (
    id          bigserial PRIMARY KEY,
    tenant_id   uuid,
    seq         bigint NOT NULL,
    time        timestamptz NOT NULL,
    actor_kind  text NOT NULL CHECK (actor_kind IN ('user','operator','app','system')),
    actor_id    uuid,
    actor_email text,
    action      text NOT NULL,
    target      text NOT NULL DEFAULT '',
    request_id  text,
    ip          text,
    user_agent  text,
    data        jsonb NOT NULL DEFAULT '{}',
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL
);
CREATE UNIQUE INDEX audit_event_chain ON audit_event
    (coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'), seq);
CREATE INDEX audit_event_tenant ON audit_event (tenant_id, id);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_event FOR SELECT
    USING (tenant_id = matura_current_tenant() OR matura_is_operator());
CREATE POLICY audit_append ON audit_event FOR INSERT
    WITH CHECK (tenant_id IS NULL OR tenant_id = matura_current_tenant() OR matura_is_operator());

-- The head of each chain. Writers lock its row, so a chain grows one event at a time; verification also compares
-- the last event with the head, so a deleted tail shows.
CREATE TABLE audit_chain (
    chain uuid PRIMARY KEY,   -- tenant id, or the nil uuid for installation events
    seq   bigint NOT NULL,
    hash  bytea NOT NULL
);
ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_chain
    USING (chain = '00000000-0000-0000-0000-000000000000' OR chain = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (chain = '00000000-0000-0000-0000-000000000000' OR chain = matura_current_tenant() OR matura_is_operator());

-- Audit streaming destinations a tenant configures. cursor is the last chain seq delivered.
CREATE TABLE audit_sink (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenant(id),
    kind            text NOT NULL DEFAULT 'webhook' CHECK (kind IN ('webhook')),
    url             text NOT NULL,
    secret          bytea NOT NULL,             -- sealed by the KeyManager
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','failing','disabled')),
    cursor          bigint NOT NULL DEFAULT 0,
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_status     integer,
    last_error      text,
    delivered       bigint NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_sink_due ON audit_sink (next_attempt_at) WHERE status <> 'disabled';

-- Security policy per tenant. maturad enforces allowed_email_domains (invitations) and ip_allowlist (tenant API);
-- Keycloak enforces require_mfa and the session limits (seconds; NULL is the installation default).
CREATE TABLE security_policy (
    tenant_id             uuid PRIMARY KEY REFERENCES tenant(id),
    require_mfa           boolean NOT NULL DEFAULT false,
    session_max_age       integer,
    idle_timeout          integer,
    allowed_email_domains text[] NOT NULL DEFAULT '{}',
    ip_allowlist          cidr[] NOT NULL DEFAULT '{}',
    version               bigint NOT NULL,
    updated_at            timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['audit_sink','security_policy'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;
