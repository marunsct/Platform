-- Agent identity (TS15, technical specification §18): tenant service accounts and AI agents as principals.

-- Each agent is a Keycloak confidential client (client credentials, token exchange) whose service-account user is
-- the agent's app_user row (kind service or agent, the token's sub) and an active member of exactly one tenant, so
-- it holds app role grants like a person. The client secret lives only in Keycloak.
CREATE TABLE agent (
    id                uuid PRIMARY KEY REFERENCES app_user(id),
    tenant_id         uuid NOT NULL REFERENCES tenant(id),
    kind              text NOT NULL CHECK (kind IN ('service','agent')),
    name              text NOT NULL,
    description       text,
    owner_id          uuid REFERENCES app_user(id),
    client_id         text NOT NULL UNIQUE,       -- Keycloak clientId, the token's azp
    client_uuid       text NOT NULL,              -- Keycloak's internal id of that client
    status            text NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    expires_at        timestamptz,
    secret_rotated_at timestamptz NOT NULL DEFAULT now(),
    version           bigint NOT NULL,
    created_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_tenant ON agent (tenant_id, name) WHERE status <> 'deleted';

ALTER TABLE agent ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent
    USING (tenant_id = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());

-- Agents act in the audit log as themselves, and a delegated call also names the person it acts for.
ALTER TABLE audit_event DROP CONSTRAINT audit_event_actor_kind_check;
ALTER TABLE audit_event ADD CONSTRAINT audit_event_actor_kind_check
    CHECK (actor_kind IN ('user','operator','app','system','agent','service'));
ALTER TABLE audit_event ADD COLUMN actor_on_behalf_of uuid;
