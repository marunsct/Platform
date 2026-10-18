-- Consent for agents acting on a person's behalf (technical specification §20.5). An agent with consent `required`
-- gets a delegated token for a person only while that person's consent is active; consent may narrow it to some
-- permissions and may expire. `implicit` (the default, the TS15 behaviour) trusts the tenant admin who created the
-- agent for every member.
ALTER TABLE agent ADD COLUMN consent text NOT NULL DEFAULT 'implicit' CHECK (consent IN ('implicit','required'));

CREATE TABLE agent_consent (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    agent_id      uuid NOT NULL REFERENCES agent(id),
    user_id       uuid NOT NULL REFERENCES app_user(id),
    permissions   text[],                       -- NULL: everything both may do; otherwise only these
    status        text NOT NULL CHECK (status IN ('active','withdrawn')),
    granted_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    withdrawn_at  timestamptz,
    withdrawn_by  uuid,
    version       bigint NOT NULL
);
CREATE UNIQUE INDEX agent_consent_active ON agent_consent (agent_id, user_id) WHERE status = 'active';
CREATE INDEX agent_consent_user ON agent_consent (user_id) WHERE status = 'active';

ALTER TABLE agent_consent ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_consent FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_consent
    USING (tenant_id = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());

-- A revocation for one agent acting for one person (consent withdrawn): tokens whose sub is user_id and act.sub is
-- actor_id. NULL: any token of user_id, as sub or as act.sub.
ALTER TABLE token_revocation ADD COLUMN actor_id uuid;
