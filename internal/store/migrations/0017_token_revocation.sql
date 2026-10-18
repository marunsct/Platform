-- Instant revocation (technical specification §21). Access tokens live 5 minutes; a revocation makes maturad and
-- the SDKs refuse tokens issued at or before not_before for a user (or an agent: as sub or as act.sub), in one
-- tenant or everywhere (tenant_id NULL), for one session or all (session_id NULL). Rows are needed only while such
-- tokens could still be valid, so they are pruned an hour after not_before.
CREATE TABLE token_revocation (
    id          uuid PRIMARY KEY,
    tenant_id   uuid REFERENCES tenant(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL,
    session_id  text,
    not_before  timestamptz NOT NULL,
    reason      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX token_revocation_user ON token_revocation (user_id, not_before);
CREATE INDEX token_revocation_recent ON token_revocation (not_before);

ALTER TABLE token_revocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_revocation FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON token_revocation
    USING (tenant_id = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());
