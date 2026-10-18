-- Human oversight of AI agents (TS15, technical specification §20.6): apps record approvals, rejections, overrides
-- and interventions by people on what agents do; each is an audit event mapped to EU AI Act Articles 12, 14 and 26.
-- event_id makes recording idempotent.
CREATE TABLE agent_oversight (
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    app_id      uuid NOT NULL REFERENCES app(id),
    event_id    text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('approval','rejection','override','intervention','stop')),
    agent_id    uuid NOT NULL,
    person_id   uuid NOT NULL,
    action      text NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, app_id, event_id)
);
CREATE INDEX agent_oversight_recent ON agent_oversight (tenant_id, occurred_at);
ALTER TABLE agent_oversight ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_oversight FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_oversight
    USING (tenant_id = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());

-- Audit retention: tenants with agents keep six months at least, whatever their setting.
CREATE OR REPLACE FUNCTION matura_audit_purge(p_tenant uuid) RETURNS TABLE (purged bigint, anchor_seq bigint, anchor_hash bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_days  integer;
    v_hold  boolean;
    v_head  bigint;
    v_first bigint;
    v_upto  bigint;
    v_hash  bytea;
    v_n     bigint;
BEGIN
    IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM matura_current_tenant() THEN
        RAISE EXCEPTION 'matura_audit_purge: the tenant must be the transaction''s tenant' USING ERRCODE = '42501';
    END IF;
    SELECT r.retention_days, r.legal_hold INTO v_days, v_hold FROM audit_retention r WHERE r.tenant_id = p_tenant;
    v_days := coalesce(v_days, 400);
    -- a tenant with AI agents keeps at least six months (EU AI Act Art. 26(6), §20.6)
    IF EXISTS (SELECT 1 FROM agent a WHERE a.tenant_id = p_tenant AND a.status <> 'deleted') THEN
        v_days := greatest(v_days, 183);
    END IF;
    IF coalesce(v_hold, false) THEN
        RETURN QUERY SELECT 0::bigint, NULL::bigint, NULL::bytea;
        RETURN;
    END IF;
    SELECT c.seq INTO v_head FROM audit_chain c WHERE c.chain = p_tenant FOR UPDATE;
    IF v_head IS NULL THEN
        RETURN QUERY SELECT 0::bigint, NULL::bigint, NULL::bytea;
        RETURN;
    END IF;
    -- only a prefix: stop before the first event still inside the retention period
    SELECT min(e.seq) INTO v_first FROM audit_event e
        WHERE e.tenant_id = p_tenant AND e.time >= now() - make_interval(days => v_days);
    v_upto := coalesce(v_first - 1, v_head);
    SELECT e.hash INTO v_hash FROM audit_event e WHERE e.tenant_id = p_tenant AND e.seq = v_upto;
    IF v_hash IS NULL THEN  -- nothing older than the retention period is left
        RETURN QUERY SELECT 0::bigint, NULL::bigint, NULL::bytea;
        RETURN;
    END IF;
    DELETE FROM audit_event e WHERE e.tenant_id = p_tenant AND e.seq <= v_upto;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    UPDATE audit_chain c SET anchor_seq = v_upto, anchor_hash = v_hash WHERE c.chain = p_tenant;
    RETURN QUERY SELECT v_n, v_upto, v_hash;
END $$;
