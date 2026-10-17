-- Tenant data export, user erasure in the audit log, and audit retention with legal hold (TS17, technical
-- specification §14).

-- An export job and, once ready, its bundle (JSON, at most store.MaxExportBytes). The privacy worker builds it
-- and clears the bundle when it expires.
CREATE TABLE tenant_export (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    requested_by uuid REFERENCES app_user(id),
    state        text NOT NULL CHECK (state IN ('queued','running','ready','failed','expired')),
    size_bytes   bigint,
    sha256       bytea,
    bundle       bytea,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    expires_at   timestamptz
);
CREATE INDEX tenant_export_tenant ON tenant_export (tenant_id, created_at);
CREATE INDEX tenant_export_due ON tenant_export (created_at) WHERE state IN ('queued','running');
-- one export at a time per tenant
CREATE UNIQUE INDEX tenant_export_one_active ON tenant_export (tenant_id) WHERE state IN ('queued','running');

-- Audit retention per tenant (absent: the default, 400 days, no hold).
CREATE TABLE audit_retention (
    tenant_id         uuid PRIMARY KEY REFERENCES tenant(id),
    retention_days    integer NOT NULL DEFAULT 400 CHECK (retention_days >= 0),
    legal_hold        boolean NOT NULL DEFAULT false,
    legal_hold_reason text,
    version           bigint NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_export','audit_retention'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;

-- Erased users. Audit events are hashed, so they are never edited: readers (list, export, streaming, tenant
-- export) replace the user's email and name with the pseudonym on the way out, and verification reads the stored
-- rows. Only hashes of the values are kept here, so this table does not itself hold the data it hides.
CREATE TABLE audit_redaction (
    user_id    uuid PRIMARY KEY,
    pseudonym  text NOT NULL,          -- deleted-user-<first 12 hex of sha256(user id)>
    email_hash bytea,                  -- sha256(lower(email))
    name_hash  bytea,                  -- sha256(lower(display name))
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_redaction_email ON audit_redaction (email_hash);

-- The chain's anchor: events up to anchor_seq were purged by retention, and anchor_hash is the hash of the last
-- one, which the first remaining event's prev_hash must equal. Verification starts there.
ALTER TABLE audit_chain ADD COLUMN anchor_seq bigint NOT NULL DEFAULT 0;
ALTER TABLE audit_chain ADD COLUMN anchor_hash bytea;

-- The runtime role may update a chain's head but not its anchor: moving the anchor would hide events from
-- verification. Only the owner (through matura_audit_purge) may.
CREATE FUNCTION matura_audit_anchor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (TG_OP = 'INSERT' AND (NEW.anchor_seq <> 0 OR NEW.anchor_hash IS NOT NULL)
        OR TG_OP = 'UPDATE' AND (NEW.anchor_seq, NEW.anchor_hash) IS DISTINCT FROM (OLD.anchor_seq, OLD.anchor_hash))
       AND NOT pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = 'audit_chain'::regclass), 'USAGE')
    THEN
        RAISE EXCEPTION 'the audit chain anchor moves only through matura_audit_purge' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER audit_chain_anchor_guard BEFORE INSERT OR UPDATE ON audit_chain
    FOR EACH ROW EXECUTE FUNCTION matura_audit_anchor_guard();

-- The runtime role cannot delete audit events (Migrate revokes it). Retention runs through this function, which
-- runs as the owner and decides itself what may go: only a prefix of the chain older than the tenant's retention,
-- never under legal hold. The DELETE policy is for the owner role alone.
DO $$
BEGIN
    EXECUTE format('CREATE POLICY audit_retention_purge ON audit_event FOR DELETE TO %I USING (tenant_id IS NOT NULL)',
                   current_user);
END $$;

CREATE FUNCTION matura_audit_purge(p_tenant uuid) RETURNS TABLE (purged bigint, anchor_seq bigint, anchor_hash bytea)
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
REVOKE ALL ON FUNCTION matura_audit_purge(uuid) FROM PUBLIC;
