-- Operator console (TS10): tenant lifecycle with a deletion grace period, plan entitlements with per-tenant
-- overrides, and support access that a tenant can see and approve.

-- pending_deletion: deleted by an owner or operator, restorable until purge_after; the purger then moves the tenant
-- to deleting (apps delete its data, placements are retired) and, once every placement is gone, to deleted.
-- restore_status is the status a restore returns to (a suspended tenant stays suspended).
ALTER TABLE tenant DROP CONSTRAINT tenant_status_check;
ALTER TABLE tenant ADD CONSTRAINT tenant_status_check
    CHECK (status IN ('provisioning','active','suspended','pending_deletion','deleting','deleted'));
ALTER TABLE tenant
    ADD COLUMN status_reason         text,
    ADD COLUMN purge_after           timestamptz,
    ADD COLUMN restore_status        text,
    ADD COLUMN entitlement_overrides jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN support_access        text NOT NULL DEFAULT 'approval'
        CHECK (support_access IN ('approval','allowed','off'));
CREATE INDEX tenant_purge_due ON tenant (purge_after) WHERE status = 'pending_deletion';
CREATE INDEX tenant_deleting ON tenant (id) WHERE status = 'deleting';

-- Time-boxed, read-only access of one operator to one tenant's admin views. Rows are never deleted: they are the
-- tenant's record of every request, decision and use.
CREATE TABLE support_access (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenant(id),
    operator_id      uuid NOT NULL REFERENCES app_user(id),
    reason           text NOT NULL,
    duration_minutes integer NOT NULL CHECK (duration_minutes BETWEEN 1 AND 480),
    state            text NOT NULL CHECK (state IN ('pending','approved','denied','revoked','ended')),
    auto_approved    boolean NOT NULL DEFAULT false,
    requested_at     timestamptz NOT NULL DEFAULT now(),
    decided_by       uuid REFERENCES app_user(id),
    decided_at       timestamptz,
    starts_at        timestamptz,
    expires_at       timestamptz,
    ended_by         uuid REFERENCES app_user(id),
    ended_at         timestamptz,
    last_used_at     timestamptz,
    uses             integer NOT NULL DEFAULT 0
);
CREATE INDEX support_access_tenant ON support_access (tenant_id, requested_at DESC);
CREATE INDEX support_access_active ON support_access (tenant_id, operator_id, expires_at) WHERE state = 'approved';

ALTER TABLE support_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_access FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON support_access
    USING (tenant_id = matura_current_tenant() OR matura_is_operator())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());
