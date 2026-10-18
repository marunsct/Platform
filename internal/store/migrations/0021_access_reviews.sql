-- Access reviews (TS11, technical specification §18.4): a tenant's owners and admins confirm, item by item, that
-- people and agents still need their app roles and their admin, billing or owner tenant role. At completion — by
-- hand, or at due_at — items marked revoke, and items nobody decided when on_pending is revoke, are revoked.
CREATE TABLE access_review (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name         text NOT NULL,
    status       text NOT NULL CHECK (status IN ('open','completed','cancelled')),
    on_pending   text NOT NULL DEFAULT 'revoke' CHECK (on_pending IN ('revoke','keep')),
    due_at       timestamptz NOT NULL,
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    completed_by uuid,                  -- NULL: completed by the deadline
    kept         integer NOT NULL DEFAULT 0,
    revoked      integer NOT NULL DEFAULT 0,
    version      bigint NOT NULL
);
CREATE INDEX access_review_due ON access_review (due_at) WHERE status = 'open';

CREATE TABLE access_review_item (
    id          uuid PRIMARY KEY,
    review_id   uuid NOT NULL REFERENCES access_review(id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('grant','tenant_role')),
    grant_id    uuid,                   -- kind grant
    user_id     uuid NOT NULL,          -- whose access it is
    app         text,                   -- kind grant
    role        text NOT NULL,          -- app role, or tenant role
    workspace_id uuid,
    decision    text NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','keep','revoke')),
    decided_by  uuid,
    decided_at  timestamptz,
    note        text,
    outcome     text                    -- at completion: kept, revoked, already_gone, last_owner_kept
);
CREATE INDEX access_review_item_review ON access_review_item (review_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['access_review','access_review_item'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;
