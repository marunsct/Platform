-- SCIM 2.0 provisioning (TS14, technical specification §19): bearer tokens per tenant, provisioned users, groups,
-- group-to-role mappings and the grants those mappings created.

-- Changes made through SCIM are audited with actor kind `scim` (actor id: the token).
ALTER TABLE audit_event DROP CONSTRAINT audit_event_actor_kind_check;
ALTER TABLE audit_event ADD CONSTRAINT audit_event_actor_kind_check
    CHECK (actor_kind IN ('user','operator','app','system','scim'));

-- Only the SHA-256 of a token is kept; prefix is its first characters, to tell tokens apart in lists.
CREATE TABLE scim_token (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    name         text NOT NULL,
    hash         bytea NOT NULL UNIQUE,
    prefix       text NOT NULL,
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX scim_token_tenant ON scim_token (tenant_id);

-- A person the tenant's identity provider provisioned. user_id is the Matura (and Keycloak) user id, which is also
-- the SCIM resource id. created_account: SCIM created the Keycloak account (rather than linking an existing one).
CREATE TABLE scim_user (
    tenant_id       uuid NOT NULL REFERENCES tenant(id),
    user_id         uuid NOT NULL REFERENCES app_user(id),
    user_name       text NOT NULL,
    external_id     text,
    active          boolean NOT NULL DEFAULT true,
    email           text NOT NULL,
    emails          jsonb NOT NULL DEFAULT '[]',
    given_name      text,
    family_name     text,
    display_name    text,
    enterprise      jsonb NOT NULL DEFAULT '{}',
    extra           jsonb NOT NULL DEFAULT '{}',
    created_account boolean NOT NULL DEFAULT false,
    version         bigint NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE UNIQUE INDEX scim_user_name ON scim_user (tenant_id, lower(user_name));
CREATE UNIQUE INDEX scim_user_external ON scim_user (tenant_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE scim_group (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    display_name text NOT NULL,
    external_id  text,
    version      bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX scim_group_name ON scim_group (tenant_id, lower(display_name));

CREATE TABLE scim_group_member (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    user_id   uuid NOT NULL,
    PRIMARY KEY (tenant_id, group_id, user_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES scim_group (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES scim_user (tenant_id, user_id) ON DELETE CASCADE
);
CREATE INDEX scim_group_member_user ON scim_group_member (tenant_id, user_id);

-- Members of the group named group_name (case-insensitive) get the app role for the whole tenant.
CREATE TABLE scim_group_mapping (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    group_name text NOT NULL,
    app_id     uuid NOT NULL REFERENCES app(id),
    role       text NOT NULL,
    version    bigint NOT NULL,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scim_group_mapping_unique ON scim_group_mapping (tenant_id, lower(group_name), app_id, role);

-- Grants created because of group membership; only these are revoked when the membership or mapping goes away.
CREATE TABLE scim_managed_grant (
    tenant_id uuid NOT NULL,
    grant_id  uuid NOT NULL,
    user_id   uuid NOT NULL,
    PRIMARY KEY (tenant_id, grant_id)
);
CREATE INDEX scim_managed_grant_user ON scim_managed_grant (tenant_id, user_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['scim_token','scim_user','scim_group','scim_group_member','scim_group_mapping',
                             'scim_managed_grant'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;
