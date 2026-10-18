-- Per-tenant data-encryption keys and customer-managed keys (TS17, technical specification §9.2). Each tenant has
-- a 256-bit tenant key per version; tenant secrets (SSO client secret, audit stream secrets, placement passwords,
-- export bundles) and the data keys apps use for field encryption are sealed under it. The tenant key itself is
-- sealed by the installation's key ring, or by the tenant's own key (BYOK) when it set one. Destroying a tenant's
-- keys (when it is deleted) makes everything sealed under them unreadable, in backups too (crypto-shredding).
CREATE TABLE tenant_key (
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    version      integer NOT NULL CHECK (version > 0),
    wrapped      bytea,                    -- NULL once destroyed
    sealed_by    text NOT NULL CHECK (sealed_by IN ('installation','customer')),
    status       text NOT NULL CHECK (status IN ('active','retired','destroyed')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    destroyed_at timestamptz,
    PRIMARY KEY (tenant_id, version),
    CHECK ((status = 'destroyed') = (wrapped IS NULL))
);
CREATE UNIQUE INDEX tenant_key_active ON tenant_key (tenant_id) WHERE status = 'active';

-- The tenant's own key-encryption key. config holds the provider's settings, sealed by the installation's ring
-- (a transit token is a secret); key_ref is shown.
CREATE TABLE tenant_key_provider (
    tenant_id  uuid PRIMARY KEY REFERENCES tenant(id),
    provider   text NOT NULL CHECK (provider IN ('transit','awskms','gcpkms','azurekv')),
    key_ref    text NOT NULL,
    config     bytea NOT NULL,
    version    bigint NOT NULL,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_key','tenant_key_provider'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;

-- Export bundles may now be sealed under the tenant key (bytea already); nothing to change in tenant_export.
