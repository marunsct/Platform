-- Enterprise SSO (TS13): verified email domains and one SSO connection per tenant.

-- A domain is claimed by adding it (with a random challenge) and proven with a DNS TXT record at
-- _matura-challenge.<domain>. Several tenants may claim a domain; only one may hold it verified.
CREATE TABLE tenant_domain (
    tenant_id       uuid NOT NULL REFERENCES tenant(id),
    domain          text NOT NULL CHECK (domain = lower(domain)),
    challenge       text NOT NULL,
    verified_at     timestamptz,
    last_checked_at timestamptz,
    last_error      text,
    version         bigint NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain)
);
CREATE UNIQUE INDEX tenant_domain_verified ON tenant_domain (domain) WHERE verified_at IS NOT NULL;

-- The tenant's identity provider, mirrored into Keycloak as identity provider `alias` (t-<tenant slug>).
-- client_secret is sealed with the key-encryption key (associated data "tenant_sso:<tenant id>").
CREATE TABLE tenant_sso (
    tenant_id           uuid PRIMARY KEY REFERENCES tenant(id),
    alias               text NOT NULL UNIQUE,
    protocol            text NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    display_name        text NOT NULL,
    config              jsonb NOT NULL DEFAULT '{}',
    client_secret       bytea,
    default_tenant_role text NOT NULL DEFAULT 'member' CHECK (default_tenant_role IN ('admin', 'billing', 'member')),
    version             bigint NOT NULL,
    created_by          uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_domain','tenant_sso'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;
