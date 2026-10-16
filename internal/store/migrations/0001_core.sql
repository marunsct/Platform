-- Matura control plane, core schema (technical specification §3).
-- Runs as the owner role. maturad itself connects as matura_app, which has no BYPASSRLS, so the policies below
-- apply to every query it makes. A missing matura.tenant_id setting matches no rows (fail closed).

CREATE SEQUENCE matura_version_seq;

CREATE TABLE tenant (
    id                uuid PRIMARY KEY,
    slug              text NOT NULL UNIQUE,
    name              text NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('company','shared','personal')),
    status            text NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    plan              text,
    data_mode_default text NOT NULL DEFAULT 'shared' CHECK (data_mode_default IN ('shared','schema','database')),
    home_region       text,
    version           bigint NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    name        text NOT NULL,
    status      text NOT NULL CHECK (status IN ('active','archived','deleted')),
    is_default  boolean NOT NULL DEFAULT false,
    version     bigint NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX workspace_one_default ON workspace (tenant_id) WHERE is_default;

CREATE TABLE app_user (
    id             uuid PRIMARY KEY,               -- Keycloak user id, the token's sub
    email          text UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    display_name   text,
    avatar_url     text,
    locale         text,
    kind           text NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status         text NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version        bigint NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE membership (
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    user_id     uuid NOT NULL REFERENCES app_user(id),
    tenant_role text NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status      text NOT NULL CHECK (status IN ('active','deactivated','removed')),
    joined_at   timestamptz NOT NULL DEFAULT now(),
    version     bigint NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX membership_user ON membership (user_id);

CREATE TABLE app (
    id         uuid PRIMARY KEY,
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    client_id  text NOT NULL UNIQUE,
    manifest   jsonb NOT NULL,
    status     text NOT NULL CHECK (status IN ('active','disabled')),
    version    bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_role (
    app_id      uuid NOT NULL REFERENCES app(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text,
    permissions text[] NOT NULL DEFAULT '{}',
    is_default  boolean NOT NULL DEFAULT false,
    version     bigint NOT NULL,
    PRIMARY KEY (app_id, name)
);

CREATE TABLE tenant_app (
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    app_id     uuid NOT NULL REFERENCES app(id),
    status     text NOT NULL CHECK (status IN ('enabled','disabled')),
    version    bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, app_id)
);

CREATE TABLE role_grant (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    app_id       uuid NOT NULL REFERENCES app(id),
    workspace_id uuid,
    subject_type text NOT NULL CHECK (subject_type IN ('user','group','service_account')),
    subject_id   uuid NOT NULL,
    role         text NOT NULL,
    status       text NOT NULL CHECK (status IN ('active','revoked')),
    version      bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspace(tenant_id, id),
    FOREIGN KEY (app_id, role) REFERENCES app_role(app_id, name)
);
CREATE UNIQUE INDEX role_grant_unique_active ON role_grant
    (tenant_id, app_id, coalesce(workspace_id, '00000000-0000-0000-0000-000000000000'), subject_type, subject_id, role)
    WHERE status = 'active';
CREATE INDEX role_grant_subject ON role_grant (tenant_id, subject_id) WHERE status = 'active';

CREATE TABLE invitation (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    email       text NOT NULL,
    tenant_role text NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    app_roles   jsonb NOT NULL DEFAULT '[]',
    delivery    text NOT NULL CHECK (delivery IN ('link','temp_password')),
    deliver_to  text,
    token_hash  bytea NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    state       text NOT NULL CHECK (state IN ('pending','accepted','revoked','expired')),
    invited_by  uuid REFERENCES app_user(id),
    version     bigint NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitation_tenant ON invitation (tenant_id, state);

CREATE TABLE plan (
    id                 text PRIMARY KEY,
    name               text NOT NULL,
    data_mode_required text CHECK (data_mode_required IN ('shared','schema','database')),
    data_mode_default  text NOT NULL DEFAULT 'shared' CHECK (data_mode_default IN ('shared','schema','database')),
    limits             jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE db_server (
    id           uuid PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    host         text NOT NULL,
    port         integer NOT NULL DEFAULT 5432,
    admin_user   text NOT NULL,
    admin_secret bytea NOT NULL,
    region       text,
    dedicated    boolean NOT NULL DEFAULT false,
    labels       jsonb NOT NULL DEFAULT '{}',
    status       text NOT NULL CHECK (status IN ('active','draining','disabled')),
    version      bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE placement (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenant(id),
    app_id         uuid NOT NULL REFERENCES app(id),
    mode           text NOT NULL CHECK (mode IN ('shared','schema','database')),
    manager        text NOT NULL CHECK (manager IN ('app','platform')),
    db_server_id   uuid REFERENCES db_server(id),
    database_name  text,
    schema_name    text,
    role_name      text,
    role_secret    bytea,
    location_label text,
    state          text NOT NULL CHECK (state IN ('requested','provisioning','provisioned','migrating','ready',
                                                  'moving','retiring','deleted','failed')),
    error          text,
    version        bigint NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id)
);

CREATE TABLE outbox (
    id         bigserial PRIMARY KEY,
    version    bigint NOT NULL,
    tenant_id  uuid,
    type       text NOT NULL,
    subject    text NOT NULL,
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_tenant ON outbox (tenant_id, id);

-- Row-level security ---------------------------------------------------------------------------------------------

CREATE FUNCTION matura_current_tenant() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('matura.tenant_id', true), '')::uuid $$;
CREATE FUNCTION matura_current_user() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('matura.user_id', true), '')::uuid $$;
CREATE FUNCTION matura_is_operator() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('matura.scope', true), '') = 'operator' $$;

ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE ROW LEVEL SECURITY;
-- a tenant is visible in its own context, to its members (for "my tenants"), and to operators
CREATE POLICY tenant_isolation ON tenant
    USING (id = matura_current_tenant() OR matura_is_operator()
           OR id IN (SELECT m.tenant_id FROM membership m
                     WHERE m.user_id = matura_current_user() AND m.status = 'active'))
    WITH CHECK (id = matura_current_tenant() OR matura_is_operator());

ALTER TABLE membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE membership FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON membership
    USING (tenant_id = matura_current_tenant() OR matura_is_operator() OR user_id = matura_current_user())
    WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator());

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workspace','tenant_app','role_grant','invitation','placement'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = matura_current_tenant() OR matura_is_operator())
                          WITH CHECK (tenant_id = matura_current_tenant() OR matura_is_operator())', t);
    END LOOP;
END $$;
