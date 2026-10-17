-- Matura contract tables (matura.contract.v1) for PostgreSQL 13+. Contract: docs/spec/03-app-integration-contract.md §3.
-- Run once in the app's database (or in each tenant's schema or database), with the app's migration tool.
-- Apply changes with the version rule (README.md here): keep a row only when the incoming version is newer.

CREATE TABLE IF NOT EXISTS matura_tenant (
    id uuid PRIMARY KEY, slug text NOT NULL UNIQUE, name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('company','shared','personal')),
    status text NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    plan text, data_mode text NOT NULL CHECK (data_mode IN ('shared','schema','database')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_workspace (
    id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES matura_tenant(id), name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active','archived','deleted')), is_default boolean NOT NULL DEFAULT false,
    version bigint NOT NULL, updated_at timestamptz NOT NULL, UNIQUE (tenant_id, id));
CREATE TABLE IF NOT EXISTS matura_user (
    id uuid PRIMARY KEY, email text, email_verified boolean NOT NULL DEFAULT false, display_name text,
    avatar_url text, locale text,
    kind text NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status text NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_membership (
    tenant_id uuid NOT NULL REFERENCES matura_tenant(id), user_id uuid NOT NULL REFERENCES matura_user(id),
    tenant_role text NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status text NOT NULL CHECK (status IN ('active','deactivated','removed')), joined_at timestamptz NOT NULL,
    version bigint NOT NULL, updated_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, user_id));
CREATE TABLE IF NOT EXISTS matura_role_grant (
    id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES matura_tenant(id), workspace_id uuid,
    subject_type text NOT NULL CHECK (subject_type IN ('user','group','service_account')), subject_id uuid NOT NULL,
    role text NOT NULL, status text NOT NULL CHECK (status IN ('active','revoked')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace(tenant_id, id));
CREATE INDEX IF NOT EXISTS matura_role_grant_subject ON matura_role_grant (tenant_id, subject_id) WHERE status = 'active';
CREATE TABLE IF NOT EXISTS matura_app_role (
    name text PRIMARY KEY, description text, permissions text[] NOT NULL, is_default boolean NOT NULL DEFAULT false,
    status text NOT NULL CHECK (status IN ('active','deleted')), version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_sync_cursor (stream text PRIMARY KEY, cursor text NOT NULL, synced_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_inbox (event_id text PRIMARY KEY, received_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_contract (version text PRIMARY KEY, applied_at timestamptz NOT NULL);
INSERT INTO matura_contract (version, applied_at) VALUES ('matura.contract.v1', now()) ON CONFLICT (version) DO NOTHING;
