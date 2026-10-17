/**
 * The contract DDL, copied verbatim from docs/contract/sql/ (test/contract.test.ts checks they stay identical).
 */

/** docs/contract/sql/postgres.sql */
export const POSTGRES_SQL = `-- Matura contract tables (matura.contract.v1) for PostgreSQL 13+. Contract: docs/spec/03-app-integration-contract.md §3.
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
`;

/** docs/contract/sql/postgres-shared-rls.sql */
export const POSTGRES_SHARED_RLS_SQL = `-- Shared mode only (one database for all tenants): row-level security on the contract tables (PostgreSQL).
-- Each transaction sets the tenant: SELECT set_config('matura.tenant_id', '<tid>', true). The app's runtime role must
-- not own these tables or have BYPASSRLS; the sync job that applies events runs as a role that may (or sets the tenant
-- of each event). Apply the same policy to the app's own tables that carry tenant_id.

ALTER TABLE matura_tenant ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_tenant FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON matura_tenant;
CREATE POLICY tenant_isolation ON matura_tenant USING (id = nullif(current_setting('matura.tenant_id', true), '')::uuid);
ALTER TABLE matura_workspace ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_workspace FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON matura_workspace;
CREATE POLICY tenant_isolation ON matura_workspace USING (tenant_id = nullif(current_setting('matura.tenant_id', true), '')::uuid);
ALTER TABLE matura_membership ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_membership FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON matura_membership;
CREATE POLICY tenant_isolation ON matura_membership USING (tenant_id = nullif(current_setting('matura.tenant_id', true), '')::uuid);
ALTER TABLE matura_role_grant ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_role_grant FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON matura_role_grant;
CREATE POLICY tenant_isolation ON matura_role_grant USING (tenant_id = nullif(current_setting('matura.tenant_id', true), '')::uuid);
ALTER TABLE matura_user ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_user FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON matura_user;
CREATE POLICY tenant_isolation ON matura_user USING (EXISTS (SELECT 1 FROM matura_membership m
    WHERE m.user_id = matura_user.id AND m.tenant_id = nullif(current_setting('matura.tenant_id', true), '')::uuid));
`;

/** docs/contract/sql/sqlite.sql */
export const SQLITE_SQL = `-- Matura contract tables (matura.contract.v1) for SQLite 3.24+ (tests, desktop and local editions; no row-level security). Contract: docs/spec/03-app-integration-contract.md §3.
-- Run once in the app's database (or in each tenant's schema or database), with the app's migration tool.
-- Apply changes with the version rule (README.md here): keep a row only when the incoming version is newer.

CREATE TABLE IF NOT EXISTS matura_tenant (
    id text PRIMARY KEY, slug text NOT NULL UNIQUE, name text NOT NULL, kind text NOT NULL, status text NOT NULL,
    plan text, data_mode text NOT NULL, version integer NOT NULL, updated_at text NOT NULL);
CREATE TABLE IF NOT EXISTS matura_workspace (
    id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES matura_tenant(id), name text NOT NULL,
    status text NOT NULL, is_default boolean NOT NULL DEFAULT 0, version integer NOT NULL, updated_at text NOT NULL,
    UNIQUE (tenant_id, id));
CREATE TABLE IF NOT EXISTS matura_user (
    id text PRIMARY KEY, email text, email_verified boolean NOT NULL DEFAULT 0, display_name text, avatar_url text,
    locale text, kind text NOT NULL DEFAULT 'human', status text NOT NULL, version integer NOT NULL,
    updated_at text NOT NULL);
CREATE TABLE IF NOT EXISTS matura_membership (
    tenant_id text NOT NULL REFERENCES matura_tenant(id), user_id text NOT NULL REFERENCES matura_user(id),
    tenant_role text NOT NULL, status text NOT NULL, joined_at text NOT NULL, version integer NOT NULL,
    updated_at text NOT NULL, PRIMARY KEY (tenant_id, user_id));
CREATE TABLE IF NOT EXISTS matura_role_grant (
    id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES matura_tenant(id), workspace_id text,
    subject_type text NOT NULL, subject_id text NOT NULL, role text NOT NULL, status text NOT NULL,
    version integer NOT NULL, updated_at text NOT NULL);
CREATE INDEX IF NOT EXISTS matura_role_grant_subject ON matura_role_grant (tenant_id, subject_id);
CREATE TABLE IF NOT EXISTS matura_app_role (
    name text PRIMARY KEY, description text, permissions text NOT NULL, is_default boolean NOT NULL DEFAULT 0,
    status text NOT NULL, version integer NOT NULL, updated_at text NOT NULL);
CREATE TABLE IF NOT EXISTS matura_sync_cursor (stream text PRIMARY KEY, cursor text NOT NULL, synced_at text NOT NULL);
CREATE TABLE IF NOT EXISTS matura_inbox (event_id text PRIMARY KEY, received_at text NOT NULL);
CREATE TABLE IF NOT EXISTS matura_contract (version text PRIMARY KEY, applied_at text NOT NULL);
INSERT INTO matura_contract (version, applied_at) VALUES ('matura.contract.v1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) ON CONFLICT (version) DO NOTHING;
`;
