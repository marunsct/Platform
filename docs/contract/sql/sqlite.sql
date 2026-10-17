-- Matura contract tables (matura.contract.v1) for SQLite 3.24+ (tests, desktop and local editions; no row-level security). Contract: docs/spec/03-app-integration-contract.md §3.
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
