-- Matura contract tables (matura.contract.v1) for SQL Server 2016+ and Azure SQL. Contract: docs/spec/03-app-integration-contract.md §3.
-- Run once in the app's database (or in each tenant's schema or database), with the app's migration tool.
-- Apply changes with the version rule (README.md here): keep a row only when the incoming version is newer.
-- No row-level security here (SQL Server has its own; the contract does not set it up): filter every query by
-- tenant_id, or use schema or database mode. Timestamps are UTC.

IF OBJECT_ID('matura_tenant') IS NULL
CREATE TABLE matura_tenant (
    id uniqueidentifier NOT NULL PRIMARY KEY,
    slug nvarchar(63) NOT NULL UNIQUE,
    name nvarchar(255) NOT NULL,
    kind nvarchar(16) NOT NULL CHECK (kind IN ('company','shared','personal')),
    status nvarchar(16) NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    [plan] nvarchar(64) NULL,
    data_mode nvarchar(16) NOT NULL CHECK (data_mode IN ('shared','schema','database')),
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL,
    placement_version bigint NOT NULL DEFAULT 0
);
IF COL_LENGTH('matura_tenant', 'placement_version') IS NULL
ALTER TABLE matura_tenant ADD placement_version bigint NOT NULL DEFAULT 0;
IF OBJECT_ID('matura_workspace') IS NULL
CREATE TABLE matura_workspace (
    id uniqueidentifier NOT NULL PRIMARY KEY,
    tenant_id uniqueidentifier NOT NULL REFERENCES matura_tenant (id),
    name nvarchar(255) NOT NULL,
    status nvarchar(16) NOT NULL CHECK (status IN ('active','archived','deleted')),
    is_default bit NOT NULL DEFAULT 0,
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL,
    CONSTRAINT matura_workspace_tenant UNIQUE (tenant_id, id)
);
IF OBJECT_ID('matura_user') IS NULL
CREATE TABLE matura_user (
    id uniqueidentifier NOT NULL PRIMARY KEY,
    email nvarchar(320) NULL,
    email_verified bit NOT NULL DEFAULT 0,
    display_name nvarchar(255) NULL,
    avatar_url nvarchar(2048) NULL,
    locale nvarchar(35) NULL,
    kind nvarchar(16) NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status nvarchar(16) NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL
);
IF OBJECT_ID('matura_membership') IS NULL
CREATE TABLE matura_membership (
    tenant_id uniqueidentifier NOT NULL REFERENCES matura_tenant (id),
    user_id uniqueidentifier NOT NULL REFERENCES matura_user (id),
    tenant_role nvarchar(16) NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status nvarchar(16) NOT NULL CHECK (status IN ('active','deactivated','removed')),
    joined_at datetime2(6) NOT NULL,
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
IF OBJECT_ID('matura_role_grant') IS NULL
CREATE TABLE matura_role_grant (
    id uniqueidentifier NOT NULL PRIMARY KEY,
    tenant_id uniqueidentifier NOT NULL REFERENCES matura_tenant (id),
    workspace_id uniqueidentifier NULL,
    subject_type nvarchar(16) NOT NULL CHECK (subject_type IN ('user','group','service_account')),
    subject_id uniqueidentifier NOT NULL,
    role nvarchar(64) NOT NULL,
    status nvarchar(16) NOT NULL CHECK (status IN ('active','revoked')),
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL,
    CONSTRAINT matura_role_grant_workspace FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace (tenant_id, id)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'matura_role_grant_subject')
CREATE INDEX matura_role_grant_subject ON matura_role_grant (tenant_id, subject_id) WHERE status = 'active';
IF OBJECT_ID('matura_app_role') IS NULL
CREATE TABLE matura_app_role (
    name nvarchar(64) NOT NULL PRIMARY KEY,
    description nvarchar(1024) NULL,
    permissions nvarchar(max) NOT NULL CHECK (ISJSON(permissions) = 1),
    is_default bit NOT NULL DEFAULT 0,
    status nvarchar(16) NOT NULL CHECK (status IN ('active','deleted')),
    version bigint NOT NULL,
    updated_at datetime2(6) NOT NULL
);
IF OBJECT_ID('matura_sync_cursor') IS NULL
CREATE TABLE matura_sync_cursor (
    stream nvarchar(64) NOT NULL PRIMARY KEY,
    cursor_value nvarchar(255) NOT NULL,
    synced_at datetime2(6) NOT NULL
);
IF OBJECT_ID('matura_inbox') IS NULL
CREATE TABLE matura_inbox (
    event_id nvarchar(128) NOT NULL PRIMARY KEY,
    received_at datetime2(6) NOT NULL
);
IF OBJECT_ID('matura_contract') IS NULL
CREATE TABLE matura_contract (
    version nvarchar(32) NOT NULL PRIMARY KEY,
    applied_at datetime2(6) NOT NULL
);
IF NOT EXISTS (SELECT 1 FROM matura_contract WHERE version = 'matura.contract.v1')
INSERT INTO matura_contract (version, applied_at) VALUES ('matura.contract.v1', SYSUTCDATETIME());
