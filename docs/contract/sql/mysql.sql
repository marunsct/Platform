-- Matura contract tables (matura.contract.v1) for MySQL 8.0.16+ and MariaDB 10.5+. Contract: docs/spec/03-app-integration-contract.md §3.
-- Run once in the app's database (or in each tenant's database), with the app's migration tool.
-- Apply changes with the version rule (README.md here): keep a row only when the incoming version is newer.
-- No row-level security here: filter every query by tenant_id, or use schema or database mode.
-- Ids are UUIDs as text (char(36)); timestamps are UTC.

CREATE TABLE IF NOT EXISTS matura_tenant (
    id char(36) NOT NULL PRIMARY KEY,
    slug varchar(63) NOT NULL UNIQUE,
    name varchar(255) NOT NULL,
    kind varchar(16) NOT NULL CHECK (kind IN ('company','shared','personal')),
    status varchar(16) NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    plan varchar(64),
    data_mode varchar(16) NOT NULL CHECK (data_mode IN ('shared','schema','database')),
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL
);
CREATE TABLE IF NOT EXISTS matura_workspace (
    id char(36) NOT NULL PRIMARY KEY,
    tenant_id char(36) NOT NULL,
    name varchar(255) NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('active','archived','deleted')),
    is_default boolean NOT NULL DEFAULT false,
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL,
    UNIQUE KEY matura_workspace_tenant (tenant_id, id),
    CONSTRAINT matura_workspace_tenant_fk FOREIGN KEY (tenant_id) REFERENCES matura_tenant (id)
);
CREATE TABLE IF NOT EXISTS matura_user (
    id char(36) NOT NULL PRIMARY KEY,
    email varchar(320),
    email_verified boolean NOT NULL DEFAULT false,
    display_name varchar(255),
    avatar_url varchar(2048),
    locale varchar(35),
    kind varchar(16) NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status varchar(16) NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL
);
CREATE TABLE IF NOT EXISTS matura_membership (
    tenant_id char(36) NOT NULL,
    user_id char(36) NOT NULL,
    tenant_role varchar(16) NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status varchar(16) NOT NULL CHECK (status IN ('active','deactivated','removed')),
    joined_at datetime(6) NOT NULL,
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT matura_membership_tenant_fk FOREIGN KEY (tenant_id) REFERENCES matura_tenant (id),
    CONSTRAINT matura_membership_user_fk FOREIGN KEY (user_id) REFERENCES matura_user (id)
);
CREATE TABLE IF NOT EXISTS matura_role_grant (
    id char(36) NOT NULL PRIMARY KEY,
    tenant_id char(36) NOT NULL,
    workspace_id char(36),
    subject_type varchar(16) NOT NULL CHECK (subject_type IN ('user','group','service_account')),
    subject_id char(36) NOT NULL,
    role varchar(64) NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('active','revoked')),
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL,
    KEY matura_role_grant_subject (tenant_id, subject_id, status),
    CONSTRAINT matura_role_grant_tenant_fk FOREIGN KEY (tenant_id) REFERENCES matura_tenant (id),
    CONSTRAINT matura_role_grant_workspace_fk FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS matura_app_role (
    name varchar(64) NOT NULL PRIMARY KEY,
    description varchar(1024),
    permissions json NOT NULL,
    is_default boolean NOT NULL DEFAULT false,
    status varchar(16) NOT NULL CHECK (status IN ('active','deleted')),
    version bigint NOT NULL,
    updated_at datetime(6) NOT NULL
);
CREATE TABLE IF NOT EXISTS matura_sync_cursor (
    stream varchar(64) NOT NULL PRIMARY KEY,
    cursor_value varchar(255) NOT NULL,
    synced_at datetime(6) NOT NULL
);
CREATE TABLE IF NOT EXISTS matura_inbox (
    event_id varchar(128) NOT NULL PRIMARY KEY,
    received_at datetime(6) NOT NULL
);
CREATE TABLE IF NOT EXISTS matura_contract (
    version varchar(32) NOT NULL PRIMARY KEY,
    applied_at datetime(6) NOT NULL
);
INSERT IGNORE INTO matura_contract (version, applied_at) VALUES ('matura.contract.v1', UTC_TIMESTAMP(6));
