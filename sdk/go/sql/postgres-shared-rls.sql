-- Shared mode only (one database for all tenants): row-level security on the contract tables (PostgreSQL).
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
