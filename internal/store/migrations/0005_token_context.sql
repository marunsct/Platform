-- The tenant a user signed in to last, used when a sign-in names no tenant (technical specification §6).
ALTER TABLE app_user ADD COLUMN last_tenant_id uuid REFERENCES tenant(id) ON DELETE SET NULL;
