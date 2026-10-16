-- Roles are managed in Matura (ADR 0008): apps declare a permission catalogue, roles may be created or edited in
-- Matura, and re-applying a manifest leaves those alone.

CREATE TABLE app_permission (
    app_id      uuid NOT NULL REFERENCES app(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text,
    PRIMARY KEY (app_id, name)
);

INSERT INTO app_permission (app_id, name)
SELECT DISTINCT app_id, unnest(permissions) FROM app_role
ON CONFLICT DO NOTHING;
DELETE FROM app_permission WHERE name = '*';

ALTER TABLE app_role
    ADD COLUMN origin text NOT NULL DEFAULT 'manifest' CHECK (origin IN ('manifest','platform')),
    ADD COLUMN edited boolean NOT NULL DEFAULT false;

-- renaming a role in Matura carries its grants along
ALTER TABLE role_grant DROP CONSTRAINT role_grant_app_id_role_fkey;
ALTER TABLE role_grant ADD CONSTRAINT role_grant_app_id_role_fkey
    FOREIGN KEY (app_id, role) REFERENCES app_role(app_id, name) ON UPDATE CASCADE;
