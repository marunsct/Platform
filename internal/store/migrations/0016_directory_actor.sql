-- SCIM changes are audited per directory connection: actor kind `directory`, actor id the SCIM token's id and actor
-- email `scim:<token name>`, so a tenant with Okta and Entra connected can tell which one made a change.
ALTER TABLE audit_event DROP CONSTRAINT audit_event_actor_kind_check;
ALTER TABLE audit_event ADD CONSTRAINT audit_event_actor_kind_check
    CHECK (actor_kind IN ('user','operator','app','system','agent','service','directory'));
