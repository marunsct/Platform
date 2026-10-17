-- Provisioning data placements (technical specification §7, TS7b).
-- owner_role: the role an app migrates with in platform-managed shared mode (in schema and database mode the
-- tenant's role owns its schema or database, so role_name is used for both).
-- data_deleted_at: the app confirmed it deleted the tenant's data (POST …:deleted); the provisioner then drops the
-- storage. attempts and next_attempt_at: retries with backoff after a failed provisioning step.
ALTER TABLE placement
    ADD COLUMN owner_role_name   text,
    ADD COLUMN owner_role_secret bytea,
    ADD COLUMN data_deleted_at   timestamptz,
    ADD COLUMN attempts          integer NOT NULL DEFAULT 0,
    ADD COLUMN next_attempt_at   timestamptz NOT NULL DEFAULT now();

CREATE INDEX placement_work ON placement (next_attempt_at)
    WHERE manager = 'platform' AND state IN ('requested', 'failed', 'retiring');
