-- Fine-grained permissions with OpenFGA (TS11, technical specification §9.6). Installation-wide bookkeeping, not
-- tenant-owned: the tuples themselves live in OpenFGA, namespaced by tenant (internal/fga).

-- The installation's OpenFGA store, Matura's base model, and how far the sync worker has read the outbox
-- (NULL: never, or the store was replaced; the worker then writes every current fact again).
CREATE TABLE fga_state (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    store_id      text,
    base_model_id text,
    base_hash     text,
    cursor        bigint,
    synced_at     timestamptz
);
INSERT INTO fga_state DEFAULT VALUES;

-- The OpenFGA model written for each app's manifest model (Matura's types plus the app's).
CREATE TABLE fga_app_model (
    app_id     uuid PRIMARY KEY REFERENCES app(id),
    model_hash text NOT NULL,
    model_id   text NOT NULL,
    written_at timestamptz NOT NULL DEFAULT now()
);
