# Contract tables in any database

The `matura_*` tables (contract §3) for apps that do not use a Matura SDK, or use a database the SDKs do not cover.
Run the file for your database once with your migration tool; every file is safe to run again.

| File | Database | Notes |
|---|---|---|
| `postgres.sql` | PostgreSQL 13+ | the reference; `uuid`, `timestamptz`, `text[]` permissions |
| `postgres-shared-rls.sql` | PostgreSQL, shared mode | row-level security on the contract tables; set `matura.tenant_id` per transaction |
| `mysql.sql` | MySQL 8.0.16+, MariaDB 10.5+ | ids as `char(36)`, `json` permissions, UTC `datetime(6)`; checked on MariaDB 10.11 |
| `sqlserver.sql` | SQL Server 2016+, Azure SQL | `uniqueidentifier`, `nvarchar(max)` JSON permissions, `datetime2`; syntax-checked only |
| `sqlite.sql` | SQLite 3.24+ | tests, desktop and local editions; ids and times as text, permissions as a JSON array |

`matura_sync_cursor.cursor` is named `cursor_value` in MySQL and SQL Server, where `cursor` is a reserved word.

Only PostgreSQL gets row-level security from the contract. On the others, filter every query by `tenant_id`, or put
each tenant in its own schema or database (data placement modes, ADR 0006).

## Applying a change: the version rule

Every event, change-feed entry and snapshot row carries a `version`. Keep a row only when the incoming version is
newer than the stored one; then order and duplicates do not matter. In one transaction per event:

1. Record the event id: insert into `matura_inbox`; if it is already there, stop (it was applied).
2. Insert stubs for rows the change refers to that you have not seen yet (a membership's tenant and user, a grant's
   tenant and workspace) with version 0 and the id as name; the next change for them fills them in.
3. Upsert the row with the version rule, as below.

`docs/contract/test-vectors.json` (`apply`) is a sequence of events with the expected final rows; run it against your
implementation.

PostgreSQL and SQLite:

```sql
INSERT INTO matura_tenant AS t (id, slug, name, kind, status, plan, data_mode, version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET slug = excluded.slug, name = excluded.name, kind = excluded.kind,
    status = excluded.status, plan = excluded.plan, data_mode = excluded.data_mode,
    version = excluded.version, updated_at = excluded.updated_at
WHERE t.version < excluded.version;
```

MySQL and MariaDB (assign `version` last: MySQL applies the assignments in order):

```sql
INSERT INTO matura_tenant (id, slug, name, kind, status, plan, data_mode, version, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    slug = IF(VALUES(version) > version, VALUES(slug), slug),
    name = IF(VALUES(version) > version, VALUES(name), name),
    kind = IF(VALUES(version) > version, VALUES(kind), kind),
    status = IF(VALUES(version) > version, VALUES(status), status),
    plan = IF(VALUES(version) > version, VALUES(plan), plan),
    data_mode = IF(VALUES(version) > version, VALUES(data_mode), data_mode),
    updated_at = IF(VALUES(version) > version, VALUES(updated_at), updated_at),
    version = GREATEST(version, VALUES(version));
```

SQL Server:

```sql
MERGE matura_tenant WITH (HOLDLOCK) AS t
USING (VALUES (@id, @slug, @name, @kind, @status, @plan, @data_mode, @version, @updated_at))
    AS s (id, slug, name, kind, status, [plan], data_mode, version, updated_at) ON t.id = s.id
WHEN MATCHED AND t.version < s.version THEN UPDATE SET slug = s.slug, name = s.name, kind = s.kind,
    status = s.status, [plan] = s.[plan], data_mode = s.data_mode, version = s.version, updated_at = s.updated_at
WHEN NOT MATCHED THEN INSERT (id, slug, name, kind, status, [plan], data_mode, version, updated_at)
    VALUES (s.id, s.slug, s.name, s.kind, s.status, s.[plan], s.data_mode, s.version, s.updated_at);
```

Two changes are not plain upserts:

- **Role renamed** (`matura.app.role.updated` with `previous_name`): update `matura_role_grant.role` from the old name
  to the new one, mark the old `matura_app_role` row deleted at this version, and upsert the new one.
- **Placement** (`matura.placement.*`): set `matura_tenant.data_mode` to the placement's `mode`.
