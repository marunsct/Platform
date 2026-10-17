"""The ``matura_*`` contract tables and the version rule that keeps them current (contract §3, §5).

Every change, from a webhook, the change feed, a snapshot or a token, goes through :meth:`Contract.apply`, which keeps
a row only when its ``version`` is newer than the stored one. Order and duplicates therefore do not matter.

Works with SQLAlchemy connections, sync (:class:`sqlalchemy.engine.Connection`) or async
(:class:`sqlalchemy.ext.asyncio.AsyncConnection`), on PostgreSQL (``matura.contract.v1``) and SQLite (tests and
local editions, no row-level security).
"""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

CONTRACT_VERSION = "matura.contract.v1"

_PG = """
CREATE TABLE IF NOT EXISTS matura_tenant (
    id uuid PRIMARY KEY, slug text NOT NULL UNIQUE, name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('company','shared','personal')),
    status text NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    plan text, data_mode text NOT NULL CHECK (data_mode IN ('shared','schema','database')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_workspace (
    id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES matura_tenant(id), name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active','archived','deleted')), is_default boolean NOT NULL DEFAULT false,
    version bigint NOT NULL, updated_at timestamptz NOT NULL, UNIQUE (tenant_id, id));
CREATE TABLE IF NOT EXISTS matura_user (
    id uuid PRIMARY KEY, email text, email_verified boolean NOT NULL DEFAULT false, display_name text,
    avatar_url text, locale text,
    kind text NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status text NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_membership (
    tenant_id uuid NOT NULL REFERENCES matura_tenant(id), user_id uuid NOT NULL REFERENCES matura_user(id),
    tenant_role text NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status text NOT NULL CHECK (status IN ('active','deactivated','removed')), joined_at timestamptz NOT NULL,
    version bigint NOT NULL, updated_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, user_id));
CREATE TABLE IF NOT EXISTS matura_role_grant (
    id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES matura_tenant(id), workspace_id uuid,
    subject_type text NOT NULL CHECK (subject_type IN ('user','group','service_account')), subject_id uuid NOT NULL,
    role text NOT NULL, status text NOT NULL CHECK (status IN ('active','revoked')),
    version bigint NOT NULL, updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace(tenant_id, id));
CREATE INDEX IF NOT EXISTS matura_role_grant_subject ON matura_role_grant (tenant_id, subject_id) WHERE status = 'active';
CREATE TABLE IF NOT EXISTS matura_app_role (
    name text PRIMARY KEY, description text, permissions text[] NOT NULL, is_default boolean NOT NULL DEFAULT false,
    status text NOT NULL CHECK (status IN ('active','deleted')), version bigint NOT NULL, updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_sync_cursor (stream text PRIMARY KEY, cursor text NOT NULL, synced_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_inbox (event_id text PRIMARY KEY, received_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS matura_contract (version text PRIMARY KEY, applied_at timestamptz NOT NULL);
"""

_PG_RLS = """
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
"""

_SQLITE = """
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
"""


def ddl(dialect: str, *, rls: bool = False) -> list[str]:
    """The contract DDL as separate statements. ``rls`` adds the shared-mode policies (PostgreSQL only)."""
    if dialect == "postgresql":
        sql = _PG + (_PG_RLS if rls else "")
    elif dialect == "sqlite":
        sql = _SQLITE
    else:
        raise ValueError(f"contract tables for {dialect} ship in docs/contract (TS7e); use postgresql or sqlite here")
    return [s.strip() for s in sql.split(";") if s.strip()]


Hook = Callable[[Any, dict[str, Any]], Awaitable[None] | None]


class _Dialect:
    def __init__(self, name: str):
        self.pg = name == "postgresql"

    def id(self, v: Any) -> Any:
        if v is None or v == "":
            return None
        return uuid.UUID(str(v)) if self.pg else str(v)

    def ts(self, v: Any) -> Any:
        if v is None:
            dt = datetime.now(UTC)
        elif isinstance(v, datetime):
            dt = v
        else:
            dt = datetime.fromisoformat(str(v))
        return dt if self.pg else dt.isoformat()

    def arr(self, v: list[str] | None) -> Any:
        return list(v or []) if self.pg else json.dumps(list(v or []))


def _upsert(table: str, key: list[str], cols: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    names = list(cols)
    sets = ", ".join(f"{c} = excluded.{c}" for c in names if c not in key)
    sql = (f"INSERT INTO {table} AS t ({', '.join(names)}) VALUES ({', '.join(':' + c for c in names)}) "
           f"ON CONFLICT ({', '.join(key)}) DO UPDATE SET {sets} WHERE t.version < excluded.version")
    return sql, cols


def _placeholder(table: str, cols: dict[str, Any], key: str) -> tuple[str, dict[str, Any]]:
    names = list(cols)
    sql = (f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join(':' + c for c in names)}) "
           f"ON CONFLICT ({key}) DO NOTHING")
    return sql, cols


class Contract:
    """Applies Matura changes to the contract tables, and runs the app's hooks in the same transaction.

    ``on(object_or_type, hook)`` registers a hook for an object (``"membership"``) or an exact event type
    (``"matura.tenant.deleting"``); hooks receive ``(connection, event)`` and may be async on async connections.
    """

    def __init__(self, dialect: str = "postgresql"):
        self.dialect = dialect
        self._d = _Dialect(dialect)
        self._hooks: dict[str, list[Hook]] = {}

    def on(self, key: str, hook: Hook) -> Hook:
        self._hooks.setdefault(key, []).append(hook)
        return hook

    # --- statements -------------------------------------------------------------------------------------------------

    def _tenant_stub(self, tid: Any) -> tuple[str, dict[str, Any]]:
        d = self._d
        return _placeholder("matura_tenant", {"id": d.id(tid), "slug": str(tid), "name": str(tid), "kind": "company",
                                              "status": "active", "plan": None, "data_mode": "shared", "version": 0,
                                              "updated_at": d.ts(None)}, "id")

    def _user_stub(self, uid: Any) -> tuple[str, dict[str, Any]]:
        d = self._d
        return _placeholder("matura_user", {"id": d.id(uid), "email": None, "email_verified": False,
                                            "display_name": None, "locale": None, "kind": "human",
                                            "status": "active", "version": 0, "updated_at": d.ts(None)}, "id")

    def statements(self, event: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """The SQL that applies one event (CloudEvents envelope as Matura sends it)."""
        d = self._d
        data = event.get("data") or {}
        obj = data.get("object")
        version = int(data.get("version") or 0)
        p = data.get(obj) if obj else None
        if not isinstance(p, dict):
            return []
        typ = event.get("type", "")
        if obj == "tenant":
            return [_upsert("matura_tenant", ["id"], {
                "id": d.id(p["id"]), "slug": p["slug"], "name": p["name"], "kind": p.get("kind", "company"),
                "status": p["status"], "plan": p.get("plan"),
                "data_mode": p.get("data_mode") or p.get("data_mode_default") or "shared",
                "version": version, "updated_at": d.ts(p.get("updated_at"))})]
        if obj == "workspace":
            return [self._tenant_stub(p["tenant_id"]), _upsert("matura_workspace", ["id"], {
                "id": d.id(p["id"]), "tenant_id": d.id(p["tenant_id"]), "name": p["name"], "status": p["status"],
                "is_default": bool(p.get("is_default")), "version": version, "updated_at": d.ts(p.get("updated_at"))})]
        if obj == "user":
            return [_upsert("matura_user", ["id"], {
                "id": d.id(p["id"]), "email": p.get("email"), "email_verified": bool(p.get("email_verified")),
                "display_name": p.get("display_name"), "locale": p.get("locale"), "kind": p.get("kind", "human"),
                "status": p["status"], "version": version, "updated_at": d.ts(p.get("updated_at"))})]
        if obj == "membership":
            return [self._tenant_stub(p["tenant_id"]), self._user_stub(p["user_id"]),
                    _upsert("matura_membership", ["tenant_id", "user_id"], {
                        "tenant_id": d.id(p["tenant_id"]), "user_id": d.id(p["user_id"]),
                        "tenant_role": p["tenant_role"], "status": p["status"], "joined_at": d.ts(p.get("joined_at")),
                        "version": version, "updated_at": d.ts(p.get("updated_at"))})]
        if obj == "grant":
            stubs = [self._tenant_stub(p["tenant_id"])]
            if p.get("workspace_id"):
                stubs.append(_placeholder("matura_workspace", {
                    "id": d.id(p["workspace_id"]), "tenant_id": d.id(p["tenant_id"]), "name": str(p["workspace_id"]),
                    "status": "active", "is_default": False, "version": 0, "updated_at": d.ts(None)}, "id"))
            return [*stubs, _upsert("matura_role_grant", ["id"], {
                "id": d.id(p["id"]), "tenant_id": d.id(p["tenant_id"]), "workspace_id": d.id(p.get("workspace_id")),
                "subject_type": p["subject_type"], "subject_id": d.id(p["subject_id"]), "role": p["role"],
                "status": p["status"], "version": version, "updated_at": d.ts(p.get("updated_at"))})]
        if obj == "app_role":
            role = p.get("role") if isinstance(p.get("role"), dict) else p
            out: list[tuple[str, dict[str, Any]]] = []
            prev = p.get("previous_name")
            if prev:  # renamed in Matura: grants follow, as they do there
                out.append(("UPDATE matura_role_grant SET role = :new WHERE role = :old",
                            {"new": role["name"], "old": prev}))
                # the old name is gone as of this version, even if its creation arrives later
                out.append(_upsert("matura_app_role", ["name"], {
                    "name": prev, "description": None, "permissions": d.arr([]), "is_default": False,
                    "status": "deleted", "version": version, "updated_at": d.ts(None)}))
            out.append(_upsert("matura_app_role", ["name"], {
                "name": role["name"], "description": role.get("description"),
                "permissions": d.arr(role.get("permissions")), "is_default": bool(role.get("is_default")),
                "status": "deleted" if typ.endswith(".deleted") else "active", "version": version,
                "updated_at": d.ts(None)}))
            return out
        if obj == "placement":
            return [("UPDATE matura_tenant SET data_mode = :mode WHERE id = :id",
                     {"mode": p["mode"], "id": d.id(p["tenant_id"])})]
        return []  # tenant_app, app_manifest, ping: hooks only

    def from_principal(self, principal: Any) -> list[tuple[str, dict[str, Any]]]:
        """Rows a verified token can create (just-in-time, contract §5). They are written only when missing, with
        version 0, so the next event or feed read (always a higher version) fills in what a token lacks."""
        d = self._d
        if not principal.tenant_id:
            return []
        now = d.ts(None)
        return [
            _placeholder("matura_tenant", {
                "id": d.id(principal.tenant_id), "slug": principal.tenant_slug or str(principal.tenant_id),
                "name": principal.tenant_slug or str(principal.tenant_id), "kind": "company", "status": "active",
                "plan": None, "data_mode": principal.placement_mode or "shared", "version": 0, "updated_at": now},
                "id"),
            _placeholder("matura_user", {
                "id": d.id(principal.user_id), "email": principal.email or None,
                "email_verified": principal.email_verified, "display_name": principal.name, "locale": None,
                "kind": "service" if principal.is_service else "human", "status": "active", "version": 0,
                "updated_at": now}, "id"),
            _placeholder("matura_membership", {
                "tenant_id": d.id(principal.tenant_id), "user_id": d.id(principal.user_id),
                "tenant_role": (principal.tenant_roles or ("member",))[0], "status": "active", "joined_at": now,
                "version": 0, "updated_at": now}, "tenant_id, user_id"),
        ]

    # --- running ----------------------------------------------------------------------------------------------------

    async def create(self, conn: Any, *, rls: bool = False) -> None:
        """Create the contract tables (idempotent) on a sync or async SQLAlchemy connection."""
        from sqlalchemy import text

        for stmt in ddl(self.dialect, rls=rls):
            await _maybe(conn.execute(text(stmt)))
        await _maybe(conn.execute(
            text("INSERT INTO matura_contract (version, applied_at) VALUES (:v, :t) ON CONFLICT (version) DO NOTHING"),
            {"v": CONTRACT_VERSION, "t": self._d.ts(None)}))

    async def apply(self, conn: Any, event: dict[str, Any], *, dedupe: bool = True) -> bool:
        """Apply one event and run its hooks. Returns False for an event id already applied (``matura_inbox``)."""
        from sqlalchemy import text

        if dedupe and event.get("id"):
            r = await _maybe(conn.execute(
                text("INSERT INTO matura_inbox (event_id, received_at) VALUES (:id, :t) ON CONFLICT (event_id) DO NOTHING"),
                {"id": event["id"], "t": self._d.ts(None)}))
            if r.rowcount == 0:
                return False
        for sql, params in self.statements(event):
            await _maybe(conn.execute(text(sql), params))
        obj = (event.get("data") or {}).get("object", "")
        for hook in [*self._hooks.get(obj, []), *self._hooks.get(event.get("type", ""), []), *self._hooks.get("*", [])]:
            await _maybe(hook(conn, event))
        return True

    async def apply_principal(self, conn: Any, principal: Any) -> None:
        from sqlalchemy import text

        for sql, params in self.from_principal(principal):
            await _maybe(conn.execute(text(sql), params))

    async def cursor(self, conn: Any, stream: str = "changes") -> str | None:
        from sqlalchemy import text

        r = await _maybe(conn.execute(text("SELECT cursor FROM matura_sync_cursor WHERE stream = :s"), {"s": stream}))
        row = r.first()
        return row[0] if row else None

    async def save_cursor(self, conn: Any, cursor: str, stream: str = "changes") -> None:
        from sqlalchemy import text

        await _maybe(conn.execute(text(
            "INSERT INTO matura_sync_cursor (stream, cursor, synced_at) VALUES (:s, :c, :t) "
            "ON CONFLICT (stream) DO UPDATE SET cursor = excluded.cursor, synced_at = excluded.synced_at"),
            {"s": stream, "c": cursor, "t": self._d.ts(None)}))

    async def prune_inbox(self, conn: Any, days: int = 7) -> None:
        from datetime import timedelta

        from sqlalchemy import text

        cutoff = datetime.now(UTC) - timedelta(days=days)
        await _maybe(conn.execute(text("DELETE FROM matura_inbox WHERE received_at < :c"),
                                  {"c": cutoff if self._d.pg else cutoff.isoformat()}))


async def _maybe(v: Any) -> Any:
    return await v if inspect.isawaitable(v) else v
