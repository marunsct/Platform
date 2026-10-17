"""Reading the app's change feed and snapshots from maturad (contract §7, level 2)."""

from __future__ import annotations

from typing import Any

import httpx

from .contract import Contract


class CursorExpired(Exception):
    """The stored cursor is older than the feed keeps (30 days): take a snapshot (``Sync.bootstrap``)."""


class MaturaAPI:
    """maturad's app endpoints, authenticated with the app's client id and secret (HTTP Basic)."""

    def __init__(self, base_url: str, app: str, client_id: str, client_secret: str, *,
                 client: httpx.AsyncClient | None = None, timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.app = app
        self._auth = (client_id, client_secret)
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.get(self.base + path, params=params, auth=self._auth)
        if r.status_code == 410:
            raise CursorExpired(r.json().get("detail", "cursor expired"))
        r.raise_for_status()
        return r.json()

    async def changes(self, cursor: str | None = None, limit: int = 500) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return await self._get(f"/v1/apps/{self.app}/changes", params)

    async def snapshot(self, tenant: str | None = None) -> dict[str, Any]:
        return await self._get(f"/v1/apps/{self.app}/snapshot", {"tenant": tenant} if tenant else None)

    async def _send(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.request(method, self.base + path, json=body, auth=self._auth)
        r.raise_for_status()
        return r.json()

    # --- data placement (technical specification §7, level 3) ---

    async def placement(self, tenant: str) -> dict[str, Any]:
        """Where the tenant's data lives: mode, manager, state (requested, provisioned, ready, retiring, deleted)."""
        return await self._get(f"/v1/apps/{self.app}/placements/{tenant}")

    async def register_placement(self, tenant: str, location_label: str, *, database_name: str | None = None,
                                 schema_name: str | None = None) -> dict[str, Any]:
        """Record storage the app created itself (manager ``app``); the placement becomes ``provisioned``."""
        body: dict[str, Any] = {"location_label": location_label}
        if database_name:
            body["database_name"] = database_name
        if schema_name:
            body["schema_name"] = schema_name
        return await self._send("PUT", f"/v1/apps/{self.app}/placements/{tenant}", body)

    async def credentials(self, tenant: str, *, migrate: bool = False) -> dict[str, Any]:
        """Connection for platform-managed storage: host, port, database, user, password, search_path, expires_at.
        ``migrate`` returns the role that owns the tables (different from the runtime role in shared mode).
        Keep it in memory only and ask again after ``expires_at``."""
        return await self._send("POST", f"/v1/apps/{self.app}/placements/{tenant}/credentials",
                                {"purpose": "migrate" if migrate else "runtime"})

    async def placement_ready(self, tenant: str) -> dict[str, Any]:
        """The app migrated the tenant's storage and serves it."""
        return await self._send("POST", f"/v1/apps/{self.app}/placements/{tenant}:ready")

    async def placement_deleted(self, tenant: str) -> dict[str, Any]:
        """The app deleted a retiring tenant's data; Matura then drops platform-managed storage."""
        return await self._send("POST", f"/v1/apps/{self.app}/placements/{tenant}:deleted")

    async def aclose(self) -> None:
        await self._client.aclose()


def snapshot_events(snap: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a snapshot into events the contract applies with the same version rule (no event ids: not de-duplicated)."""
    def ev(obj: str, typ: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {"type": f"matura.{typ}", "data": {"object": obj, "version": payload.get("version", 0), obj: payload}}

    out = [ev("app_role", "app.role.updated", r) for r in snap.get("roles") or []]
    if snap.get("tenant"):
        out.append(ev("tenant", "tenant.updated", snap["tenant"]))
    out += [ev("workspace", "workspace.updated", w) for w in snap.get("workspaces") or []]
    out += [ev("user", "user.updated", u) for u in snap.get("users") or []]
    out += [ev("membership", "membership.updated", m) for m in snap.get("memberships") or []]
    out += [ev("grant", "grant.added", g) for g in snap.get("grants") or []]
    if snap.get("placement"):
        out.append(ev("placement", "placement.updated", snap["placement"]))
    return out


class Sync:
    """Keeps the contract tables current from the feed: ``bootstrap`` once, then ``catch_up`` at start-up and hourly.

    ``begin`` returns a context manager yielding a connection in a transaction (for example ``engine.begin``).
    Each page is applied and its cursor stored in one transaction, so a crash repeats at most one page.
    """

    def __init__(self, api: MaturaAPI, contract: Contract, begin: Any):
        self.api = api
        self.contract = contract
        self.begin = begin

    async def bootstrap(self) -> str:
        """Snapshot every tenant that enabled the app, then store the cursor the first snapshot gave."""
        index = await self.api.snapshot()
        cursor = index["cursor"]
        async with self.begin() as conn:
            for e in snapshot_events(index):
                await self.contract.apply(conn, e, dedupe=False)
        for tid in index.get("tenants") or []:
            snap = await self.api.snapshot(tid)
            async with self.begin() as conn:
                for e in snapshot_events(snap):
                    await self.contract.apply(conn, e, dedupe=False)
        async with self.begin() as conn:
            await self.contract.save_cursor(conn, cursor)
        return cursor

    async def catch_up(self, max_pages: int = 1000) -> int:
        """Apply every change after the stored cursor. Returns how many events were new."""
        async with self.begin() as conn:
            cursor = await self.contract.cursor(conn)
        if cursor is None:
            cursor = await self.bootstrap()
        applied = 0
        for _ in range(max_pages):
            try:
                page = await self.api.changes(cursor)
            except CursorExpired:
                cursor = await self.bootstrap()
                continue
            async with self.begin() as conn:
                for e in page["items"]:
                    applied += await self.contract.apply(conn, e)
                await self.contract.save_cursor(conn, page["next_cursor"])
            cursor = page["next_cursor"]
            if not page.get("has_more"):
                break
        return applied
