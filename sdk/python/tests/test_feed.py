import uuid

import httpx
from sqlalchemy import text

from matura import MaturaAPI, Sync

T = str(uuid.uuid4())
U = str(uuid.uuid4())


def fake_maturad(pages, expire_first=False):
    """A stand-in for maturad's app endpoints: an index snapshot, a tenant snapshot and paged changes."""
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        assert req.headers["authorization"].startswith("Basic ")
        if req.url.path.endswith("/snapshot"):
            if req.url.params.get("tenant"):
                return httpx.Response(200, json={
                    "cursor": "10", "tenant": {"id": T, "slug": "acme", "name": "Acme", "kind": "company",
                                               "status": "active", "data_mode_default": "shared", "version": 3},
                    "users": [{"id": U, "email": "ana@acme.test", "status": "active", "version": 2}],
                    "memberships": [{"tenant_id": T, "user_id": U, "tenant_role": "owner", "status": "active",
                                     "version": 4}],
                    "workspaces": [], "grants": [], "roles": []})
            return httpx.Response(200, json={"cursor": "10", "tenants": [T],
                                             "roles": [{"name": "admin", "permissions": ["*"], "version": 1}]})
        cursor = req.url.params.get("cursor", "0")
        if expire_first and cursor == "10" and len([c for c in calls if "changes" in c]) == 1:
            return httpx.Response(410, json={"detail": "too old"})
        return httpx.Response(200, json=pages.get(cursor, {"items": [], "next_cursor": cursor, "has_more": False}))

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls


def member_event(i, role, version):
    return {"id": f"evt_{i}", "type": "matura.membership.updated",
            "data": {"object": "membership", "version": version,
                     "membership": {"tenant_id": T, "user_id": U, "tenant_role": role, "status": "active"}}}


async def test_bootstrap_then_pages(db):
    engine, contract = db
    pages = {"10": {"items": [member_event(11, "admin", 11)], "next_cursor": "11", "has_more": True},
             "11": {"items": [member_event(12, "member", 12), member_event(11, "admin", 11)], "next_cursor": "13",
                    "has_more": False}}
    client, calls = fake_maturad(pages)
    sync = Sync(MaturaAPI("http://maturad", "agentcanvas", "agentcanvas", "s"), contract, engine.begin)
    sync.api._client = client
    assert await sync.catch_up() == 2
    async with engine.connect() as c:
        assert (await c.execute(text("SELECT tenant_role FROM matura_membership"))).scalar() == "member"
        assert (await c.execute(text("SELECT cursor FROM matura_sync_cursor"))).scalar() == "13"
        assert (await c.execute(text("SELECT name FROM matura_app_role"))).scalar() == "admin"
    # nothing new: one call from the stored cursor
    n = len(calls)
    assert await sync.catch_up() == 0
    assert len(calls) == n + 1 and calls[-1].endswith("cursor=13")


async def test_expired_cursor_takes_a_snapshot(db):
    engine, contract = db
    client, calls = fake_maturad({}, expire_first=True)
    sync = Sync(MaturaAPI("http://maturad", "agentcanvas", "agentcanvas", "s"), contract, engine.begin)
    sync.api._client = client
    await sync.catch_up()
    assert sum("snapshot" in c and "tenant=" not in c for c in calls) == 2
