"""End-to-end check of the Python SDK against a running maturad in development mode (MATURA_AUTH=dev).

    uv run --project sdk/python python scripts/e2e_python_sdk.py http://127.0.0.1:8080

Registers an app, creates a secret, two tenants and members through the API, then lets the SDK bootstrap and
follow the change feed into SQLite contract tables, and checks the result. Exits non-zero on any mismatch.
"""

import asyncio
import sys
import tempfile
import uuid

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from matura import Contract, MaturaAPI, Sync

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
SLUG = "e2e" + uuid.uuid4().hex[:6]


def as_user(uid, op=False):
    h = {"X-Matura-Dev-User": str(uid), "X-Matura-Dev-Email": f"{str(uid)[24:]}@example.test"}
    if op:
        h["X-Matura-Dev-Operator"] = "true"
    return h


async def main() -> None:
    op, alice, bob = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with httpx.AsyncClient(base_url=BASE) as c:
        async def call(method, path, who, body=None, want=None):
            r = await c.request(method, path, headers=who, json=body)
            if want and r.status_code != want:
                raise SystemExit(f"{method} {path}: {r.status_code} {r.text}")
            return r.json() if r.content else None

        await call("PUT", f"/admin/v1/apps/{SLUG}", as_user(op, True), {
            "slug": SLUG, "name": "E2E", "auth": {"redirect_uris": ["http://localhost/cb"], "public_client": True},
            "roles": [{"name": "admin", "permissions": ["*"]}, {"name": "viewer", "permissions": ["doc.read"]}],
            "default_role": "viewer", "owner_role": "admin",
            "tenancy": {"modes": ["shared"], "managers": ["app"]}}, 200)
        sec = await call("POST", f"/admin/v1/apps/{SLUG}/secrets", as_user(op, True), {"label": "e2e"}, 201)
        await call("GET", "/v1/me", as_user(bob), None, 200)
        t1 = await call("POST", "/v1/tenants", as_user(alice), {"slug": SLUG + "-a", "name": "A"}, 201)
        await call("PUT", f"/v1/tenants/{t1['id']}/apps/{SLUG}", as_user(alice), None, 200)
        t2 = await call("POST", "/v1/tenants", as_user(alice), {"slug": SLUG + "-b", "name": "B"}, 201)  # no app

        engine = create_async_engine(f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/c.db")
        contract = Contract("sqlite")
        async with engine.begin() as conn:
            await contract.create(conn)
        sync = Sync(MaturaAPI(BASE, SLUG, sec["client_id"], sec["secret"]), contract, engine.begin)
        await sync.catch_up()

        # changes after the bootstrap arrive through the feed
        await call("POST", f"/v1/tenants/{t1['id']}/members", as_user(alice), {"user_id": str(bob)}, 201)
        await call("POST", f"/v1/tenants/{t1['id']}/grants", as_user(alice),
                   {"app": SLUG, "user_id": str(bob), "role": "viewer"}, 201)
        await call("PATCH", f"/v1/tenants/{t1['id']}", as_user(alice), {"name": "A Corp"}, 200)
        await sync.catch_up()

        async with engine.connect() as conn:
            q = lambda sql: conn.execute(text(sql))  # noqa: E731
            tenants = (await q("SELECT id, name FROM matura_tenant ORDER BY name")).all()
            members = (await q("SELECT user_id, tenant_role FROM matura_membership ORDER BY tenant_role")).all()
            grants = (await q("SELECT subject_id, role, status FROM matura_role_grant")).all()
            roles = (await q("SELECT name FROM matura_app_role ORDER BY name")).scalars().all()
        checks = {
            "only the tenant that enabled the app": [tuple(t) for t in tenants] == [(t1["id"], "A Corp")],
            "both members": sorted(m[1] for m in members) == ["member", "owner"],
            "bob's grant": [tuple(g) for g in grants] == [(str(bob), "viewer", "active")],
            "roles": roles == ["admin", "viewer"],
            "tenant B absent": t2["id"] not in [t[0] for t in tenants],
        }
        await engine.dispose()
    failed = [k for k, ok in checks.items() if not ok]
    for k, ok in checks.items():
        print(("ok   " if ok else "FAIL ") + k)
    if failed:
        print("tenants", tenants, "members", members, "grants", grants, "roles", roles)
        raise SystemExit(1)


asyncio.run(main())
