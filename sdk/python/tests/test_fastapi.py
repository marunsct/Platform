import uuid

import httpx
from fastapi import FastAPI
from sqlalchemy import text

from matura import Verifier
from matura.fastapi import MaturaFastAPI, webhook_router
from matura.testing import FakeIssuer, signed_event


async def test_permissions_and_webhooks(db):
    engine, contract = db
    iss = FakeIssuer(audience="agentcanvas")
    m = MaturaFastAPI(Verifier(iss.issuer, "agentcanvas", jwks=iss.jwks))
    app = FastAPI()

    @app.post("/workflows")
    async def create(p=m.require_permission("workflow.write")):
        return {"tenant": p.tenant_id}

    app.include_router(webhook_router("whsec_1", contract, engine.begin))
    t = str(uuid.uuid4())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://app") as client:
        assert (await client.post("/workflows")).status_code == 401
        r = await client.post("/workflows", headers={"Authorization": "Bearer " + iss.token(tenant_id=t, perms=["workflow.read"])})
        assert r.status_code == 403 and "workflow.write" in r.json()["detail"]
        r = await client.post("/workflows", headers={"Authorization": "Bearer " + iss.token(tenant_id=t, perms=["workflow.write"])})
        assert r.status_code == 200 and r.json() == {"tenant": t}

        event = {"id": "evt_1", "type": "matura.tenant.created",
                 "data": {"object": "tenant", "version": 3, "tenant": {"id": t, "slug": "acme", "name": "Acme",
                                                                        "kind": "company", "status": "active"}}}
        body, headers = signed_event("whsec_1", event)
        forged = {**headers, "Matura-Signature": "t=1,v1=00"}
        assert (await client.post("/matura/events", content=body, headers=forged)).status_code == 401
        assert (await client.post("/matura/events", content=body, headers=headers)).status_code == 204
        assert (await client.post("/matura/events", content=body, headers=headers)).status_code == 204
    async with engine.connect() as c:
        assert (await c.execute(text("SELECT name FROM matura_tenant"))).scalars().all() == ["Acme"]
