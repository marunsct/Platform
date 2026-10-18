# Matura SDK for Python

Verify Matura access tokens, check permissions, and keep the `matura_*` contract tables in sync
([app integration contract](../../docs/spec/03-app-integration-contract.md),
[designing an app for Matura](../../docs/guide/designing-apps-for-matura.md)).

```python
from matura import Verifier, Contract, MaturaAPI, Sync
from matura.fastapi import MaturaFastAPI, webhook_router

verifier = Verifier(issuer="https://id.example.com/realms/matura", audience="agentcanvas")
matura = MaturaFastAPI(verifier)

@app.post("/workflows")
async def create(p = matura.require_permission("workflow.write")):
    ...  # p.tenant_id, p.user_id, p.workspace_id, p.permissions

contract = Contract("postgresql")                       # or "sqlite"
app.include_router(webhook_router(WEBHOOK_SECRET, contract, engine.begin))
sync = Sync(MaturaAPI(MATURA_URL, "agentcanvas", CLIENT_ID, CLIENT_SECRET), contract, engine.begin)
await sync.catch_up()                                  # at start-up and hourly
```

Resource permissions, with an authorization model in the manifest (contract §11; 501 without OpenFGA):

```python
api = MaturaAPI(MATURA_URL, "agentcanvas", CLIENT_ID, CLIENT_SECRET)
await api.write_relations(p.tenant_id, writes=[(f"user:{p.user_id}", "owner", f"canvas:{canvas_id}")])
allowed = await api.check(p.tenant_id, f"user:{p.user_id}", "editor", f"canvas:{canvas_id}")
results = await api.batch_check(p.tenant_id, [(f"user:{p.user_id}", "viewer", f"canvas:{c}") for c in ids])
```

Tests: `matura.testing.FakeIssuer` mints tokens for any tenant, roles and permissions; pass `issuer.jwks` to
`Verifier(..., jwks=...)`.

Run the SDK's own tests: `uv run pytest` (set `MATURA_TEST_DATABASE_URL` to also test on PostgreSQL).
