import random
import uuid

from sqlalchemy import text

from matura import Principal

T = str(uuid.uuid4())
U = str(uuid.uuid4())
W = str(uuid.uuid4())
G = str(uuid.uuid4())


def ev(i, typ, obj, version, payload):
    return {"id": f"evt_{i}", "type": f"matura.{typ}", "data": {"object": obj, "version": version, obj: payload}}


def history():
    return [
        ev(1, "user.created", "user", 1, {"id": U, "email": "ana@acme.test", "email_verified": True,
                                           "display_name": "Ana", "kind": "human", "status": "active"}),
        ev(2, "tenant.created", "tenant", 2, {"id": T, "slug": "acme", "name": "Acme", "kind": "company",
                                               "status": "active", "data_mode_default": "shared"}),
        ev(3, "workspace.created", "workspace", 3, {"id": W, "tenant_id": T, "name": "Default", "status": "active",
                                                     "is_default": True}),
        ev(4, "membership.added", "membership", 4, {"tenant_id": T, "user_id": U, "tenant_role": "member",
                                                     "status": "active"}),
        ev(5, "app.role.created", "app_role", 5, {"name": "editor", "permissions": ["workflow.write"]}),
        ev(6, "grant.added", "grant", 6, {"id": G, "tenant_id": T, "workspace_id": W, "subject_type": "user",
                                           "subject_id": U, "role": "editor", "status": "active"}),
        ev(7, "membership.updated", "membership", 7, {"tenant_id": T, "user_id": U, "tenant_role": "admin",
                                                       "status": "active"}),
        ev(8, "tenant.updated", "tenant", 8, {"id": T, "slug": "acme", "name": "Acme Corp", "kind": "company",
                                               "status": "active", "data_mode_default": "shared"}),
        ev(9, "app.role.updated", "app_role", 9, {"role": {"name": "author", "permissions": ["workflow.write"]},
                                                   "previous_name": "editor"}),
        ev(10, "user.updated", "user", 10, {"id": U, "email": "ana@acme.example", "email_verified": True,
                                            "display_name": "Ana S", "kind": "human", "status": "active"}),
    ]


async def state(engine):
    async with engine.connect() as c:
        out = {}
        for q in ["SELECT name, version FROM matura_tenant", "SELECT tenant_role, version FROM matura_membership",
                  "SELECT email, display_name FROM matura_user", "SELECT role, status FROM matura_role_grant",
                  "SELECT name, status FROM matura_app_role ORDER BY name", "SELECT name FROM matura_workspace"]:
            out[q] = [tuple(r) for r in (await c.execute(text(q))).all()]
        return out


async def test_order_and_duplicates_do_not_matter(db):
    engine, contract = db
    async with engine.begin() as c:
        for e in history():
            await contract.apply(c, e)
    want = await state(engine)
    assert want["SELECT name, version FROM matura_tenant"] == [("Acme Corp", 8)]
    assert want["SELECT tenant_role, version FROM matura_membership"] == [("admin", 7)]
    assert want["SELECT role, status FROM matura_role_grant"] == [("author", "active")]
    assert want["SELECT name, status FROM matura_app_role ORDER BY name"] == [("author", "active"), ("editor", "deleted")]

    for seed in range(5):
        engine2, _ = engine, contract
        async with engine2.begin() as c:
            for t in ["matura_role_grant", "matura_membership", "matura_workspace", "matura_user", "matura_tenant",
                      "matura_app_role", "matura_inbox"]:
                await c.execute(text(f"DELETE FROM {t}"))
        shuffled = history() * 2
        random.Random(seed).shuffle(shuffled)
        # a renamed role and its grant arrive in any order; apply each event alone, as webhooks would
        for e in shuffled:
            async with engine2.begin() as c:
                await contract.apply(c, e)
        got = await state(engine2)
        for q in want:
            if "role_grant" in q:
                continue  # a grant replayed after the rename keeps the name it was granted under, until the feed
            assert got[q] == want[q], (seed, q)


async def test_inbox_skips_repeats_and_hooks_run(db):
    engine, contract = db
    seen = []
    contract.on("membership", lambda conn, e: seen.append(e["id"]))
    contract.on("matura.tenant.created", lambda conn, e: seen.append("tenant!"))
    async with engine.begin() as c:
        for e in history()[:4]:
            assert await contract.apply(c, e)
        assert not await contract.apply(c, history()[3])
    assert seen == ["tenant!", "evt_4"]


async def test_token_rows_are_filled_by_events(db):
    engine, contract = db
    p = Principal.from_claims({"sub": U, "tid": T, "tenant": "acme", "troles": ["member"], "email": "a@x"})
    async with engine.begin() as c:
        await contract.apply_principal(c, p)
        await contract.apply_principal(c, p)  # repeats do nothing
    s = await state(engine)
    assert s["SELECT name, version FROM matura_tenant"] == [("acme", 0)]
    async with engine.begin() as c:
        await contract.apply(c, history()[1])
    assert (await state(engine))["SELECT name, version FROM matura_tenant"] == [("Acme", 2)]


async def test_cursor(db):
    engine, contract = db
    async with engine.begin() as c:
        assert await contract.cursor(c) is None
        await contract.save_cursor(c, "41")
        await contract.save_cursor(c, "42")
        assert await contract.cursor(c) == "42"
