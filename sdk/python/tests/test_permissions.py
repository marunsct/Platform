import json

import httpx
import pytest

from matura import MaturaAPI


def fake_permissions():
    """A stand-in for maturad's permission endpoints: keeps tuples, answers direct checks."""
    tuples: set[tuple[str, str, str]] = set()
    seen: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"].startswith("Basic ")
        body = json.loads(req.content or b"{}")
        seen.append(body)
        path = req.url.path
        if not path.startswith("/v1/apps/notes/tenants/t1"):
            return httpx.Response(501, json={"type": "https://matura.dev/problems/permissions-not-configured"})
        key = lambda t: (t["user"], t["relation"], t["object"])
        if path.endswith("/relations"):
            tuples.update(key(t) for t in body["writes"])
            tuples.difference_update(key(t) for t in body["deletes"])
            return httpx.Response(200, json={"written": len(body["writes"]), "deleted": len(body["deletes"])})
        if path.endswith(":check"):
            return httpx.Response(200, json={"allowed": key(body) in tuples})
        if path.endswith(":batch-check"):
            return httpx.Response(200, json={"results": [{"allowed": key(c) in tuples} for c in body["checks"]]})
        if path.endswith(":list-objects"):
            return httpx.Response(200, json={"objects": sorted(
                o for u, r, o in tuples if u == body["user"] and r == body["relation"])})
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


async def test_permission_helpers():
    client, seen = fake_permissions()
    api = MaturaAPI("http://maturad", "notes", "notes", "s", client=client)
    await api.write_relations("t1", writes=[("user:u1", "editor", "document:d1"),
                                            {"user": "user:u1", "relation": "editor", "object": "document:d2"}])
    assert await api.check("t1", "user:u1", "editor", "document:d1", fresh=True)
    assert seen[-1]["consistency"] == "higher"
    assert not await api.check("t1", "user:u2", "editor", "document:d1")
    res = await api.batch_check("t1", [("user:u1", "editor", "document:d2"), ("user:u2", "editor", "document:d2")],
                                contextual=[("user:u2", "viewer", "document:d2")])
    assert [r["allowed"] for r in res] == [True, False]
    assert seen[-1]["contextual_tuples"] == [{"user": "user:u2", "relation": "viewer", "object": "document:d2"}]
    assert await api.list_objects("t1", "user:u1", "editor", "document") == ["document:d1", "document:d2"]
    await api.write_relations("t1", deletes=[("user:u1", "editor", "document:d1")])
    assert not await api.check("t1", "user:u1", "editor", "document:d1")
    with pytest.raises(httpx.HTTPStatusError) as e:
        await api.check("t2", "user:u1", "editor", "document:d1")
    assert e.value.response.status_code == 501
    await api.aclose()
