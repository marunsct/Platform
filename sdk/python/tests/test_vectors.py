"""The shared token and apply vectors (docs/contract/test-vectors.json) that every Matura SDK runs."""

import json
from datetime import UTC, datetime
from pathlib import Path

import jwt.api_jwt
import pytest
from sqlalchemy import create_engine, text

from matura import Verifier
from matura.contract import Contract, ddl
from matura.tokens import InvalidToken

VECTORS = json.loads((Path(__file__).parents[3] / "docs/contract/test-vectors.json").read_text())


@pytest.fixture
def frozen(monkeypatch):
    now = VECTORS["tokens"]["now"]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(now, tz or UTC)

    monkeypatch.setattr(jwt.api_jwt, "datetime", Clock)


@pytest.mark.parametrize("case", VECTORS["tokens"]["cases"], ids=lambda c: c["name"])
def test_token_vectors(case, frozen):
    t = VECTORS["tokens"]
    v = Verifier(t["issuer"], t["audience"], jwks=t["jwks"])
    if not case["valid"]:
        with pytest.raises(InvalidToken):
            v.verify(case["token"])
        return
    p = v.verify(case["token"])
    want = case["principal"]
    assert p.user_id == want["user_id"]
    assert p.tenant_id == want["tenant_id"]
    assert p.tenant_slug == want["tenant_slug"]
    assert p.workspace_id == want["workspace_id"]
    assert list(p.tenant_roles) == want["tenant_roles"]
    assert list(p.roles) == want["roles"]
    assert list(p.permissions) == want["permissions"]
    assert p.email == want["email"]
    assert p.placement_mode == want["placement_mode"]
    assert p.kind == want["kind"]
    actor = want["actor"]
    assert (p.actor is None) if actor is None else (
        p.actor is not None and (p.actor.sub, p.actor.kind, p.actor.client_id) ==
        (actor["sub"], actor["kind"], actor["client_id"]))
    for perm, ok in want["has"].items():
        assert p.has(perm) is ok, perm


async def test_apply_vectors():
    a = VECTORS["apply"]
    c = Contract("sqlite")
    with create_engine("sqlite://").begin() as conn:
        for stmt in ddl("sqlite"):
            conn.execute(text(stmt))
        applied = [await c.apply(conn, e) for e in a["events"]]
        assert applied == a["applied"]
        for table, want in a["rows"].items():
            cols = list(want[0])
            got = [dict(zip(cols, r, strict=True)) for r in conn.execute(text(
                f"SELECT {', '.join(cols)} FROM {table} ORDER BY {cols[0]}"))]
            for row in got:
                if "permissions" in row:
                    row["permissions"] = json.loads(row["permissions"])
                if "is_default" in row:
                    row["is_default"] = bool(row["is_default"])
            assert got == want, table
