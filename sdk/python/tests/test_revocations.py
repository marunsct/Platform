import time
from datetime import UTC, datetime

import pytest

from matura import InvalidToken, Revocations, Verifier
from matura.testing import FakeIssuer


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat()


def test_revocations_stop_tokens():
    iss = FakeIssuer(audience="notes")
    revs = Revocations()
    v = Verifier(iss.issuer, "notes", jwks=iss.jwks, revocations=revs)
    old = int(time.time()) - 60
    token = iss.token("u1", tenant_id="t1", iat=old, sid="s1")
    v.verify(token)

    # another session's revocation, as a webhook event
    assert revs.apply({"type": "matura.revocation.created", "data": {"object": "revocation", "version": 3,
                       "revocation": {"id": "r1", "user_id": "u1", "tenant_id": None, "session_id": "s2",
                                      "not_before": iso(time.time()), "reason": "session_ended"}}})
    v.verify(token)

    revs.add({"id": "r2", "user_id": "u1", "tenant_id": "t1", "session_id": None, "not_before": iso(time.time())})
    with pytest.raises(InvalidToken, match="revoked"):
        v.verify(token)
    v.verify(iss.token("u1", tenant_id="t2", iat=old))  # another tenant
    v.verify(iss.token("u1", tenant_id="t1", iat=int(time.time()) + 2))  # issued after

    revs.add({"id": "r3", "user_id": "agent", "not_before": iso(time.time())})
    with pytest.raises(InvalidToken):
        v.verify(iss.token("u9", tenant_id="t1", iat=old, act={"sub": "agent", "kind": "agent"}))

    revs.add({"id": "old", "user_id": "x", "not_before": iso(time.time() - 3600)})
    assert len(revs) == 3
    assert not revs.apply({"type": "matura.user.updated", "data": {"object": "user", "user": {}}})


async def test_load_from_api():
    class API:
        async def revocations(self):
            return {"items": [{"id": "r1", "user_id": "u1", "tenant_id": None, "session_id": None,
                               "not_before": iso(time.time()), "reason": "requested"}]}

    revs = Revocations()
    await revs.load(API())
    assert len(revs) == 1 and revs.revoked({"sub": "u1", "iat": int(time.time()) - 5})
