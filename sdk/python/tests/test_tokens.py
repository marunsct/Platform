import json
from pathlib import Path

import pytest

from matura import BadSignature, InvalidToken, Principal, Verifier, sign, verify
from matura.testing import FakeIssuer


def test_verify_and_permissions():
    iss = FakeIssuer(audience="agentcanvas")
    v = Verifier(iss.issuer, "agentcanvas", jwks=iss.jwks)
    p = v.verify(iss.token("u1", tenant_id="t1", tenant="acme", perms=["workflow.read"], roles=["viewer"]))
    assert p.tenant_id == "t1" and p.tenant_slug == "acme" and p.has("workflow.read") and not p.has("workflow.write")
    admin = v.verify(iss.token("u2", tenant_id="t1", perms=["*"]))
    assert admin.has("anything.at.all")


@pytest.mark.parametrize("bad", ["wrong audience", "expired", "other issuer", "other key", "garbage"])
def test_refused(bad):
    iss = FakeIssuer(audience="agentcanvas")
    v = Verifier(iss.issuer, "agentcanvas", jwks=iss.jwks)
    token = {
        "wrong audience": lambda: iss.token(audience="devflow"),
        "expired": lambda: iss.token(ttl=-120),
        "other issuer": lambda: FakeIssuer(issuer="https://evil", audience="agentcanvas").token(),
        "other key": lambda: FakeIssuer(audience="agentcanvas").token(),
        "garbage": lambda: "not.a.token",
    }[bad]()
    with pytest.raises(InvalidToken):
        v.verify(token)


def test_perms_ref_expands_from_role_table():
    p = Principal.from_claims({"sub": "u", "roles": ["editor", "viewer"], "perms_ref": "matura_app_role"})
    assert not p.has("workflow.write")
    e = p.expand({"editor": ["workflow.write", "workflow.read"], "viewer": ["workflow.read"]})
    assert e.permissions == ("workflow.read", "workflow.write") and e.perms_ref is None


def test_shared_signature_vectors():
    v = json.loads((Path(__file__).parents[3] / "docs/contract/test-vectors.json").read_text())
    for s in v["signatures"]:
        ok = True
        try:
            verify(v["secret"], s["header"], s["body"].encode(), now=s["now"])
        except BadSignature:
            ok = False
        assert ok == s["valid"], s["name"]


def test_sign_roundtrip():
    h = sign("k", b"{}", at=1000)
    verify("k", h, b"{}", now=1100)
    with pytest.raises(BadSignature):
        verify("k", h, b"{}", now=2000)
