"""Agent identity in the Python SDK (TS15): principal kind and actor, protected-resource metadata."""

import pytest

from matura import Actor, Principal, Verifier, metadata_url, protected_resource_metadata, www_authenticate
from matura.testing import FakeIssuer

AGENT = "0192b7a4-0000-7000-8000-00000000a6e7"


def test_agent_and_delegated_principals():
    iss = FakeIssuer(audience="agentcanvas")
    v = Verifier(iss.issuer, "agentcanvas", jwks=iss.jwks)
    own = v.verify(iss.token(AGENT, tenant_id="t1", perms=["run.start"], kind="agent", email=None))
    assert own.kind == "agent" and own.actor is None and not own.is_delegated and own.is_service

    act = {"sub": AGENT, "kind": "agent", "client_id": "agent-3f9c2a1b7d4e"}
    d = v.verify(iss.token("u1", tenant_id="t1", perms=["workflow.read"], kind="human", act=act))
    assert d.kind == "human" and d.is_delegated and not d.is_service
    assert d.actor == Actor(sub=AGENT, kind="agent", client_id="agent-3f9c2a1b7d4e")
    assert d.has("workflow.read") and not d.has("run.start")


def test_kind_defaults():
    assert Principal.from_claims({"sub": "u", "email": "a@b.c"}).kind == "human"
    # a client-credentials token from before agent identity
    assert Principal.from_claims({"sub": "u", "client_id": "worker"}).kind == "service"
    assert Principal.from_claims({"sub": "u", "kind": "robot"}).kind == "human"
    p = Principal.from_claims({"sub": "u", "act": {"sub": AGENT}})
    assert p.actor == Actor(sub=AGENT, kind="agent", client_id=None)
    assert Principal.from_claims({"sub": "u", "act": "nonsense"}).actor is None


def test_protected_resource_metadata():
    assert metadata_url("https://canvas.example.com") == "https://canvas.example.com/.well-known/oauth-protected-resource"
    assert metadata_url("https://canvas.example.com/mcp/") == \
        "https://canvas.example.com/.well-known/oauth-protected-resource/mcp"
    with pytest.raises(ValueError):
        metadata_url("/mcp")
    doc = protected_resource_metadata("https://canvas.example.com/mcp", ["https://id.example.com/realms/matura"],
                                      scopes_supported=["openid"], resource_name="AgentCanvas MCP")
    assert doc == {"resource": "https://canvas.example.com/mcp",
                   "authorization_servers": ["https://id.example.com/realms/matura"],
                   "bearer_methods_supported": ["header"], "scopes_supported": ["openid"],
                   "resource_name": "AgentCanvas MCP"}
    with pytest.raises(ValueError):
        protected_resource_metadata("https://x.example", [])
    assert www_authenticate("https://canvas.example.com/mcp") == \
        'Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp"'
    assert www_authenticate("https://canvas.example.com/mcp", error="insufficient_scope", scope='a "b"') == (
        'Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp", '
        'error="insufficient_scope", scope="a \\"b\\""')
