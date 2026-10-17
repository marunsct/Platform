"""A fake Matura issuer for tests: mint tokens for any tenant, roles and permissions without Keycloak."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from .signatures import sign


class FakeIssuer:
    """Signs tokens shaped like Matura's (contract §2). Pass ``issuer.jwks`` to :class:`matura.Verifier`."""

    def __init__(self, issuer: str = "https://matura.test/realms/matura", audience: str = "app"):
        self.issuer = issuer
        self.audience = audience
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = uuid.uuid4().hex[:16]
        pub = json.loads(RSAAlgorithm.to_jwk(self._key.public_key()))
        pub.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        self.jwks: dict[str, Any] = {"keys": [pub]}

    def token(
        self,
        user_id: str | None = None,
        *,
        tenant_id: str | None = None,
        tenant: str | None = None,
        workspace_id: str | None = None,
        tenant_roles: list[str] | None = None,
        roles: list[str] | None = None,
        perms: list[str] | None = None,
        email: str | None = None,
        name: str | None = None,
        ttl: int = 300,
        audience: str | None = None,
        **extra: Any,
    ) -> str:
        now = int(time.time())
        sub = user_id or str(uuid.uuid4())
        claims: dict[str, Any] = {
            "iss": self.issuer, "aud": audience or self.audience, "sub": sub, "iat": now, "exp": now + ttl,
            "email": email or f"{sub[:8]}@example.test", "email_verified": True, "name": name or "Test User",
            "troles": tenant_roles or ["member"], "roles": roles or [], "perms": perms or [],
            "ver": {"u": 1, "m": 1, "t": 1}, "azp": audience or self.audience,
        }
        if tenant_id:
            claims.update({"tid": tenant_id, "tenant": tenant or tenant_id[:8], "pmode": "shared"})
        if workspace_id:
            claims["wid"] = workspace_id
        claims.update(extra)
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})


def signed_event(secret: str, event: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    """Body and headers of a webhook as Matura sends it, for testing a receiver."""
    body = json.dumps(event).encode()
    return body, {"Matura-Signature": sign(secret, body), "Matura-Event-Id": event.get("id", ""),
                  "Content-Type": "application/cloudevents+json"}
