"""Access-token verification against the Matura realm's signing keys (contract §2, level 1)."""

from __future__ import annotations

import asyncio
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKSet

from .principal import Principal
from .revocations import Revocations

ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]


class InvalidToken(Exception):
    """The token is missing, malformed, expired, for another audience or signed by an unknown key (answer 401)."""


class Verifier:
    """Verifies Matura access tokens: signature (JWKS, cached), issuer, audience (the app's client id), expiry.

    ``jwks`` (a JWK Set dict) skips the network, for tests with :class:`matura.testing.FakeIssuer`.
    ``revocations`` (a :class:`matura.Revocations`) makes revoked tokens fail before they expire.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_url: str | None = None,
        jwks: dict[str, Any] | None = None,
        leeway: int = 30,
        jwks_cache_seconds: int = 300,
        revocations: Revocations | None = None,
    ):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.leeway = leeway
        self.revocations = revocations
        self._static = PyJWKSet.from_dict(jwks) if jwks is not None else None
        url = jwks_url or f"{self.issuer}/protocol/openid-connect/certs"
        self._client = None if self._static else PyJWKClient(url, cache_jwk_set=True, lifespan=jwks_cache_seconds)

    def _key(self, token: str) -> Any:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError:
            raise InvalidToken("malformed token") from None
        if self._static is not None:
            for k in self._static.keys:
                if kid is None or k.key_id == kid:
                    return k.key
            raise InvalidToken("token signed with an unknown key")
        assert self._client is not None
        try:
            return self._client.get_signing_key_from_jwt(token).key
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"cannot find the token's signing key: {exc}") from None

    def verify(self, token: str) -> Principal:
        """Verify synchronously (fetches keys on a cache miss)."""
        key = self._key(token)
        try:
            claims = jwt.decode(
                token, key, algorithms=ALGORITHMS, audience=self.audience, issuer=self.issuer, leeway=self.leeway,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise InvalidToken("token expired") from None
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"invalid token: {exc}") from None
        if self.revocations is not None and self.revocations.revoked(claims):
            raise InvalidToken("token revoked")
        return Principal.from_claims(claims)

    async def averify(self, token: str) -> Principal:
        """Verify without blocking the event loop when keys must be fetched."""
        if self._static is not None:
            return self.verify(token)
        return await asyncio.to_thread(self.verify, token)


def bearer(authorization: str | None) -> str:
    """The token of an ``Authorization: Bearer …`` header."""
    if not authorization:
        raise InvalidToken("sign in: send Authorization: Bearer <token>")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise InvalidToken("expected Authorization: Bearer <token>")
    return token.strip()
