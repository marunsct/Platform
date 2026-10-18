"""FastAPI integration: the verified principal as a dependency, permission checks and the webhook receiver."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from .contract import Contract
from .principal import Principal
from .signatures import BadSignature, verify
from .tokens import InvalidToken, Verifier, bearer


class MaturaFastAPI:
    """``principal`` is a FastAPI dependency; ``require_permission("workflow.write")`` another.

    ``on_principal`` (optional) runs after verification, for example to write the just-in-time contract rows.
    """

    def __init__(self, verifier: Verifier, *, on_principal: Callable[[Request, Principal], Any] | None = None):
        self.verifier = verifier
        self.on_principal = on_principal

    async def principal(self, request: Request) -> Principal:
        cached = getattr(request.state, "matura_principal", None)
        if cached is not None:
            return cached
        try:
            p = await self.verifier.averify(bearer(request.headers.get("authorization")))
        except InvalidToken as exc:
            raise HTTPException(401, str(exc), headers={"WWW-Authenticate": 'Bearer realm="matura"'}) from None
        if self.on_principal is not None:
            r = self.on_principal(request, p)
            if hasattr(r, "__await__"):
                await r
        request.state.matura_principal = p
        return p

    def require_permission(self, *perms: str) -> Callable[..., Any]:
        async def dep(request: Request) -> Principal:
            p = await self.principal(request)
            missing = [x for x in perms if not p.has(x)]
            if missing:
                raise HTTPException(403, f"you need the permission {', '.join(missing)}; ask a tenant admin for a "
                                         "role that includes it")
            return p
        return Depends(dep)

    def require_tenant(self) -> Callable[..., Any]:
        async def dep(request: Request) -> Principal:
            p = await self.principal(request)
            if not p.tenant_id:
                raise HTTPException(403, "choose an organisation first")
            return p
        return Depends(dep)


def webhook_router(secret: str | bytes, contract: Contract, begin: Any, path: str = "/matura/events", *,
                   revocations: Any = None) -> APIRouter:
    """``POST /matura/events``: verify the signature, then apply the event in one transaction (contract §10.2).

    ``revocations`` (a :class:`matura.Revocations`) gets each revocation event, so revoked tokens stop at once."""
    router = APIRouter()

    @router.post(path, include_in_schema=False)
    async def receive(request: Request) -> Response:
        body = await request.body()
        try:
            verify(secret, request.headers.get("matura-signature"), body)
        except BadSignature as exc:
            raise HTTPException(401, str(exc)) from None
        try:
            event = json.loads(body)
        except ValueError:
            raise HTTPException(400, "body is not JSON") from None
        if revocations is not None:
            revocations.apply(event)
        async with begin() as conn:
            await contract.apply(conn, event)
        return Response(status_code=204)

    return router
