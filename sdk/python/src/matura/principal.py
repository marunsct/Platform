"""The verified caller of a request (contract §2, §8)."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any


KINDS = ("human", "service", "agent")


@dataclass(frozen=True)
class Actor:
    """The agent acting for the token's subject in a delegated token (the ``act`` claim, RFC 8693 §4.1)."""

    sub: str
    kind: str = "agent"
    client_id: str | None = None

    @classmethod
    def from_claim(cls, act: Any) -> Actor | None:
        if not isinstance(act, dict) or not act.get("sub"):
            return None
        kind = act.get("kind") if act.get("kind") in ("service", "agent") else "agent"
        return cls(sub=str(act["sub"]), kind=kind, client_id=act.get("client_id"))


def _kind(c: dict[str, Any]) -> str:
    if c.get("kind") in KINDS:
        return c["kind"]
    # tokens from before agent identity: a client-credentials token has client_id and no email
    return "service" if "client_id" in c and "email" not in c else "human"


@dataclass(frozen=True)
class Principal:
    """Who is calling and what they may do, read from a verified Matura access token.

    Apps check ``permissions`` (the token's ``perms``), never role names: roles are defined and edited in Matura,
    permissions are what the app's code declares (ADR 0008).

    ``kind`` is what ``user_id`` is: ``human``, ``service`` (a tenant service account) or ``agent`` (an AI agent).
    ``actor`` is set on a delegated token: an agent acting for the person in ``user_id``; its ``permissions`` are
    already only those both have. Record both in your audit log.
    """

    user_id: str
    tenant_id: str | None
    tenant_slug: str | None
    workspace_id: str | None
    tenant_roles: tuple[str, ...]
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    perms_ref: str | None = None
    email: str = ""
    email_verified: bool = False
    name: str | None = None
    versions: dict[str, int] = field(default_factory=dict)
    placement_mode: str | None = None
    mfa: bool = False
    session_id: str | None = None
    client_id: str | None = None
    is_service: bool = False
    kind: str = "human"
    actor: Actor | None = None
    claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_claims(cls, c: dict[str, Any]) -> Principal:
        amr = c.get("amr") or []
        return cls(
            user_id=str(c["sub"]),
            tenant_id=c.get("tid"),
            tenant_slug=c.get("tenant"),
            workspace_id=c.get("wid"),
            tenant_roles=tuple(c.get("troles") or ()),
            roles=tuple(c.get("roles") or ()),
            permissions=tuple(c.get("perms") or ()),
            perms_ref=c.get("perms_ref"),
            email=c.get("email") or "",
            email_verified=c.get("email_verified") is True,
            name=c.get("name"),
            versions={k: int(v) for k, v in (c.get("ver") or {}).items()},
            placement_mode=c.get("pmode"),
            mfa="mfa" in amr or "otp" in amr or "hwk" in amr or str(c.get("acr", "")) in ("2", "3"),
            session_id=c.get("sid"),
            client_id=c.get("azp") or c.get("client_id"),
            is_service=_kind(c) != "human",
            kind=_kind(c),
            actor=Actor.from_claim(c.get("act")),
            claims=c,
        )

    @property
    def is_delegated(self) -> bool:
        """True when an agent acts for the person in ``user_id`` (the token has ``act``)."""
        return self.actor is not None

    def has(self, permission: str) -> bool:
        """True when the token grants ``permission`` (or ``*``). With ``perms_ref`` use :meth:`expand` first."""
        return "*" in self.permissions or permission in self.permissions

    def has_tenant_role(self, *roles: str) -> bool:
        return any(r in self.tenant_roles for r in roles)

    def expand(self, role_permissions: dict[str, list[str]]) -> Principal:
        """Fill ``permissions`` from the app's role table when the token carried ``perms_ref`` (over 40 perms)."""
        if not self.perms_ref:
            return self
        perms: set[str] = set()
        for r in self.roles:
            perms.update(role_permissions.get(r, ()))
        out = ("*",) if "*" in perms else tuple(sorted(perms))
        return replace(self, permissions=out, perms_ref=None)
