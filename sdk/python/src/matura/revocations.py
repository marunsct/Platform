"""Instant revocation (technical specification §21): refuse tokens Matura revoked before they expire."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any

#: How long a revocation matters: the longest token lifetime plus skew, with margin (seconds).
REVOCATION_WINDOW = 15 * 60


def _ts(v: Any) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).timestamp()


def covers(r: dict[str, Any], claims: dict[str, Any]) -> bool:
    """Whether revocation ``r`` stops a token with ``claims``: sub (or act.sub) is its user, tid its tenant when it
    names one, sid its session when it names one, and iat is at or before not_before."""
    iat = claims.get("iat")
    if not iat:
        return False
    act = claims.get("act") or {}
    if r.get("user_id") not in (claims.get("sub"), act.get("sub") if isinstance(act, dict) else None):
        return False
    if r.get("tenant_id") and r["tenant_id"] != claims.get("tid"):
        return False
    if r.get("session_id") and r["session_id"] != claims.get("sid"):
        return False
    return float(iat) <= _ts(r["not_before"])


class Revocations:
    """Recent revocations a :class:`matura.Verifier` consults (``Verifier(..., revocations=revs)``).

    Fill it at start with ``await revs.load(api)`` and keep it current with ``revs.apply(event)`` (the webhook router
    and :class:`matura.Sync` do this when given ``revocations=``) or by loading every few seconds. Thread-safe.
    """

    def __init__(self, now: Any = time.time):
        self._by_id: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._now = now

    def add(self, *revocations: dict[str, Any]) -> None:
        cutoff = self._now() - REVOCATION_WINDOW
        with self._lock:
            for k in [k for k, r in self._by_id.items() if _ts(r["not_before"]) < cutoff]:
                del self._by_id[k]
            for r in revocations:
                if r.get("id") and r.get("user_id") and _ts(r["not_before"]) >= cutoff:
                    self._by_id[r["id"]] = r

    def apply(self, event: dict[str, Any]) -> bool:
        """Add the revocation a ``matura.revocation.created`` event carries; other events are ignored."""
        if event.get("type") != "matura.revocation.created":
            return False
        data = event.get("data") or {}
        r = data.get("revocation")
        if not isinstance(r, dict):
            return False
        self.add(r)
        return True

    def revoked(self, claims: dict[str, Any]) -> bool:
        with self._lock:
            return any(covers(r, claims) for r in self._by_id.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    async def load(self, api: Any) -> None:
        """Fetch the app's recent revocations (``GET /v1/apps/{app}/revocations``) through a :class:`MaturaAPI`."""
        page = await api.revocations()
        self.add(*page.get("items") or [])
