"""Webhook signatures (contract §6, §10.2): ``Matura-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">``."""

from __future__ import annotations

import hashlib
import hmac
import time

TOLERANCE_SECONDS = 300


class BadSignature(Exception):
    """The webhook is not from Matura, was changed, or is too old (answer 401 and do not apply it)."""


def sign(secret: str | bytes, body: bytes, at: int | None = None) -> str:
    key = secret.encode() if isinstance(secret, str) else secret
    t = str(int(time.time()) if at is None else at)
    return f"t={t},v1=" + hmac.new(key, t.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify(secret: str | bytes, header: str | None, body: bytes, now: float | None = None) -> None:
    """Raise :class:`BadSignature` unless ``header`` signs ``body`` with ``secret`` within five minutes."""
    if not header:
        raise BadSignature("missing Matura-Signature")
    key = secret.encode() if isinstance(secret, str) else secret
    t, sigs = "", []
    for part in header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            t = v
        elif k == "v1":
            sigs.append(v)
    if not t.isdigit() or not sigs:
        raise BadSignature("malformed Matura-Signature")
    if abs((time.time() if now is None else now) - int(t)) > TOLERANCE_SECONDS:
        raise BadSignature("signature timestamp is too old or in the future")
    want = hmac.new(key, t.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(want, s) for s in sigs):
        raise BadSignature("signature does not match")
