"""Matura SDK for Python (contract: docs/spec/03-app-integration-contract.md)."""

from .contract import CONTRACT_VERSION, Contract, ddl
from .feed import CursorExpired, MaturaAPI, Sync, snapshot_events
from .principal import Principal
from .signatures import BadSignature, sign, verify
from .tokens import InvalidToken, Verifier, bearer

__all__ = [
    "CONTRACT_VERSION", "BadSignature", "Contract", "CursorExpired", "InvalidToken", "MaturaAPI", "Principal", "Sync",
    "Verifier", "bearer", "ddl", "sign", "snapshot_events", "verify",
]
__version__ = "0.1.0"
