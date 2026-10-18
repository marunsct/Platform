"""Matura SDK for Python (contract: docs/spec/03-app-integration-contract.md)."""

from .contract import CONTRACT_VERSION, Contract, ddl
from .feed import CursorExpired, MaturaAPI, Sync, snapshot_events
from .principal import Actor, Principal
from .resource import metadata_url, protected_resource_metadata, www_authenticate
from .revocations import REVOCATION_WINDOW, Revocations
from .signatures import BadSignature, sign, verify
from .tokens import InvalidToken, Verifier, bearer

__all__ = [
    "CONTRACT_VERSION", "REVOCATION_WINDOW", "Actor", "BadSignature", "Contract", "CursorExpired", "InvalidToken",
    "MaturaAPI", "Principal", "Revocations", "Sync", "Verifier", "bearer", "ddl", "metadata_url", "protected_resource_metadata", "sign", "snapshot_events",
    "verify", "www_authenticate",
]
__version__ = "0.1.0"
