"""OAuth 2.0 Protected Resource Metadata (RFC 9728) for an app's API or MCP server (TS15).

An app that exposes an MCP server, or any API agents call, serves this document at
``/.well-known/oauth-protected-resource`` and points 401 answers at it, so clients find the Keycloak realm that
issues tokens for it. See docs/guide/agents.md.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

WELL_KNOWN = "/.well-known/oauth-protected-resource"


def metadata_url(resource: str) -> str:
    """Where RFC 9728 §3.1 puts a resource's metadata: the well-known path between the host and the resource's path."""
    u = urlsplit(resource)
    if not u.scheme or not u.netloc:
        raise ValueError(f"resource {resource!r} is not an absolute URL")
    return urlunsplit((u.scheme, u.netloc, WELL_KNOWN + u.path.rstrip("/"), "", ""))


def protected_resource_metadata(
    resource: str,
    authorization_servers: list[str],
    *,
    scopes_supported: list[str] | None = None,
    resource_name: str | None = None,
    resource_documentation: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """The metadata document: ``resource`` is the app's identifier (its MCP server URL, also listed in the manifest's
    ``auth.resources``), ``authorization_servers`` the Matura realm's issuer URL."""
    if not authorization_servers:
        raise ValueError("name at least one authorization server (the Matura realm's issuer URL)")
    doc: dict[str, Any] = {"resource": resource, "authorization_servers": list(authorization_servers),
                           "bearer_methods_supported": ["header"]}
    if scopes_supported:
        doc["scopes_supported"] = list(scopes_supported)
    if resource_name:
        doc["resource_name"] = resource_name
    if resource_documentation:
        doc["resource_documentation"] = resource_documentation
    doc.update(extra)
    return doc


def _quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def www_authenticate(
    resource: str,
    *,
    error: str | None = None,
    error_description: str | None = None,
    scope: str | None = None,
    realm: str | None = None,
) -> str:
    """The ``WWW-Authenticate`` value of a 401 (or 403 with ``error="insufficient_scope"``) that points the client at
    the resource's metadata (RFC 9728 §5.1, RFC 6750 §3)."""
    params = []
    if realm:
        params.append(f"realm={_quote(realm)}")
    params.append(f"resource_metadata={_quote(metadata_url(resource))}")
    if error:
        params.append(f"error={_quote(error)}")
    if error_description:
        params.append(f"error_description={_quote(error_description)}")
    if scope:
        params.append(f"scope={_quote(scope)}")
    return "Bearer " + ", ".join(params)
