"""Regenerate the token and apply sections of docs/contract/test-vectors.json (contract §10.2, TS7e).

Run from sdk/python:  uv run python ../../scripts/gen_contract_vectors.py

Tokens are signed with a throwaway key; only its public half is kept, so the file holds no private key. The expected
contract rows of the apply section come from the Python SDK applying the events to SQLite.
"""

from __future__ import annotations

import asyncio
import base64
import json
import pathlib

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from matura.contract import Contract, ddl

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILE = ROOT / "docs" / "contract" / "test-vectors.json"
ISSUER = "https://matura.test/realms/matura"
AUDIENCE = "notes"
NOW = 1792140360  # 2026-10-17T09:26:00Z
T1, T2 = "0192b7a4-6000-7000-8000-000000000001", "0192b7a4-6000-7000-8000-000000000002"
T3 = "0192b7a4-6000-7000-8000-000000000003"
U1 = "0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11"
W1 = "0192b7a4-7000-7000-8000-0000000000a1"
G1 = "0192b7a4-8000-7000-8000-0000000000b1"


def tokens() -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    pub.update({"kid": "test-key-1", "use": "sig", "alg": "RS256"})
    base = {"iss": ISSUER, "aud": AUDIENCE, "sub": U1, "iat": NOW - 60, "exp": NOW + 240, "azp": AUDIENCE,
            "email": "ada@example.test", "email_verified": True, "name": "Ada Lovelace", "tid": T1, "tenant": "acme",
            "wid": W1, "troles": ["admin"], "roles": ["editor"], "perms": ["note.read", "note.write"],
            "ver": {"u": 12, "m": 15, "t": 10}, "pmode": "shared", "sid": "sess-1"}

    def sign(claims: dict, k=key, kid="test-key-1", alg="RS256") -> str:
        return jwt.encode(claims, k, algorithm=alg, headers={"kid": kid})

    good = sign(base)
    h, p, s = good.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["perms"] = ["*"]
    tampered = h + "." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "." + s
    none = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT","kid":"test-key-1"}').decode().rstrip("=") + "." + p + ".")
    principal = {"user_id": U1, "tenant_id": T1, "tenant_slug": "acme", "workspace_id": W1, "tenant_roles": ["admin"],
                 "roles": ["editor"], "permissions": ["note.read", "note.write"], "email": "ada@example.test",
                 "placement_mode": "shared", "has": {"note.read": True, "note.write": True, "note.delete": False}}
    cases = [
        {"name": "valid", "token": good, "valid": True, "principal": principal},
        {"name": "wildcard permission", "token": sign({**base, "roles": ["admin"], "perms": ["*"]}), "valid": True,
         "principal": {**principal, "roles": ["admin"], "permissions": ["*"],
                       "has": {"note.read": True, "note.write": True, "note.delete": True}}},
        {"name": "no tenant (signed in, no tenant chosen)", "valid": True,
         "token": sign({k: v for k, v in base.items() if k not in ("tid", "tenant", "wid", "pmode")} | {"perms": []}),
         "principal": {**principal, "tenant_id": None, "tenant_slug": None, "workspace_id": None,
                       "placement_mode": None, "permissions": [],
                       "has": {"note.read": False, "note.write": False, "note.delete": False}}},
        {"name": "expired", "token": sign({**base, "iat": NOW - 900, "exp": NOW - 300}), "valid": False},
        {"name": "other audience", "token": sign({**base, "aud": "billing", "azp": "billing"}), "valid": False},
        {"name": "other issuer", "token": sign({**base, "iss": "https://evil.test/realms/matura"}), "valid": False},
        {"name": "payload changed after signing", "token": tampered, "valid": False},
        {"name": "signed by an unknown key", "token": sign(base, k=other), "valid": False},
        {"name": "alg none", "token": none, "valid": False},
        {"name": "missing sub", "token": sign({k: v for k, v in base.items() if k != "sub"}), "valid": False},
    ]
    return {"description": "Access tokens to verify with 'now', 'issuer', 'audience' and 'jwks' (contract §2). Accept "
                           "exactly the 'valid' ones (allow at most 30 s clock leeway); for those, the principal must "
                           "match and 'has' lists permission checks.",
            "issuer": ISSUER, "audience": AUDIENCE, "now": NOW, "jwks": {"keys": [pub]}, "cases": cases}


def ev(n: int, typ: str, obj: str, version: int, payload: dict, tenant: str | None = T1) -> dict:
    e = {"specversion": "1.0", "id": f"evt_{n}", "source": "matura://installation/main", "type": "matura." + typ,
         "time": "2026-10-17T09:00:00Z", "subject": f"test/{n}", "sequence": str(n), "datacontenttype": "application/json",
         "data": {"object": obj, "version": version, obj: payload}}
    if tenant:
        e["tenantid"] = tenant
    return e


def apply_section() -> dict:
    ts = "2026-10-17T09:00:00Z"
    tenant = {"id": T1, "slug": "acme", "name": "Acme", "kind": "company", "status": "active", "plan": None,
              "data_mode_default": "shared", "updated_at": ts}
    events = [
        ev(1, "tenant.created", "tenant", 10, tenant),
        ev(2, "user.updated", "user", 12, {"id": U1, "email": "ada@example.test", "email_verified": True,
                                           "display_name": "Ada", "kind": "human", "status": "active",
                                           "updated_at": ts}, tenant=None),
        ev(3, "membership.updated", "membership", 15, {"tenant_id": T1, "user_id": U1, "tenant_role": "admin",
                                                       "status": "active", "joined_at": ts, "updated_at": ts}),
        ev(4, "membership.added", "membership", 13, {"tenant_id": T1, "user_id": U1, "tenant_role": "member",
                                                     "status": "active", "joined_at": ts, "updated_at": ts}),
        ev(2, "user.updated", "user", 12, {"id": U1, "email": "ada@example.test", "email_verified": True,
                                           "display_name": "Ada", "kind": "human", "status": "active",
                                           "updated_at": ts}, tenant=None),
        ev(5, "tenant.updated", "tenant", 9, {**tenant, "name": "Stale name"}),
        ev(6, "workspace.created", "workspace", 11, {"id": W1, "tenant_id": T1, "name": "Lab", "status": "active",
                                                     "is_default": False, "updated_at": ts}),
        ev(7, "app.role.created", "app_role", 5, {"name": "editor", "description": "Edits notes",
                                                  "permissions": ["note.read", "note.write"], "is_default": False},
           tenant=None),
        ev(8, "grant.added", "grant", 16, {"id": G1, "tenant_id": T1, "workspace_id": W1, "subject_type": "user",
                                           "subject_id": U1, "role": "editor", "status": "active", "updated_at": ts}),
        ev(9, "grant.revoked", "grant", 18, {"id": G1, "tenant_id": T1, "workspace_id": W1, "subject_type": "user",
                                              "subject_id": U1, "role": "editor", "status": "revoked",
                                              "updated_at": ts}),
        ev(10, "app.role.updated", "app_role", 20, {"role": {"name": "author", "description": "Writes notes",
                                                            "permissions": ["note.read", "note.write"],
                                                            "is_default": True}, "previous_name": "editor"},
           tenant=None),
        ev(11, "membership.added", "membership", 31, {"tenant_id": T2, "user_id": U1, "tenant_role": "member",
                                                      "status": "active", "joined_at": ts, "updated_at": ts},
           tenant=T2),
        ev(12, "tenant.created", "tenant", 30, {**tenant, "id": T2, "slug": "globex", "name": "Globex"}, tenant=T2),
        ev(13, "placement.provisioned", "placement", 32, {"tenant_id": T2, "app_id": "x", "mode": "database",
                                                          "state": "provisioned"}, tenant=T2),
        # placements have their own version: an older one arriving late changes nothing, and a newer tenant change
        # keeps the placement's data_mode (its data_mode_default is only the tenant's default)
        ev(14, "placement.requested", "placement", 29, {"tenant_id": T2, "app_id": "x", "mode": "schema",
                                                        "state": "requested"}, tenant=T2),
        ev(15, "tenant.updated", "tenant", 40, {**tenant, "id": T2, "slug": "globex", "name": "Globex Corp"},
           tenant=T2),
        # a placement before its tenant: the tenant stub keeps the mode, and the tenant created later fills the rest
        ev(16, "placement.provisioned", "placement", 52, {"tenant_id": T3, "app_id": "x", "mode": "schema",
                                                          "state": "provisioned"}, tenant=T3),
        ev(17, "tenant.created", "tenant", 50, {**tenant, "id": T3, "slug": "initech", "name": "Initech"},
           tenant=T3),
        ev(18, "placement.requested", "placement", 51, {"tenant_id": T3, "app_id": "x", "mode": "database",
                                                        "state": "requested"}, tenant=T3),
    ]
    queries = {
        "matura_tenant": ("SELECT id, slug, name, kind, status, plan, data_mode, version, placement_version "
                          "FROM matura_tenant ORDER BY id"),
        "matura_user": "SELECT id, email, display_name, status, version FROM matura_user ORDER BY id",
        "matura_membership": "SELECT tenant_id, user_id, tenant_role, status, version FROM matura_membership "
                             "ORDER BY tenant_id, user_id",
        "matura_workspace": "SELECT id, tenant_id, name, status, version FROM matura_workspace ORDER BY id",
        "matura_role_grant": "SELECT id, tenant_id, workspace_id, subject_id, role, status, version "
                             "FROM matura_role_grant ORDER BY id",
        "matura_app_role": "SELECT name, permissions, is_default, status, version FROM matura_app_role ORDER BY name",
    }

    async def run() -> dict:
        from sqlalchemy import create_engine, text

        eng = create_engine("sqlite://")
        c = Contract("sqlite")
        applied = []
        with eng.begin() as conn:
            for stmt in ddl("sqlite"):
                conn.execute(text(stmt))
            for e in events:
                applied.append(await c.apply(conn, e))
            out = {}
            for table, q in queries.items():
                res = conn.execute(text(q))
                cols = list(res.keys())
                rows = []
                for r in res:
                    row = dict(zip(cols, r, strict=True))
                    if "permissions" in row:
                        row["permissions"] = json.loads(row["permissions"])
                    if "is_default" in row:
                        row["is_default"] = bool(row["is_default"])
                    rows.append(row)
                out[table] = rows
        return {"applied": applied, "rows": out}

    result = asyncio.run(run())
    return {"description": "Apply these events in this order (contract §5): skip an event id already applied, keep a "
                           "row only when its version is newer, create missing tenant/user/workspace rows as stubs "
                           "with version 0, rename grants with an app role (a rename follows the grant events "
                           "before it, as webhooks and the feed deliver them in commit order), and set a tenant's data_mode from "
                           "a placement only when the placement's version is newer than placement_version (tenant "
                           "changes then keep it). 'applied' says which events are new; "
                           "'rows' is the final state of the listed columns (stub names are the id).",
            "events": events, "applied": result["applied"], "rows": result["rows"]}


def main() -> None:
    vectors = json.loads(FILE.read_text())
    vectors["description"] = ("Test vectors for any Matura integration (contract §10): webhook signatures, access "
                              "tokens and applying events to the contract tables. Every SDK runs them.")
    vectors["tokens"] = tokens()
    vectors["apply"] = apply_section()
    FILE.write_text(json.dumps(vectors, indent=2) + "\n")


if __name__ == "__main__":
    main()
