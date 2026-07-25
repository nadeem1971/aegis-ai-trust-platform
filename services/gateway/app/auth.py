"""
Identity and access control (threat model T-07, T-10).

Two modes:
  * entra  — validates Entra ID JWTs (RS256) against the tenant JWKS, maps
             app-role claims to AEGIS roles.
  * dev    — local development only: a signed local JWT with the same claim
             shape, so RBAC logic is exercised identically without a tenant.
             Refuses to start if AEGIS_ENV is not 'dev'.

Roles (least privilege, per threat model):
  business_user    — may call /v1/chat; sees only its own audit entries
  security_analyst — may call /v1/chat; may read the audit trail
  auditor          — READ ONLY: audit trail and chain verification, no model access
  platform_admin   — full access including chain verification and config
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from .config import settings


class Role(StrEnum):
    BUSINESS_USER = "business_user"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    PLATFORM_ADMIN = "platform_admin"


# Capability model — the single source of truth for authorization decisions.
CAPABILITIES: dict[str, set[Role]] = {
    "model:invoke": {Role.BUSINESS_USER, Role.SECURITY_ANALYST, Role.PLATFORM_ADMIN},
    "audit:read": {Role.SECURITY_ANALYST, Role.AUDITOR, Role.PLATFORM_ADMIN},
    "audit:verify": {Role.AUDITOR, Role.PLATFORM_ADMIN},
    "admin:config": {Role.PLATFORM_ADMIN},
}


@dataclass(frozen=True)
class Principal:
    subject: str
    name: str
    roles: frozenset[Role]

    def has(self, capability: str) -> bool:
        allowed = CAPABILITIES.get(capability, set())
        return bool(self.roles & allowed)


bearer_scheme = HTTPBearer(auto_error=True)

_jwk_client: PyJWKClient | None = None


def _get_jwk_client() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(
            f"https://login.microsoftonline.com/{settings.entra_tenant_id}/discovery/v2.0/keys"
        )
    return _jwk_client


def _decode_entra(token: str) -> dict[str, Any]:
    signing_key = _get_jwk_client().get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.entra_audience,
        issuer=f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0",
    )


def _decode_dev(token: str) -> dict[str, Any]:
    if settings.aegis_env != "dev":
        raise RuntimeError("dev auth mode is forbidden outside AEGIS_ENV=dev")
    return jwt.decode(token, settings.dev_jwt_secret, algorithms=["HS256"], audience="aegis-gateway")


def _claims_to_principal(claims: dict[str, Any]) -> Principal:
    raw_roles = claims.get("roles") or []
    roles: set[Role] = set()
    for r in raw_roles:
        try:
            roles.add(Role(r))
        except ValueError:
            continue  # unknown role claims are ignored, never granted

    if not roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No recognized AEGIS role assigned to this identity.",
        )

    return Principal(
        subject=claims.get("sub", "unknown"),
        name=claims.get("name") or claims.get("preferred_username") or "unknown",
        roles=frozenset(roles),
    )


async def get_principal(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> Principal:
    token = credentials.credentials
    try:
        claims = _decode_dev(token) if settings.auth_mode == "dev" else _decode_entra(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}")
    return _claims_to_principal(claims)


def requires(capability: str):
    """Dependency factory enforcing a capability. Denials are audited by the
    caller so that failed authorization attempts are themselves evidence."""

    async def _guard(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if not principal.has(capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Capability '{capability}' not granted to roles {sorted(principal.roles)}",
            )
        return principal

    return _guard


def mint_dev_token(subject: str, name: str, roles: list[str], ttl_seconds: int = 3600) -> str:
    """Local development helper — mirrors the Entra claim shape exactly."""
    if settings.aegis_env != "dev":
        raise RuntimeError("dev token minting is forbidden outside AEGIS_ENV=dev")
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "name": name,
            "roles": roles,
            "aud": "aegis-gateway",
            "iat": now,
            "exp": now + ttl_seconds,
        },
        settings.dev_jwt_secret,
        algorithm="HS256",
    )
