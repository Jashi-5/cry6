"""API-key authentication for services calling sensitive endpoints."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app.config import get_settings
from app.core.exceptions import UnauthorizedServiceError


@dataclass(frozen=True)
class ServiceIdentity:
    service_id: str
    tenants: tuple[str, ...]

    def can_access(self, tenant_id: str) -> bool:
        return "*" in self.tenants or tenant_id in self.tenants


def authenticate(api_key: str | None) -> ServiceIdentity | None:
    """Return the service that owns this key, or None."""
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    found = None
    for service_id, entry in get_settings().service_api_keys.items():
        # No early exit, so timing does not reveal which entry matched.
        if hmac.compare_digest(digest, entry.key_sha256.lower()):
            found = ServiceIdentity(service_id, tuple(entry.tenants))
    return found


async def require_service(x_api_key: str | None = Header(default=None)) -> ServiceIdentity:
    """FastAPI dependency: reject the request unless it carries a valid X-API-Key."""
    identity = authenticate(x_api_key)
    if identity is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "A valid X-API-Key header is required.")
    return identity


async def require_service_outside_development(
    x_api_key: str | None = Header(default=None),
) -> ServiceIdentity | None:
    """
    For /protect and /analyze. The local demo page calls these from the browser, which
    cannot hold a key, so development stays open. Everywhere else an open endpoint would
    let anyone reverse tokens by trying guesses.
    """
    if get_settings().is_development():
        return None
    return await require_service(x_api_key)


def require_tenant(identity: ServiceIdentity, tenant_id: str) -> None:
    if not identity.can_access(tenant_id):
        raise UnauthorizedServiceError(
            f"Service '{identity.service_id}' may not act for tenant '{tenant_id}'."
        )
