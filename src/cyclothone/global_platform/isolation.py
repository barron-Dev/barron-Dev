from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from uuid import UUID

@dataclass(frozen=True)
class IsolationCheck:
    tenant_id: UUID
    resource_tenant: UUID
    resource_kind: str
    resource_id: str
    allowed: bool
    reason: str

class TenantIsolationGuard:
    def check(self, caller_tenant: UUID, resource_tenant: UUID, resource_kind: str, resource_id: str) -> IsolationCheck:
        allowed = caller_tenant == resource_tenant
        return IsolationCheck(caller_tenant, resource_tenant, resource_kind, resource_id, allowed, "same-tenant" if allowed else "tenant-mismatch")
    def deny_all_but(self, caller_tenant: UUID, tenant_ids: list[UUID]) -> UUID:
        if set(tenant_ids) != {caller_tenant}:
            raise PermissionError("multi-tenant query forbidden")
        return caller_tenant

def tenant_scoped_hash(value: str, tenant_id: UUID) -> str:
    return hmac.new(str(tenant_id).encode(), value.encode(), hashlib.sha256).hexdigest()
