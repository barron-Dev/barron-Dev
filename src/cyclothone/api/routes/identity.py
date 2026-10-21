from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase
from cyclothone.api.routes.identity_investigation import router as identity_investigation_router

router = APIRouter(tags=["identity"])


def principal(p: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    p.require(("console:read",))
    return p


router.include_router(identity_investigation_router)

@router.get("/identity/context")
async def identity_context(p: DeveloperPrincipal = Depends(principal)):
    if not p.user_id:
        raise HTTPException(403, detail="user_identity_required")

    rows = await supabase.rpc(
        "resolve_canonical_identity",
        {
            "p_user_id": p.user_id,
            "p_tenant_id": p.tenant_id,
        },
    )

    return {
        "authoritative_boundary": "tenant",
        "identity_model": {
            "security_workspace": "tenant",
            "business_customer": "customer_organization",
            "machine_trust": "trust_subject",
        },
        "identities": rows or [],
    }
