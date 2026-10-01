from __future__ import annotations

from fastapi import APIRouter, Depends

from cyclothone.data_trust.channels import DESTINATION_TYPES, SOURCE_TYPES
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request

router = APIRouter(prefix="/data-trust", tags=["data-trust"])


@router.get("/channels")
async def list_channels(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict[str, list[str]]:
    principal.require(("data:transfer",))
    return {
        "sources": sorted(SOURCE_TYPES),
        "destinations": sorted(DESTINATION_TYPES),
    }
