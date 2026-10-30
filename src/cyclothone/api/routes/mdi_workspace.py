from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException

from cyclothone.api.routes.customer_identity import principal as customer_principal
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/mdi", tags=["mobile-digital-intelligence"])
_LIMIT = 100


async def _workspace(tenant_id: str) -> dict:
    """Read persisted MDI records for one server-authenticated tenant."""
    try:
        devices = await supabase.select_recent(
            "mdi_devices",
            "id,device_key,platform,os_version,app_version,last_attestation,last_seen_at,created_at",
            tenant_id=tenant_id, order_by="last_seen_at", limit=_LIMIT,
        )
        threats = await supabase.select_recent(
            "mdi_device_threats",
            "id,device_id,threat_type,severity_level,disposition,evidence_hash,journal_contract_id,rule_version,source_adapter_version,observed_at,persisted_at",
            tenant_id=tenant_id, order_by="observed_at", limit=_LIMIT,
        )
        journal = await supabase.select_recent(
            "mdi_journal_events",
            "id,contract_id,event_type,disposition,evidence_hash,previous_hash,current_hash,signer_key_id,created_at,persisted_at",
            tenant_id=tenant_id, order_by="persisted_at", limit=_LIMIT,
        )
    except Exception as exc:
        # Missing migrations or unavailable storage are not empty/healthy states.
        raise HTTPException(status_code=503, detail="mdi_storage_unavailable") from exc
    return {
        "service": "mobile_digital_intelligence",
        "tenant_id": tenant_id,
        "data_state": "records_available" if devices or threats or journal else "no_operational_records",
        "coverage": {
            "devices_returned": len(devices),
            "threats_returned": len(threats),
            "journal_events_returned": len(journal),
            "per_collection_limit": _LIMIT,
            "truncated_possible": any(len(rows) == _LIMIT for rows in (devices, threats, journal)),
        },
        "devices": devices,
        "threats": threats,
        "journal_events": journal,
        "enforcement": {
            "native_attestation_pipeline": "not_verified",
            "remote_response_execution": "not_implemented",
            "client_claims_authorize_enforcement": False,
        },
    }


@router.get("/workspace")
async def customer_workspace(p: DeveloperPrincipal = Depends(customer_principal)):
    if not p.tenant_id:
        raise HTTPException(status_code=403, detail="workspace_not_admitted")
    return await _workspace(p.tenant_id)


async def _developer_or_customer(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> DeveloperPrincipal:
    try:
        p = await authenticate_request(authorization=authorization, x_api_key=x_api_key)
        p.require(("mobile:intelligence",))
        return p
    except HTTPException as exc:
        if exc.status_code not in {401, 403}:
            raise
    # Browser developer portal uses the authenticated Supabase user session.
    p = await customer_principal(authorization)
    if not p.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_context_required")
    return p


@router.get("/developer-workspace")
async def developer_workspace(p: DeveloperPrincipal = Depends(_developer_or_customer)):
    if p.auth_type != "customer":
        p.require(("mobile:intelligence",))
    if not p.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_context_required")
    result = await _workspace(p.tenant_id)
    return {
        **result,
        "integration": {
            "required_scope": "mobile:intelligence",
            "read_endpoint": "/api/v1/mdi/developer-workspace",
            "customer_endpoint": "/api/v1/mdi/workspace",
            "write_contract": "disabled_until_trusted_native_adapter_and_signature_verification_are_deployed",
        },
    }
