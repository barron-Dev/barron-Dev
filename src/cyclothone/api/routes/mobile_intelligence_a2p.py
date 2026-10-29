"""Tenant-authenticated MDI API-client integrity endpoint; not carrier SMS verification."""
from __future__ import annotations
import base64, json, os
from fastapi import APIRouter, Depends, Header, HTTPException
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.mdi_ingestion.a2p_verifier import A2PValidationError, verify_request_signature

router=APIRouter(prefix="/mobile-intelligence/a2p",tags=["mobile-intelligence-a2p"])

def _tenant_secret(tenant_id: str) -> bytes:
    try:
        values=json.loads(os.environ.get("CYCLOTHONE_MDI_A2P_TENANT_KEYS_JSON","{}"))
        key=base64.b64decode(values[tenant_id],validate=True)
        if len(key)<32: raise ValueError("short key")
        return key
    except Exception as exc:
        raise HTTPException(503,"a2p_integrity_key_not_configured") from exc

@router.post("/request-integrity/verify")
async def verify_a2p_request(payload: dict, x_mdi_signature: str=Header(default=""),
                             p: DeveloperPrincipal=Depends(authenticate_request)):
    p.require(("mobile:intelligence",))
    if not p.tenant_id or str(payload.get("tenant_id",""))!=str(p.tenant_id):
        raise HTTPException(403,"tenant_scope_mismatch")
    try:
        result=verify_request_signature(payload,x_mdi_signature,_tenant_secret(str(p.tenant_id)))
    except A2PValidationError as exc:
        raise HTTPException(422,str(exc)) from exc
    if not result.accepted:
        raise HTTPException(401,detail={"error":result.reason_code,"payload_sha256":result.payload_sha256})
    return {"status":result.disposition,"reason_code":result.reason_code,
            "payload_sha256":result.payload_sha256,
            "carrier_origin_verified":False,
            "delivery_performed":False,
            "note":"API client request authenticated only; carrier origin and delivery require a separately contracted provider integration."}
