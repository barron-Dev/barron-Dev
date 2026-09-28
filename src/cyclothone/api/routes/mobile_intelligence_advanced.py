from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.mobile_intelligence.advanced import AdvancedMdiService

router = APIRouter(prefix="/mobile-intelligence/advanced", tags=["mobile-intelligence-advanced"])
service = AdvancedMdiService()


def principal(p: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    p.require(("mobile:intelligence",))
    return p


class Ss7Request(BaseModel):
    gt: str = Field(min_length=1, max_length=64)
    opcode: str = Field(min_length=1, max_length=64)
    timestamp_ms: int | None = None


class OtpRequest(BaseModel):
    msisdn: str
    imei: str
    otp_issued_at_ms: int
    otp_read_at_ms: int
    carrier_mcc: str | None = None
    ip_asn: str | None = None
    previous_lat_lon: tuple[float, float] | None = None
    current_lat_lon: tuple[float, float] | None = None
    previous_at_ms: int | None = None


class FlashRequest(BaseModel):
    calls: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class SipRequest(BaseModel):
    invite: dict[str, str]


class CrossBorderRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=2, max_length=5000)


@router.post("/observe/ss7")
async def observe_ss7(body: Ss7Request, p: DeveloperPrincipal = Depends(principal)):
    return await service.observe_ss7(body.gt, body.opcode, body.timestamp_ms, tenant_id=p.tenant_id)


@router.post("/observe/otp")
async def observe_otp(body: OtpRequest, p: DeveloperPrincipal = Depends(principal)):
    return await service.observe_otp(body.model_dump(), tenant_id=p.tenant_id)


@router.post("/observe/flash-calls")
async def observe_flash_calls(body: FlashRequest, p: DeveloperPrincipal = Depends(principal)):
    return await service.observe_flash_calls(body.calls, tenant_id=p.tenant_id)


@router.post("/observe/sip")
async def observe_sip(body: SipRequest, _: DeveloperPrincipal = Depends(principal)):
    return await service.observe_sip(body.invite)


@router.post("/observe/cross-border")
async def observe_cross_border(body: CrossBorderRequest, p: DeveloperPrincipal = Depends(principal)):
    return await service.observe_cross_border(body.events, tenant_id=p.tenant_id)


@router.get("/alerts")
async def alerts(p: DeveloperPrincipal = Depends(principal)):
    from cyclothone.storage.supabase_client import supabase

    rows = await supabase.select(
        "mdi_advanced_alerts",
        "id,alert_type,subject_id,severity,score,action,algorithm,explanation,case_id,created_at,resolved_at,tenant_id",
        tenant_id=p.tenant_id,
    )
    return {"items": rows[:200]}


@router.get("/status")
async def status(p: DeveloperPrincipal = Depends(principal)):
    from cyclothone.storage.supabase_client import supabase

    rows = await supabase.select("mdi_advanced_alerts", "alert_type,severity,created_at", tenant_id=p.tenant_id)
    return {
        "service": "mobile_digital_intelligence_advanced",
        "live": True,
        "alerts_24h": sum(1 for row in rows if row.get("created_at")),
        "detectors": [
            "simswap_hazard",
            "wangiri",
            "irsf",
            "msisdn_recycle",
            "grey_route_a2p",
            "silent_sms",
            "ss7_map_anomaly",
            "otp_relay",
            "flash_call",
            "voip_trunk_fingerprint",
            "cross_border_ring",
            "satellite_ground_truth",
        ],
    }
