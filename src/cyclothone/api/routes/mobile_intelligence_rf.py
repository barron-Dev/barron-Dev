from __future__ import annotations
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase
router=APIRouter(prefix="/mobile-intelligence/rf",tags=["mobile-intelligence-rf"])
class Consent(BaseModel):
    rf_scan: bool=True
    gnss_share: bool=False
    wifi_share: bool=False
    ble_share: bool=False
    purpose: str=Field(min_length=3,max_length=240)
    expires_at: datetime
class Observation(BaseModel):
    observer_id: str|None=None
    subject_id: str|None=None
    radio: str
    observed_at: datetime|None=None
    lat: float|None=None
    lon: float|None=None
    h3_r9: str|None=None
    mcc: str|None=None
    mnc: str|None=None
    lac: str|None=None
    cid: str|None=None
    arfcn: int|None=None
    pci: int|None=None
    rx_level_dbm: float|None=None
    timing_advance: float|None=None
    bssid_hash: str|None=None
    ssid: str|None=None
    channel: int|None=None
    rssi: float|None=None
    security: str|None=None
    wps: bool|None=None
    ble_mac_hash: str|None=None
    ble_name: str|None=None
    ble_service_uuids: list[str]=[]
    tx_power: float|None=None
    gnss_sats: int|None=None
    gnss_cn0: float|None=None
    spoof_flag: bool|None=None
    raw: dict = {}
@router.post("/consent")
async def consent(body:Consent,p:DeveloperPrincipal=Depends(authenticate_request)):
    p.require(("mobile:intelligence",))
    row={"observer_id":str(p.user_id),"tenant_id":p.tenant_id,"rf_scan":body.rf_scan,"gnss_share":body.gnss_share,"wifi_share":body.wifi_share,"ble_share":body.ble_share,"purpose":body.purpose.strip(),"granted_at":datetime.now(UTC).isoformat(),"expires_at":body.expires_at.isoformat(),"revoked_at":None}
    return await supabase.upsert("mdi_observer_consent",row,on_conflict="observer_id")
@router.post("/report",status_code=201)
async def report(body:Observation,p:DeveloperPrincipal=Depends(authenticate_request)):
    p.require(("mobile:intelligence",))
    if not p.tenant_id: raise HTTPException(403,"tenant_required")
    consent=await supabase.select_one("mdi_observer_consent","rf_scan,gnss_share,wifi_share,ble_share,expires_at,revoked_at,tenant_id",observer_id=str(p.user_id),tenant_id=p.tenant_id)
    if not consent or not consent.get("rf_scan") or consent.get("revoked_at") or (consent.get("expires_at") and datetime.fromisoformat(str(consent["expires_at"]).replace("Z","+00:00"))<=datetime.now(UTC)):
        raise HTTPException(403,"rf_consent_required")
    radio=body.radio
    if radio not in {"cellular","wifi","ble","gnss","lora","nfc"}: raise HTTPException(422,"unsupported_radio")
    if radio=="gnss" and not consent.get("gnss_share"): raise HTTPException(403,"gnss_consent_required")
    if radio=="wifi" and not consent.get("wifi_share"): raise HTTPException(403,"wifi_consent_required")
    if radio=="ble" and not consent.get("ble_share"): raise HTTPException(403,"ble_consent_required")
    row=body.model_dump(); row["observer_id"]=str(p.user_id); row["tenant_id"]=p.tenant_id; row["observed_at"]=(body.observed_at or datetime.now(UTC)).isoformat()
    row.pop("subject_id",None)
    return await supabase.insert_one("mdi_rf_observations",row)
