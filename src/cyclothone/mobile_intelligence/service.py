from __future__ import annotations
from datetime import UTC, datetime
import hashlib
import re
from typing import Any
from uuid import UUID
from cyclothone.mobile_intelligence.provider import MobileProvider, ProviderUnavailable
from cyclothone.storage.supabase_client import supabase

E164 = re.compile(r"^\\+[1-9]\\d{6,14}$")
CAPABILITIES = {"number_verification","sim_swap_check","sim_swap_date","device_swap_check","device_swap_date","device_identifier","device_type","location_retrieval","location_verification","reachability","roaming"}

class MobileIntelligenceError(RuntimeError):
    pass

def normalize_number(value: str) -> str:
    raw = re.sub(r"[\\s().-]", "", value.strip())
    if not E164.fullmatch(raw): raise MobileIntelligenceError("invalid_e164_number")
    return raw

def subject_hash(number: str) -> str:
    return hashlib.sha256(number.encode()).hexdigest()

class MobileIntelligenceService:
    async def status(self, tenant_id: UUID) -> dict[str, Any]:
        async def load():
            c=await supabase._ensure(); return await c.table("mobile_provider_accounts").select("id,name,provider_kind,country_codes,number_prefixes,capabilities,enabled").eq("tenant_id",str(tenant_id)).execute()
        rows=list((await supabase._retry(load,attempts=2)).data or [])
        return {"service":"mobile_digital_intelligence","provider_count":len([r for r in rows if r.get("enabled")]),"providers":rows,"capabilities":sorted(CAPABILITIES),"live_data":bool([r for r in rows if r.get("enabled")])}

    async def query(self, tenant_id: UUID, app_id: str, number: str, capabilities: list[str], purpose: str, authority_reference: str, authorization_id: str, max_age_hours: int=24, latitude: float|None=None, longitude: float|None=None, radius_km: int|None=None) -> dict[str, Any]:
        normalized=normalize_number(number); requested=sorted(set(capabilities))
        if not requested or not set(requested).issubset(CAPABILITIES): raise MobileIntelligenceError("unsupported_mobile_capability")
        if not purpose.strip(): raise MobileIntelligenceError("purpose_required")
        if not authority_reference.strip(): raise MobileIntelligenceError("authority_reference_required")
        if (latitude is None) != (longitude is None): raise MobileIntelligenceError("location_coordinates_incomplete")
        if radius_km is not None and not (1<=radius_km<=100): raise MobileIntelligenceError("invalid_radius")
        auth=await self._authorize(tenant_id,app_id,normalized,purpose,authority_reference,authorization_id)
        provider=await self._provider(tenant_id,normalized); q=await self._create_query(tenant_id,app_id,auth,normalized,requested)
        try:
            results=[]
            for capability in requested:
                body=await provider.call(capability,self._payload(capability,normalized,max_age_hours,latitude,longitude,radius_km))
                observation=await self._record_observation(q,provider.account["id"],capability,body)
                results.append({"capability":capability,"observation_id":observation,"data":body})
            await self._finish_query(q,"completed",None); await provider.close()
            return {"query_id":q,"authorization_id":auth,"subject":{"type":"phone_number","hash":subject_hash(normalized)},"results":results,"observed_at":datetime.now(UTC).isoformat()}
        except Exception:
            await provider.close(); await self._finish_query(q,"failed","provider_query_failed"); raise

    async def _authorize(self, tenant_id: UUID, app_id: str, number: str, purpose: str, authority: str, authorization_id: str) -> str:
        row=await supabase.select_one("mobile_authorizations","id,status,valid_to,subject_hash,purpose,authority_reference",id=authorization_id,tenant_id=str(tenant_id),app_id=app_id)
        if not row or row.get("status")!="approved": raise MobileIntelligenceError("mobile_authorization_not_approved")
        if row.get("subject_hash")!=subject_hash(number): raise MobileIntelligenceError("authorization_subject_mismatch")
        if row.get("purpose")!=purpose.strip() or row.get("authority_reference")!=authority.strip(): raise MobileIntelligenceError("authorization_context_mismatch")
        if row.get("valid_to") and datetime.fromisoformat(str(row["valid_to"]).replace("Z","+00:00"))<=datetime.now(UTC): raise MobileIntelligenceError("mobile_authorization_expired")
        return str(row["id"])

    async def _provider(self, tenant_id: UUID, number: str) -> MobileProvider:
        async def load():
            c=await supabase._ensure(); return await c.table("mobile_provider_accounts").select("*").eq("tenant_id",str(tenant_id)).eq("enabled",True).execute()
        rows=list((await supabase._retry(load,attempts=2)).data or [])
        matches=[r for r in rows if not r.get("number_prefixes") or any(number.startswith(str(prefix)) for prefix in (r.get("number_prefixes") or []))]
        if not matches: raise MobileIntelligenceError("no_enabled_mobile_provider_for_number")
        return MobileProvider(matches[0])

    def _payload(self, capability: str, number: str, max_age_hours: int, latitude: float|None, longitude: float|None, radius_km: int|None) -> dict[str,Any]:
        if capability in {"sim_swap_check","device_swap_check"}: return {"phoneNumber":number,"maxAge":max_age_hours}
        if capability in {"sim_swap_date","device_swap_date","device_identifier","device_type","reachability","roaming","location_retrieval","number_verification"}: return {"phoneNumber":number}
        if capability=="location_verification":
            if latitude is None or longitude is None or radius_km is None: raise MobileIntelligenceError("location_verification_coordinates_required")
            return {"device":{"phoneNumber":number},"area":{"areaType":"Circle","center":{"latitude":latitude,"longitude":longitude},"radius":radius_km*1000}}
        raise MobileIntelligenceError("unsupported_mobile_capability")

    async def _create_query(self,tenant_id:UUID,app_id:str,authorization_id:str,number:str,capabilities:list[str])->str:
        row=await supabase.insert_one("mobile_queries",{"tenant_id":str(tenant_id),"app_id":app_id,"authorization_id":authorization_id,"subject_hash":subject_hash(number),"capabilities":capabilities,"status":"running"}); return str(row["id"])
    async def _record_observation(self,query_id:str,provider_id:str,capability:str,body:dict[str,Any])->str:
        row=await supabase.insert_one("mobile_observations",{"query_id":query_id,"provider_id":provider_id,"capability":capability,"data":body,"observed_at":datetime.now(UTC).isoformat()})
        await self._bind_canonical_subject(query_id)
        return str(row["id"])

    async def _bind_canonical_subject(self,query_id:str)->None:
        query=await supabase.select_one("mobile_queries","tenant_id,subject_hash",id=query_id)
        if not query: raise MobileIntelligenceError("mobile_query_not_found")
        await supabase.rpc("mdi_bind_subject_tenant",{
            "p_tenant_id":query["tenant_id"],
            "p_kind":"msisdn",
            "p_canonical":str(query["subject_hash"]),
            "p_display":None,
            "p_country":None,
            "p_attrs":{"source":"mobile_intelligence","query_id":query_id},
            "p_pii":3
        })
    async def _finish_query(self,query_id:str,status:str,error_code:str|None)->None: await supabase.update("mobile_queries",{"status":status,"error_code":error_code,"completed_at":datetime.now(UTC).isoformat()},id=query_id)
