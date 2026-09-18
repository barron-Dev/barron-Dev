from __future__ import annotations
import logging
from uuid import UUID
from cyclothone.gsma.client import GSMAClient
from cyclothone.gsma.normalize import OperatorResolver
from cyclothone.storage.supabase_client import supabase
logger=logging.getLogger(__name__)

class GSMAIntegration:
    def __init__(self,tenant_id:UUID)->None: self.tenant_id=tenant_id

    async def enrich(self,e164:str,latitude:float|None=None,longitude:float|None=None)->dict:
        operators=await self._operators(); target=OperatorResolver.resolve(e164,operators)
        if not target: return {"enriched":False,"reason":"no operator for country code"}
        op=next(o for o in operators if o["id"]==target.operator_id); client=GSMAClient(str(self.tenant_id),op)
        h=OperatorResolver.hash_value(e164); out={"enriched":True,"operator_id":op["id"],"signals":[]}
        try:
            swap=await client.check_sim_swap(e164)
            if swap.get("ok"):
                changed=bool(swap["body"].get("swapped"))
                delta=0.35 if changed else -0.05
                out["signals"].append({"type":"sim_swap","swapped":changed,"risk_delta":delta})
                await self._record(h,"sim_swap",op["id"],swap["body"],0.9 if changed else 0.5,delta)
            if latitude is not None and longitude is not None:
                loc=await client.verify_location(e164,latitude,longitude)
                if loc.get("ok"):
                    verified=bool(loc["body"].get("verificationResult")); delta=-0.10 if verified else 0.25
                    out["signals"].append({"type":"device_location","verified":verified,"risk_delta":delta})
                    await self._record(h,"device_location",op["id"],loc["body"],0.8,delta)
            num=await client.verify_number(e164)
            if num.get("ok"):
                verified=bool(num["body"].get("devicePhoneNumberVerified")); delta=-0.05 if verified else 0.15
                out["signals"].append({"type":"number_verification","verified":verified,"risk_delta":delta})
                await self._record(h,"number_verification",op["id"],num["body"],0.85,delta)
            return out
        finally:
            await client.aclose()

    async def _operators(self)->list[dict]:
        async def load():
            c=await supabase._ensure()
            return await c.table("gsma_operators").select("*").eq("enabled",True).execute()
        try: return list((await supabase._retry(load)).data or [])
        except Exception: return []

    async def _record(self,h,kind,op,result,confidence,delta):
        async def save():
            c=await supabase._ensure()
            return await c.table("gsma_signals").insert({"tenant_id":str(self.tenant_id),"e164_hash":h,"signal_type":kind,
              "operator_id":op,"result":result,"confidence":confidence,"risk_delta":delta}).execute()
        try: await supabase._retry(save,attempts=1)
        except Exception: logger.debug("GSMA signal persistence failed")
