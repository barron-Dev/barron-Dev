from __future__ import annotations
import logging
from datetime import datetime,timedelta,timezone
import httpx
from cyclothone.storage.supabase_client import supabase

logger=logging.getLogger(__name__)

class GSMAClient:
    def __init__(self,tenant_id:str,operator:dict)->None:
        self.tenant_id=tenant_id; self.operator=operator
        self._http=httpx.AsyncClient(timeout=httpx.Timeout(20.0,connect=5.0))

    async def aclose(self)->None:
        await self._http.aclose()

    async def check_sim_swap(self,e164:str,max_age_hours:int=24)->dict:
        return await self._post(f"{self.operator['oidc_issuer']}/api/sim-swap/v2/check",
                                 {"phoneNumber":e164,"maxAge":max_age_hours},await self._get_token())

    async def verify_location(self,e164:str,latitude:float,longitude:float,radius_km:int=5)->dict:
        return await self._post(f"{self.operator['oidc_issuer']}/api/location-verification/v0/verify",
          {"device":{"phoneNumber":e164},"area":{"areaType":"Circle","center":{"latitude":latitude,"longitude":longitude},"radius":radius_km*1000}},
          await self._get_token())

    async def verify_number(self,e164:str)->dict:
        return await self._post(f"{self.operator['oidc_issuer']}/api/number-verification/v0/verify",
                                 {"phoneNumber":e164},await self._get_token())

    async def _post(self,url:str,payload:dict,token:str)->dict:
        try:
            r=await self._http.post(url,json=payload,headers={"authorization":f"Bearer {token}","content-type":"application/json"})
            if r.status_code>=400: return {"ok":False,"status":r.status_code,"body":r.text[:300]}
            return {"ok":True,"body":r.json()}
        except Exception as exc:
            logger.warning("GSMA call failed: %s",exc)
            return {"ok":False,"error":"upstream request failed"}

    async def _get_token(self)->str:
        async def load():
            c=await supabase._ensure()
            return await c.table("gsma_tokens").select("access_token,expires_at").eq("tenant_id",self.tenant_id).eq("operator_id",self.operator["id"]).limit(1).execute()
        try:
            resp=await supabase._retry(load); rows=resp.data or []
            if rows:
                exp=datetime.fromisoformat(rows[0]["expires_at"].replace("Z","+00:00"))
                if exp>datetime.now(timezone.utc)+timedelta(seconds=60): return rows[0]["access_token"]
        except Exception: pass
        secret=await self._vault(self.operator["oidc_secret_ref"])
        if not secret: raise RuntimeError("GSMA operator credential unavailable")
        try:
            r=await self._http.post(f"{self.operator['oidc_issuer']}/oauth2/token",
              data={"grant_type":"client_credentials","client_id":self.operator["oidc_client_id"],"client_secret":secret,
                    "scope":" ".join(self.operator.get("scopes") or ["sim-swap"])},
              headers={"content-type":"application/x-www-form-urlencoded"})
            r.raise_for_status(); data=r.json(); token=data["access_token"]
            expires=datetime.now(timezone.utc)+timedelta(seconds=int(data.get("expires_in",3600)))
        except Exception as exc:
            logger.error("GSMA token mint failed: %s",exc); raise RuntimeError("could not obtain GSMA token") from exc
        # Bearer tokens are intentionally not persisted until an encrypted token-store contract exists.\n        return token\n
    async def _vault(self,ref:str)->str:
        name=ref.removeprefix("vault://")
        async def load():
            c=await supabase._ensure()
            return await c.rpc("get_vault_secret",{"p_name":name}).execute()
        try:
            resp=await supabase._retry(load)
            return resp.data if isinstance(resp.data,str) else ""
        except Exception:
            return ""
