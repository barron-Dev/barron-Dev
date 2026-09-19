from __future__ import annotations
import logging
import time
from typing import Any, Awaitable, Callable
from cyclothone.storage.supabase_client import supabase
logger=logging.getLogger(__name__)

class CatalogLoader:
    TTL=3600
    def __init__(self)->None:self._cache:dict[str,tuple[Any,float]]={}
    async def _get(self,key:str,fn:Callable[[],Awaitable[Any]]):
        now=time.time(); cached=self._cache.get(key)
        if cached and now-cached[1]<self.TTL:return cached[0]
        value=await fn(); self._cache[key]=(value,now); return value
    async def _table(self,key:str,table:str,filters:dict[str,Any]|None=None)->list[dict]:
        async def load():
            client=await supabase._ensure(); q=client.table(table).select("*")
            for col,val in (filters or {}).items(): q=q.eq(col,val)
            r=await q.execute(); return list(r.data or [])
        return await self._get(key,load)
    async def regions(self): return await self._table("regions","regions",{"active":True})
    async def frameworks(self): return await self._table("frameworks","frameworks")
    async def regulators(self): return await self._table("regulators","country_regulations")
    async def certs(self): return await self._table("certs","federation_peers",{"kind":"cert","status":"active"})
    async def isacs(self): return await self._table("isacs","federation_peers",{"kind":"isac","status":"active"})
    async def operators(self): return await self._table("operators","gsma_operators",{"enabled":True})
    async def channels(self): return await self._table("channels","lens_channel_catalog")
    def invalidate(self,key:str|None=None)->None:
        if key:self._cache.pop(key,None)
        else:self._cache.clear()
catalog=CatalogLoader()
