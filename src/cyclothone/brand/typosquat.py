from __future__ import annotations
import asyncio,socket
from sentinel.brand.permutations import generate_permutations
from sentinel.brand.similarity import combined_similarity
from sentinel.storage.supabase_client import supabase
class TyposquatScanner:
    CONCURRENCY=100
    async def scan_brand(self,brand):
        perms=generate_permutations(brand['primary_domain'],3000); sem=asyncio.Semaphore(self.CONCURRENCY); stats={'checked':0,'resolved':0,'threats':0}
        async def check(p,t):
            async with sem:
                stats['checked']+=1
                if not await _resolves(p):return
                stats['resolved']+=1; sim=combined_similarity(p,brand['primary_domain']); kind=self._classify(t)
                sev='critical' if sim>=.92 else 'high' if sim>=.82 else 'medium' if sim>=.72 else 'low'
                await self._record(brand['tenant_id'],brand['id'],kind,p,'https://'+p,sim,sev,{'technique':t,'source':'typosquat'});stats['threats']+=1
        await asyncio.gather(*(check(p,t) for p,t in perms),return_exceptions=True);return stats
    @staticmethod
    def _classify(t):return 'homoglyph' if t=='homoglyph' else 'combosquat' if t in ('combosquat','hyphenation') else 'tld_swap' if t=='tld_swap' else 'typosquat'
    async def _record(self,tenant,brand,kind,identifier,url,sim,sev,metadata):
        async def q():return await (await supabase._ensure()).rpc('record_brand_threat',{'p_tenant':tenant,'p_brand':brand,'p_kind':kind,'p_identifier':identifier,'p_url':url,'p_platform':'web','p_similarity':sim,'p_severity':sev,'p_metadata':metadata}).execute()
        try:await supabase._retry(q,attempts=2)
        except Exception:pass
async def _resolves(domain):
    loop=asyncio.get_running_loop()
    try:return bool(await loop.run_in_executor(None,lambda:socket.getaddrinfo(domain,None,proto=socket.IPPROTO_TCP)))
    except Exception:return False
