from __future__ import annotations
import logging
import httpx
from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase
logger=logging.getLogger(__name__)
class CTLogMonitor:
    BASE='https://crt.sh'
    async def query_keyword(self,keyword:str,timeout:float=30)->list[dict]:
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                r=await c.get(self.BASE+'/',params={'q':f'%{keyword}%','output':'json'},headers={'user-agent':'CyclothoneBrand/1.0'})
                return r.json() if r.status_code==200 else []
        except Exception:return []
    async def match_brands(self)->dict:
        rows=await self._brands(); out={'brands':len(rows),'candidates':0,'threats':0}
        for b in rows:
            keys=set(b.get('keywords') or []); keys.add(b['primary_domain'].split('.')[0]); seen=set()
            for kw in list(keys)[:5]:
                for e in (await self.query_keyword(kw))[:500]:
                    for san in self._extract_sans(e):
                        if san in seen or san==b['primary_domain'] or any(san.endswith('.'+d) for d in b.get('domains') or []):continue
                        seen.add(san);out['candidates']+=1;sim=combined_similarity(san,b['primary_domain'])
                        if sim<float(b.get('similarity_min',.75)):continue
                        kind=self._classify(san,b['primary_domain']);sev=self._severity(sim,kind)
                        await self._record(b['tenant_id'],b['id'],kind,san,'https://'+san,'web',sim,sev,{'issuer':e.get('issuer_name'),'cert_id':e.get('id'),'source':'ct_log'});out['threats']+=1
        return out
    @staticmethod
    def _extract_sans(e):
        out=[]
        for s in [e.get('common_name',''),*(e.get('name_value') or '').split('\n')]:
            s=s.strip().lower()
            if s and s not in out:out.append(s)
        return out
    @staticmethod
    def _classify(c,p):
        if c.startswith('xn--'):return 'homoglyph'
        cb=c.split('.')[0];pb=p.split('.')[0]
        if cb==pb:return 'tld_swap'
        if '-' in cb:return 'combosquat'
        return 'typosquat'
    @staticmethod
    def _severity(sim,kind):return 'critical' if sim>=.95 or kind=='homoglyph' else 'high' if sim>=.85 else 'medium'
    async def _record(self,tenant_id,brand_id,kind,identifier,url,platform,similarity,severity,metadata):
        try:
            c=await supabase._ensure()
            await supabase._retry(lambda:c.rpc('record_brand_threat',{'p_tenant':tenant_id,'p_brand':brand_id,'p_kind':kind,'p_identifier':identifier,'p_url':url,'p_platform':platform,'p_similarity':similarity,'p_severity':severity,'p_metadata':metadata}).execute(),attempts=2)
        except Exception: logger.debug('brand threat persistence failed',exc_info=True)
    async def _brands(self):
        async def q(): return await (await supabase._ensure()).table('brands').select('*').eq('enabled',True).eq('monitor_ct_logs',True).execute()
        try:return list((await supabase._retry(q,attempts=2)).data or [])
        except Exception:return []
