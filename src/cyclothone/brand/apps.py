from __future__ import annotations
import httpx,re
from sentinel.brand.similarity import combined_similarity
from sentinel.storage.supabase_client import supabase
class AppStoreMonitor:
    ITUNES='https://itunes.apple.com/search'
    async def scan_brand(self,brand):
        base=brand['primary_domain'].split('.')[0].lower();stats={'checked':0,'threats':0}
        async with httpx.AsyncClient(timeout=20) as c:
            try:
                r=await c.get(self.ITUNES,params={'term':base,'entity':'software','limit':100})
                items=(r.json() or {}).get('results',[]) if r.status_code==200 else []
            except Exception:items=[]
            own={str(x) for x in (brand.get('app_ids') or {}).get('ios',[]) } if isinstance((brand.get('app_ids') or {}).get('ios'),list) else set()
            for app in items:
                stats['checked']+=1;tid=str(app.get('trackId') or '')
                if tid in own:continue
                name=app.get('trackName','');seller=app.get('sellerName','');sim=max(combined_similarity(name,base),combined_similarity(seller,base))
                if sim<.6:continue
                await self._record(brand,('ios:'+str(app.get('bundleId') or tid)),app.get('trackViewUrl'), 'ios',sim, 'critical' if sim>=.85 else 'high',{'name':name,'seller':seller});stats['threats']+=1
            try:r=await c.get('https://play.google.com/store/search',params={'q':base,'c':'apps'},headers={'user-agent':'SentinelBrand/1.0'});text=r.text if r.status_code==200 else ''
            except Exception:text=''
            for pkg in list(set(re.findall(r'id=(com\.[A-Za-z0-9_.]{3,120})',text)))[:100]:
                stats['checked']+=1;sim=combined_similarity(pkg.split('.')[-1],base)
                if sim<.6:continue
                await self._record(brand,'android:'+pkg,'https://play.google.com/store/apps/details?id='+pkg,'android',sim,'critical' if sim>=.85 else 'high',{'package':pkg});stats['threats']+=1
        return stats
    async def _record(self,b,identifier,url,platform,sim,sev,meta):
        async def q():return await (await supabase._ensure()).rpc('record_brand_threat',{'p_tenant':b['tenant_id'],'p_brand':b['id'],'p_kind':'fake_app','p_identifier':identifier,'p_url':url,'p_platform':platform,'p_similarity':sim,'p_severity':sev,'p_metadata':meta}).execute()
        try:await supabase._retry(q,attempts=2)
        except Exception:pass
