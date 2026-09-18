from __future__ import annotations
import httpx
from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase
class SocialMonitor:
    PLATFORMS={'x':'https://x.com/{h}','instagram':'https://www.instagram.com/{h}/','facebook':'https://www.facebook.com/{h}','tiktok':'https://www.tiktok.com/@{h}','youtube':'https://www.youtube.com/@{h}','linkedin':'https://www.linkedin.com/company/{h}','telegram':'https://t.me/{h}'}
    async def scan_brand(self,brand):
        base=brand['primary_domain'].split('.')[0].lower(); owned={x.lower() for x in brand.get('social_handles',[])}; stats={'checked':0,'taken':0,'threats':0}
        variants=list(dict.fromkeys([base,base+'hq',base+'official',base+'_official','official'+base,base+'support',base+'help',base+'team','real'+base,base+'_app']))
        async with httpx.AsyncClient(timeout=10,follow_redirects=True) as c:
            for platform,tpl in self.PLATFORMS.items():
                for h in variants:
                    if h in owned:continue
                    stats['checked']+=1
                    try:r=await c.get(tpl.format(h=h),headers={'user-agent':'CyclothoneBrand/1.0'})
                    except Exception:continue
                    if r.status_code!=200:continue
                    stats['taken']+=1;sim=combined_similarity(h,base);sev='critical' if sim>=.9 else 'high' if sim>=.8 else 'medium'
                    await self._record(brand['tenant_id'],brand['id'],platform+':'+h,tpl.format(h=h),platform,sim,sev,{'handle':h});stats['threats']+=1
        return stats
    async def _record(self,tenant,brand,identifier,url,platform,sim,sev,metadata):
        async def q():return await (await supabase._ensure()).rpc('record_brand_threat',{'p_tenant':tenant,'p_brand':brand,'p_kind':'social_handle','p_identifier':identifier,'p_url':url,'p_platform':platform,'p_similarity':sim,'p_severity':sev,'p_metadata':metadata}).execute()
        try:await supabase._retry(q,attempts=2)
        except Exception:pass
