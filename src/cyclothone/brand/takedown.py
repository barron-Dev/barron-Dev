from __future__ import annotations
from datetime import UTC,datetime
from uuid import UUID
from cyclothone.storage.supabase_client import supabase
PROVIDERS={'cloudflare':('abuse@cloudflare.com',None),'godaddy':('abuse@godaddy.com',None),'namecheap':('abuse@namecheap.com',None),'google':(None,'https://support.google.com/legal/troubleshooter/1114905'),'meta':(None,'https://www.facebook.com/help/contact/295309487309948'),'x':(None,'https://help.twitter.com/forms/impersonation'),'linkedin':(None,'https://www.linkedin.com/help/linkedin/ask/TS-RSI'),'tiktok':('impersonation@tiktok.com',None),'apple':(None,'https://www.apple.com/legal/internet-services/itunes/appstorenotices/')}
class TakedownService:
    async def request_takedown(self,tenant_id:UUID,threat_id:UUID,provider:str,requested_by:UUID)->dict:
        if provider not in PROVIDERS:raise ValueError('unsupported provider')
        async def load():return await (await supabase._ensure()).table('brand_threats').select('*').eq('id',str(threat_id)).eq('tenant_id',str(tenant_id)).limit(1).execute()
        rows=(await supabase._retry(load,attempts=2)).data or []
        if not rows:raise ValueError('threat not found')
        threat=rows[0]
        async def brand():return await (await supabase._ensure()).table('brands').select('*').eq('id',threat['brand_id']).eq('tenant_id',str(tenant_id)).limit(1).execute()
        brands=(await supabase._retry(brand,attempts=2)).data or []
        if not brands:raise ValueError('brand not found')
        b=brands[0];subject=f"Takedown request - {threat['kind']} impersonating {b['name']}";body=self._compose(b,threat)
        async def mark():return await (await supabase._ensure()).table('brand_threats').update({'status':'takedown_requested','takedown_provider':provider,'takedown_at':datetime.now(UTC).isoformat()}).eq('id',str(threat_id)).eq('tenant_id',str(tenant_id)).execute()
        await supabase._retry(mark,attempts=2);email,form=PROVIDERS[provider]
        return {'threat_id':str(threat_id),'provider':provider,'subject':subject,'body':body,'contact_email':email,'contact_form':form,'status':'takedown_requested'}
    def _compose(self,b,t):
        return f"I represent {b['name']} ({b['primary_domain']}) and report unauthorized impersonation.\n\nIdentifier: {t['identifier']}\nURL: {t.get('url') or 'n/a'}\nPlatform: {t.get('platform') or 'web'}\nType: {t['kind']}\nSimilarity: {float(t['similarity']):.2f}\n\nThe asset is not authorized by {b['name']}. Please review it under your applicable abuse, impersonation, trademark, or acceptable-use process. Evidence can be supplied on request.\n\nRegards,\n{b['name']} Security Team\n{b['primary_domain']}"
