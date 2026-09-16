from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter,Depends,HTTPException,Query,status
from pydantic import BaseModel,Field
from sentinel.developer.auth import DeveloperPrincipal,authenticate_request
from sentinel.brand.takedown import TakedownService
from sentinel.brand.typosquat import TyposquatScanner
from sentinel.storage.supabase_client import supabase
router=APIRouter(prefix='/brand',tags=['brand']);_td=TakedownService()
def tid(p,scope):p.require((scope,));return p.tenant_id
class BrandCreate(BaseModel):
 name:str=Field(min_length=1,max_length=200);primary_domain:str=Field(min_length=3,max_length=253);domains:list[str]=Field(default_factory=list);keywords:list[str]=Field(default_factory=list);trademarks:list[str]=Field(default_factory=list);social_handles:list[str]=Field(default_factory=list);app_ids:dict=Field(default_factory=dict);logo_url:str|None=None;similarity_min:float=Field(default=.75,ge=.5,le=.99)
@router.post('/brands',status_code=201)
async def create_brand(b:BrandCreate,p:DeveloperPrincipal=Depends(authenticate_request)):
 tid0=tid(p,'brand:manage');row={**b.model_dump(),'tenant_id':tid0,'primary_domain':b.primary_domain.lower().strip(),'created_by':None}
 async def q():return await (await supabase._ensure()).table('brands').insert(row).execute()
 try:data=(await supabase._retry(q,attempts=2)).data or []
 except Exception as e:raise HTTPException(409,'brand already exists') from e
 if not data:raise HTTPException(502,'brand persistence failed')
 return data[0]
@router.get('/brands')
async def brands(p:DeveloperPrincipal=Depends(authenticate_request)):
 async def q():return await (await supabase._ensure()).table('brands').select('*').eq('tenant_id',tid(p,'brand:read')).order('created_at',desc=True).execute()
 return list((await supabase._retry(q,attempts=2)).data or [])
@router.get('/threats')
async def threats(brand_id:UUID|None=None,status_filter:str|None=Query(None,alias='status'),severity:str|None=None,kind:str|None=None,limit:int=Query(200,ge=1,le=1000),principal:DeveloperPrincipal=Depends(authenticate_request)):
 async def q():
  x=(await supabase._ensure()).table('brand_threats').select('*').eq('tenant_id',str(principal.tenant_id))
  if brand_id:x=x.eq('brand_id',str(brand_id))
  if status_filter:x=x.eq('status',status_filter)
  if severity:x=x.eq('severity',severity)
  if kind:x=x.eq('kind',kind)
  return await x.order('first_seen',desc=True).limit(limit).execute()
 principal.require(('brand:read',))
 return list((await supabase._retry(q,attempts=2)).data or [])
@router.get('/stats')
async def stats(p:DeveloperPrincipal=Depends(authenticate_request)):
 async def q():return await (await supabase._ensure()).table('brand_threats').select('kind,severity,status').eq('tenant_id',tid(p,'brand:read')).execute()
 rows=(await supabase._retry(q,attempts=2)).data or [];bk={};bs={}
 for r in rows:bk[r['kind']]=bk.get(r['kind'],0)+1;bs[r['severity']]=bs.get(r['severity'],0)+1
 return {'total':len(rows),'active':sum(r['status']=='active' for r in rows),'by_kind':bk,'by_severity':bs}
@router.post('/brands/{brand_id}/scan-typosquat')
async def scan(brand_id:UUID,p:DeveloperPrincipal=Depends(authenticate_request)):
 async def q():return await (await supabase._ensure()).table('brands').select('*').eq('id',str(brand_id)).eq('tenant_id',tid(p,'brand:scan')).limit(1).execute()
 rows=(await supabase._retry(q,attempts=2)).data or []
 if not rows:raise HTTPException(404,'brand not found')
 return await TyposquatScanner().scan_brand(rows[0])
class ThreatUpdate(BaseModel):status:str|None=Field(None,pattern='^(active|monitoring|takedown_requested|taken_down|false_positive|resolved)$')
@router.patch('/threats/{threat_id}')
async def update(threat_id:UUID,b:ThreatUpdate,p:DeveloperPrincipal=Depends(authenticate_request)):
 if not b.status:raise HTTPException(400,'nothing to update')
 async def q():return await (await supabase._ensure()).table('brand_threats').update({'status':b.status}).eq('id',str(threat_id)).eq('tenant_id',tid(p,'brand:manage')).execute()
 data=(await supabase._retry(q,attempts=2)).data or []
 if not data:raise HTTPException(404,'threat not found')
 return data[0]
class TakedownRequest(BaseModel):provider:str=Field(min_length=1,max_length=40)
@router.post('/threats/{threat_id}/takedown')
async def takedown(threat_id:UUID,b:TakedownRequest,p:DeveloperPrincipal=Depends(authenticate_request)):
 tid0=tid(p,'brand:takedown')
 try:return await _td.request_takedown(tid0,threat_id,b.provider,None)
 except ValueError as e:raise HTTPException(400,str(e)) from e
