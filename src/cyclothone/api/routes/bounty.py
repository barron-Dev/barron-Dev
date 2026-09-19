from __future__ import annotations
import hmac,os
from uuid import UUID
from fastapi import APIRouter,Depends,Header,HTTPException,Query
from pydantic import BaseModel,Field
from cyclothone.api.routes.developer import _user_id
from cyclothone.bounty.service import BountyService
from cyclothone.storage.supabase_client import supabase

router=APIRouter(prefix="/bounty",tags=["bounty"])
async def _identity(user_id:str):
 from cyclothone.developer.identity import resolve_developer
 identity=await resolve_developer(user_id)
 if not identity:raise HTTPException(403,"tenant access not provisioned")
 return identity

class ResearcherCreate(BaseModel):
 handle:str=Field(min_length=3,max_length=64)
 display_name:str|None=Field(default=None,max_length=120)
 country:str|None=Field(default=None,min_length=2,max_length=2,pattern="^[A-Z]{2}$")
 payout_method:str=Field(default="usdc",pattern="^(usdc|usdt|wire|ach|sepa|mobile_money|paypal)$")
 payout_ref:str|None=Field(default=None,max_length=500)

@router.post("/researchers",status_code=201)
async def register(body:ResearcherCreate,user_id:str=Depends(_user_id)):
 try:
  rid=await supabase.rpc("bounty_register_researcher",{"p_user":user_id,"p_handle":body.handle,"p_display_name":body.display_name,"p_country":body.country,"payout_method":body.payout_method,"payout_ref":body.payout_ref})
  return {"id":str(rid),"handle":body.handle}
 except Exception as exc:raise HTTPException(409,"researcher registration failed") from exc

@router.get("/researchers")
async def researchers(user_id:str=Depends(_user_id),limit:int=Query(100,ge=1,le=500)):
 async def q():return await (await supabase._ensure()).table("bounty_researchers").select("id,handle,display_name,country,tier,vetted,reputation,submissions_total,accepted_total,status").eq("user_id",user_id).limit(limit).execute()
 return list((await supabase._retry(q)).data or [])

class CampaignCreate(BaseModel):
 name:str=Field(min_length=1,max_length=200);description:str|None=Field(default=None,max_length=10000)
 category:str=Field(pattern="^(ioc|rule|vulnerability|malware_sample|attribution|threat_report|tool|research)$")
 acceptance:dict=Field(default_factory=dict);payout_tiers:dict=Field(default_factory=lambda:{"low":50,"medium":250,"high":1000,"critical":5000})
 budget_total:float=Field(gt=0,le=100000000);currency:str=Field(default="USD",pattern="^[A-Z]{3}$")

@router.post("/campaigns",status_code=201)
async def create_campaign(body:CampaignCreate,user_id:str=Depends(_user_id)):
 identity=await _identity(user_id)
 if getattr(identity,"role",None) not in ("owner","admin"):raise HTTPException(403,"insufficient role")
 return await supabase.insert_one("bounty_campaigns",{**body.model_dump(),"tenant_id":identity.tenant_id,"enabled":True})

@router.get("/campaigns")
async def campaigns(user_id:str=Depends(_user_id),category:str|None=None,limit:int=Query(100,ge=1,le=500)):
 identity=await _identity(user_id)
 async def q():
  client=await supabase._ensure();query=client.table("bounty_campaigns").select("*").eq("enabled",True).or_(f"tenant_id.is.null,tenant_id.eq.{identity.tenant_id}").order("created_at",desc=True).limit(limit)
  return await (query.eq("category",category) if category else query).execute()
 return list((await supabase._retry(q)).data or [])

class SubmissionCreate(BaseModel):
 researcher_id:UUID;campaign_id:UUID;title:str=Field(min_length=3,max_length=400);body:str=Field(min_length=1,max_length=20000);artifacts:list[dict]=Field(min_length=1,max_length=200)

@router.post("/submissions",status_code=201)
async def submit(body:SubmissionCreate,user_id:str=Depends(_user_id)):
 r=await supabase.select_one("bounty_researchers","id,user_id",id=str(body.researcher_id))
 if not r or r["user_id"]!=user_id:raise HTTPException(403,"researcher does not belong to caller")
 try:return await BountyService().submit(body.researcher_id,body.campaign_id,body.title,body.body,body.artifacts)
 except ValueError as exc:raise HTTPException(400,str(exc)) from exc

@router.get("/submissions")
async def submissions(user_id:str=Depends(_user_id),limit:int=Query(200,ge=1,le=500)):
 identity=await _identity(user_id)
 async def q():
  client=await supabase._ensure();camps=await client.table("bounty_campaigns").select("id").or_(f"tenant_id.is.null,tenant_id.eq.{identity.tenant_id}").execute()
  ids=[x["id"] for x in (camps.data or [])]
  if not ids:return []
  return await client.table("bounty_submissions").select("id,researcher_id,campaign_id,title,severity,verdict,auto_score,payout_amount,payout_status,created_at").in_("campaign_id",ids).order("created_at",desc=True).limit(limit).execute()
 resp=await supabase._retry(q);return resp if isinstance(resp,list) else list(resp.data or [])

class DecideBody(BaseModel):
 submission_id:UUID;verdict:str=Field(pattern="^(accept|reject|duplicate|malicious)$");severity:str=Field(default="medium",pattern="^(low|medium|high|critical)$");reason:str=Field(min_length=3,max_length=1000);block_ref:str|None=Field(default=None,max_length=500)

@router.post("/submissions/decide")
async def decide(body:DecideBody,user_id:str=Depends(_user_id)):
 identity=await _identity(user_id)
 if getattr(identity,"role",None) not in ("owner","admin","member"):raise HTTPException(403,"insufficient role")
 try:return await BountyService().decide(body.submission_id,body.verdict,body.severity,UUID(user_id),body.reason,body.block_ref)
 except ValueError as exc:raise HTTPException(400,str(exc)) from exc

@router.post("/payouts/run")
async def run_payouts(authorization:str|None=Header(None)):
 expected=os.getenv("CYCLOTHONE_BOUNTY_INTERNAL_KEY")
 scheme,_,token=(authorization or "").partition(" ")
 if not expected or scheme.lower()!="bearer" or not hmac.compare_digest(token,expected):raise HTTPException(401,"invalid internal credential")
 rows=await BountyService().claim_payouts(50)
 return {"claimed":len(rows),"status":"processing","provider_dispatch":"required"}

@router.get("/payouts")
async def payouts(user_id:str=Depends(_user_id),limit:int=Query(100,ge=1,le=500)):
 identity=await _identity(user_id)
 async def q():
  client=await supabase._ensure();camps=await client.table("bounty_campaigns").select("id").or_(f"tenant_id.is.null,tenant_id.eq.{identity.tenant_id}").execute()
  ids=[x["id"] for x in (camps.data or [])]
  if not ids:return []
  subs=await client.table("bounty_submissions").select("id").in_("campaign_id",ids).execute();sids=[x["id"] for x in (subs.data or [])]
  if not sids:return []
  return await client.table("bounty_payouts").select("id,researcher_id,submission_id,amount,currency,method,status,provider,tx_hash,created_at,sent_at,confirmed_at").in_("submission_id",sids).order("created_at",desc=True).limit(limit).execute()
 resp=await supabase._retry(q);return resp if isinstance(resp,list) else list(resp.data or [])

@router.get("/stats")
async def stats(user_id:str=Depends(_user_id)):
 identity=await _identity(user_id);return await supabase.rpc("bounty_stats",{"p_tenant":identity.tenant_id})
