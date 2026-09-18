from __future__ import annotations
from uuid import UUID
from datetime import datetime, timezone
from cyclothone.bounty.verifier import BountyAutoVerifier
from cyclothone.storage.supabase_client import supabase
class BountyService:
 def __init__(self):self.verifier=BountyAutoVerifier()
 async def submit(self,researcher_id:UUID,campaign_id:UUID,title:str,body:str,artifacts:list[dict])->dict:
  r=await supabase.select_one("bounty_researchers","id,user_id,status,reputation",id=str(researcher_id))
  if not r or r["status"]!="active":raise ValueError("researcher not active")
  c=await supabase.select_one("bounty_campaigns","*",id=str(campaign_id))
  if not c or not c["enabled"]:raise ValueError("campaign not active")
  now=datetime.now(timezone.utc)
  if now < datetime.fromisoformat(c["starts_at"].replace("Z","+00:00")) or (c.get("ends_at") and now >= datetime.fromisoformat(c["ends_at"].replace("Z","+00:00"))): raise ValueError("campaign not active")
  if float(r["reputation"])<float((c.get("acceptance") or {}).get("min_reputation") or 0):raise ValueError("researcher reputation below campaign minimum")
  result=self.verifier.verify(c,title,body,artifacts);ch=self.verifier.content_hash(title,body,artifacts)
  sid=await supabase.rpc("bounty_submit",{"p_researcher":str(researcher_id),"p_campaign":str(campaign_id),"p_title":title,"p_body":body,"p_artifacts":artifacts,"p_content_hash":ch,"p_auto_verdict":result.verdict,"p_auto_score":result.score,"p_auto_reasons":result.reasons})
  # Auto-verification never creates a financial obligation. A payout requires a confirmed block reference and an authorized curator decision.
  return {"submission_id":str(sid),"auto_verdict":result.verdict,"auto_score":result.score,"reasons":result.reasons}
 async def decide(self,submission_id:UUID,verdict:str,severity:str,curator_id:UUID,reason:str,block_ref:str|None=None)->dict:
  s=await supabase.select_one("bounty_submissions","id,campaign_id",id=str(submission_id))
  if not s:raise ValueError("submission not found")
  c=await supabase.select_one("bounty_campaigns","*",id=str(s["campaign_id"]))
  if not c:raise ValueError("campaign not found")
  if verdict=="accept" and not block_ref:
   raise ValueError("confirmed block reference required for payout")
  amount=self._tier_amount(c,severity) if verdict=="accept" else 0
  await self._decide(str(submission_id),verdict,severity,amount,str(curator_id),reason,block_ref)
  return {"submission_id":str(submission_id),"payout":amount}
 async def _decide(self,sid,verdict,severity,amount,verdict_by,reason,block_ref=None):
  await supabase.rpc("bounty_decide",{"p_submission":sid,"p_verdict":verdict,"p_severity":severity,"p_payout":amount,"p_verdict_by":verdict_by,"p_reason":reason,"p_block_ref":block_ref})
 async def claim_payouts(self,batch:int=50)->list[dict]:
  if not 1<=batch<=200:raise ValueError("invalid payout batch")
  return list(await supabase.rpc("bounty_claim_payouts",{"p_limit":batch}) or [])
 @staticmethod
 def _tier_amount(campaign,severity):
  from decimal import Decimal, ROUND_DOWN
  raw=Decimal(str((campaign.get("payout_tiers") or {}).get(severity,0)))
  return float(max(Decimal("0"),raw.quantize(Decimal("0.01"),rounding=ROUND_DOWN)))
 @staticmethod
 def _severity(score):return "critical" if score>=.95 else "high" if score>=.85 else "medium" if score>=.70 else "low"
