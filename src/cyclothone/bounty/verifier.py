from __future__ import annotations
import hashlib, ipaddress, re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IOC_PATTERNS={
 "sha256":re.compile(r"^[a-f0-9]{64}$"),"sha1":re.compile(r"^[a-f0-9]{40}$"),"md5":re.compile(r"^[a-f0-9]{32}$"),
 "domain":re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"),
 "email":re.compile(r"^[^@\s]{1,254}@[^@\s]{1,254}\.[a-z]{2,63}$"),
 "ja3":re.compile(r"^[a-f0-9]{32}$"),"mutex":re.compile(r"^[A-Za-z0-9_{}\\.\-]{3,128}$")}
DANGEROUS=(re.compile(r"\bcurl\s+[^|\n]+\|\s*(?:bash|sh)\b",re.I),re.compile(r"\bwget\s+[^|\n]+\|\s*(?:bash|sh)\b",re.I),
 re.compile(r"\beval\s*\(\s*base64",re.I),re.compile(r"\bos\.system\s*\(",re.I),re.compile(r"\bsubprocess\.(?:run|call|Popen)\b",re.I),
 re.compile(r"\brm\s+-rf\s+/(?:\s|$)",re.I))
MAX_ARTIFACTS=200
@dataclass(frozen=True)
class VerificationResult:
 verdict:str; score:float; reasons:list[dict]=field(default_factory=list)
class BountyAutoVerifier:
 def verify(self,campaign:dict,title:str,body:str,artifacts:list[dict])->VerificationResult:
  if not 1<=len(artifacts)<=MAX_ARTIFACTS:return VerificationResult("reject",0.0,[{"check":"artifact_count","passed":False}])
  valid=0
  for a in artifacts:
   if not isinstance(a,dict):continue
   kind=str(a.get("kind") or ""); value=str(a.get("value") or "")
   if kind in ("file","sample"):ok=bool(re.fullmatch(r"[a-f0-9]{64}",str(a.get("sha256") or "").lower()))
   elif kind in IOC_PATTERNS:
    ok=bool(IOC_PATTERNS[kind].fullmatch(value.lower()))
    if kind in ("ipv4","ipv6"):
     try:ok=ipaddress.ip_address(value).version==(4 if kind=="ipv4" else 6)
     except ValueError:ok=False
    elif kind=="url":
     try:u=urlsplit(value);ok=u.scheme in ("http","https") and bool(u.hostname)
     except ValueError:ok=False
   else:ok=False
   valid+=int(ok)
  if valid==0:return VerificationResult("reject",0.0,[{"check":"valid_artifacts","passed":False}])
  for pat in DANGEROUS:
   if pat.search(title+"\n"+body):return VerificationResult("reject",0.0,[{"check":"safety_scan","passed":False}])
  score=0.5+(0.15 if valid==len(artifacts) else -0.10)
  words=len(body.split());score+=0.10 if words>=40 else (-0.20 if words<20 else 0)
  crit=campaign.get("acceptance") or {}
  if crit.get("requires_sample") and not any(isinstance(a,dict) and a.get("kind") in ("file","sample") for a in artifacts):score-=0.30
  if crit.get("requires_poc") and "poc" not in body.lower():score-=0.15
  minimum=float(crit.get("min_confidence") or 0)
  if minimum:
   m=re.search(r"confidence\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)",body,re.I);found=None if not m else float(m.group(1));found=found/100 if found is not None and found>1 else found
   if found is None or not 0<=found<=1 or found<minimum:score-=0.15
  score=round(max(0,min(1,score)),4)
  return VerificationResult("accept" if score>=0.75 else "peer_review" if score>=0.45 else "reject",score,[{"check":"valid_artifacts","passed":True,"count":valid},{"check":"safety_scan","passed":True},{"check":"body_quality","words":words}])
 @staticmethod
 def content_hash(title:str,body:str,artifacts:list[dict])->str:
  canonical="|".join((title.strip().lower(),body.strip().lower()[:5000],",".join(sorted(f"{a.get('kind')}:{a.get('value') or a.get('sha256')}" for a in artifacts if isinstance(a,dict)))))
  return hashlib.sha256(canonical.encode()).hexdigest()
