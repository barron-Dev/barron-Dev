from __future__ import annotations
from datetime import datetime, timezone
import hashlib,json
from fastapi import APIRouter,HTTPException
from cyclothone.storage.supabase_client import supabase
from cyclothone.api.routes.trust import _verify_ed25519

router=APIRouter(prefix="/trust/public",tags=["public-trust-verification"])

def _now(): return datetime.now(timezone.utc)
def _dt(v): return datetime.fromisoformat(str(v).replace("Z","+00:00")) if v else None
def _valid_key(k):
    if not k or k.get("algorithm")!="ED25519" or k.get("status")!="ACTIVE" or not k.get("public_key"): return False
    return (not k.get("not_before") or _dt(k["not_before"])<=_now()) and (not k.get("not_after") or _dt(k["not_after"])>_now())
def _verify(k,s,h):
    if not _valid_key(k) or not s or not h or len(h)!=64: return False
    try: _verify_ed25519(k["public_key"],s,bytes.fromhex(h)); return True
    except ValueError: return False

@router.get("/certificates/{serial_number}")
async def verify_public_certificate(serial_number:str):
    m=await supabase.rpc("trust_public_certificate_material",{"p_serial_number":serial_number})
    if not m: raise HTTPException(status_code=404,detail="certificate_not_found")
    c=m.get("certificate") or {};p=m.get("proof") or {};ps=m.get("proof_signature") or {};pk=m.get("proof_key");a=m.get("attestation");ak=m.get("attestation_key");ck=m.get("certificate_key")
    reasons=[]
    cert_ok=c.get("algorithm")=="ED25519" and _verify(ck,c.get("signature"),c.get("payload_hash"))
    proof_ok=bool(p and ps and ps.get("algorithm")=="ED25519" and ps.get("signed_payload_hash")==p.get("proof_hash") and _verify(pk,ps.get("signature"),p.get("proof_hash")))
    att_ok=not p.get("attestation_id")
    if a: att_ok=a.get("signature_algorithm")=="ED25519" and _verify(ak,a.get("signature"),a.get("signed_payload_hash"))
    if not cert_ok: reasons.append("certificate_signature_invalid")
    if not proof_ok: reasons.append("proof_signature_invalid")
    if not att_ok: reasons.append("attestation_signature_invalid")
    current=c.get("status")=="ACTIVE" and _dt(c.get("valid_from"))<=_now() and _dt(c.get("valid_until"))>_now()
    if not current: reasons.append("certificate_not_current")
    verified=cert_ok and proof_ok and att_ok and current
    vh=hashlib.sha256(json.dumps({"certificate_id":c.get("id"),"certificate_payload_hash":c.get("payload_hash"),"proof_hash":p.get("proof_hash"),"attestation_hash":a.get("attestation_hash") if a else None,"verified":verified,"reasons":reasons},sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
    await supabase.rpc("trust_commit_public_certificate_verification",{"p_certificate_id":c["id"],"p_status":"VERIFIED" if verified else "FAILED","p_verification_hash":vh,"p_reason":None if verified else ",".join(reasons)})
    return {"verified":verified,"serial_number":serial_number,"certificate_id":c["id"],"algorithm":"ED25519","certificate_signature_verified":cert_ok,"proof_signature_verified":proof_ok,"attestation_signature_verified":att_ok,"valid_from":c.get("valid_from"),"valid_until":c.get("valid_until"),"verification_hash":vh,"reasons":reasons}
