"""Trusted-worker writer for independently verified signed MDI contracts."""
from __future__ import annotations
import base64, json, os
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .contracts import SignedMDIContract, verify_signed_contract

class JournalWriteError(RuntimeError): pass

def _trusted_key(key_id: str) -> Ed25519PublicKey:
    raw=os.environ.get("CYCLOTHONE_MDI_SIGNER_PUBLIC_KEYS_JSON","")
    try:
        mapping=json.loads(raw)
        encoded=mapping[key_id]
        key_bytes=base64.b64decode(encoded,validate=True)
        if len(key_bytes)!=32: raise ValueError("invalid Ed25519 key length")
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as exc:
        raise JournalWriteError("trusted signer key unavailable or invalid") from exc

def persist_verified_contract(contract: SignedMDIContract) -> str:
    """Verify with a separately provisioned trust key before calling the service-role-only append RPC."""
    if not verify_signed_contract(contract,_trusted_key(contract.signer_key_id)):
        raise JournalWriteError("contract signature or hash verification failed")
    base=os.environ.get("SUPABASE_URL","").rstrip("/")
    key=os.environ.get("SUPABASE_SERVICE_ROLE_KEY","")
    if not base.startswith("https://") or not key:
        raise JournalWriteError("trusted worker Supabase configuration missing")
    payload={
      "p_contract_id":contract.contract_id,"p_tenant_id":contract.tenant_id,
      "p_event_type":contract.event_type,"p_disposition":contract.disposition,
      "p_evidence_hash":contract.evidence_hash,"p_payload":contract.payload,
      "p_previous_hash":contract.previous_hash,"p_current_hash":contract.current_hash,
      "p_signer_key_id":contract.signer_key_id,"p_signature_b64":contract.signature_b64,
      "p_created_at":contract.created_at
    }
    with httpx.Client(timeout=httpx.Timeout(10,connect=3),follow_redirects=False) as client:
        response=client.post(f"{base}/rest/v1/rpc/mdi_append_journal_event",
          headers={"apikey":key,"Authorization":f"Bearer {key}","Content-Type":"application/json"},
          json=payload)
    if response.status_code not in (200,201):
        # Do not log response body; it may contain sensitive tenant data.
        raise JournalWriteError(f"journal append rejected ({response.status_code})")
    try: result=response.json()
    except ValueError as exc: raise JournalWriteError("journal append returned invalid response") from exc
    if not isinstance(result,str): raise JournalWriteError("journal append did not return an event id")
    return result
