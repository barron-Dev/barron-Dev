"""Signed MDI result contracts; cryptographic integrity, not proof of attribution."""
from __future__ import annotations
import base64, hashlib, json, re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ALLOWED_DISPOSITIONS={"threat_detected","verified_clean","partial_coverage","unknown","source_unavailable","human_review_required"}
_EVENT_RE=re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
_HASH_RE=re.compile(r"^[a-f0-9]{64}$")

class ContractError(ValueError): pass

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

@dataclass(frozen=True)
class SignedMDIContract:
    contract_id: str
    tenant_id: str
    event_type: str
    disposition: str
    evidence_hash: str
    payload: dict[str, Any]
    previous_hash: str
    current_hash: str
    signer_key_id: str
    signature_b64: str
    created_at: str

def build_signed_contract(*, tenant_id: str, event_type: str, disposition: str,
                          payload: dict[str, Any], previous_hash: str | None,
                          signer_key_id: str, private_key: Ed25519PrivateKey,
                          contract_id: str | None = None,
                          created_at: datetime | None = None) -> SignedMDIContract:
    try: tenant=str(UUID(tenant_id))
    except (ValueError,TypeError,AttributeError) as exc: raise ContractError("tenant_id must be a UUID") from exc
    if not _EVENT_RE.fullmatch(event_type): raise ContractError("invalid event_type")
    if disposition not in _ALLOWED_DISPOSITIONS: raise ContractError("invalid disposition")
    if not isinstance(payload,dict): raise ContractError("payload must be an object")
    if len(canonical_json(payload))>256_000: raise ContractError("payload exceeds 256 KiB")
    if previous_hash is not None and not _HASH_RE.fullmatch(previous_hash): raise ContractError("invalid previous_hash")
    if not signer_key_id or len(signer_key_id)>128: raise ContractError("invalid signer_key_id")
    when=(created_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    from uuid import uuid4
    cid=contract_id or f"mdi_cnt_{uuid4().hex}"
    evidence_hash=hashlib.sha256(canonical_json(payload)).hexdigest()
    body={"contract_id":cid,"tenant_id":tenant,"event_type":event_type,"disposition":disposition,
          "evidence_hash":evidence_hash,"payload":payload,"previous_hash":previous_hash or ("0"*64),
          "created_at":when,"signer_key_id":signer_key_id}
    current=hashlib.sha256(canonical_json(body)).hexdigest()
    signed={**body,"current_hash":current}
    signature=base64.b64encode(private_key.sign(canonical_json(signed))).decode("ascii")
    return SignedMDIContract(cid,tenant,event_type,disposition,evidence_hash,payload,
        body["previous_hash"],current,signer_key_id,signature,when)

def verify_signed_contract(contract: SignedMDIContract, public_key: Ed25519PublicKey) -> bool:
    body={"contract_id":contract.contract_id,"tenant_id":str(UUID(contract.tenant_id)),
          "event_type":contract.event_type,"disposition":contract.disposition,
          "evidence_hash":contract.evidence_hash,"payload":contract.payload,
          "previous_hash":contract.previous_hash,"created_at":contract.created_at,
          "signer_key_id":contract.signer_key_id}
    if hashlib.sha256(canonical_json(contract.payload)).hexdigest()!=contract.evidence_hash: return False
    if hashlib.sha256(canonical_json(body)).hexdigest()!=contract.current_hash: return False
    try:
        public_key.verify(base64.b64decode(contract.signature_b64,validate=True),
                          canonical_json({**body,"current_hash":contract.current_hash}))
        return True
    except Exception:
        return False

def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw=key.public_bytes(Encoding.Raw,PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()
