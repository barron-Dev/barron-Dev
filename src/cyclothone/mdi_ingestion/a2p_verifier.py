"""Defensive A2P request-integrity verification; not a carrier route or SHAKEN/STIR substitute."""
from __future__ import annotations
import hashlib, hmac, json, re, time
from dataclasses import dataclass
from typing import Any, Mapping
from .contracts import canonical_json

_E164=re.compile(r"^\+[1-9][0-9]{7,14}$")
class A2PValidationError(ValueError): pass
@dataclass(frozen=True)
class A2PVerification:
    accepted: bool
    disposition: str
    payload_sha256: str
    reason_code: str

def validate_a2p_payload(payload: Mapping[str,Any]) -> dict[str,Any]:
    if not isinstance(payload,Mapping): raise A2PValidationError("payload must be an object")
    required={"tenant_id","message_id","from_e164","to_e164","body","issued_at"}
    if set(payload)!=required: raise A2PValidationError("unexpected or missing payload fields")
    for key in ("from_e164","to_e164"):
        if not isinstance(payload[key],str) or not _E164.fullmatch(payload[key]): raise A2PValidationError(f"invalid {key}")
    if not isinstance(payload["message_id"],str) or not 1<=len(payload["message_id"])<=128: raise A2PValidationError("invalid message_id")
    if not isinstance(payload["body"],str) or len(payload["body"].encode("utf-8"))>4096: raise A2PValidationError("message body too large")
    if not isinstance(payload["issued_at"],int): raise A2PValidationError("issued_at must be Unix seconds")
    if abs(int(time.time())-payload["issued_at"])>300: raise A2PValidationError("request timestamp outside allowed window")
    if not isinstance(payload["tenant_id"],str) or not payload["tenant_id"]: raise A2PValidationError("tenant_id required")
    return dict(payload)

def verify_request_signature(payload: Mapping[str,Any], signature_hex: str, shared_secret: bytes) -> A2PVerification:
    """HMAC authenticates the API client request; it does not attest SMS origin or carrier identity."""
    clean=validate_a2p_payload(payload)
    if len(shared_secret)<32: raise A2PValidationError("configured signing secret must be at least 32 bytes")
    digest=hashlib.sha256(canonical_json(clean)).hexdigest()
    expected=hmac.new(shared_secret,canonical_json(clean),hashlib.sha256).hexdigest()
    if not isinstance(signature_hex,str) or not hmac.compare_digest(expected,signature_hex.lower()):
        return A2PVerification(False,"rejected",digest,"invalid_request_signature")
    return A2PVerification(True,"accepted_for_downstream_policy",digest,"client_request_authenticated")
