from __future__ import annotations
import base64, hashlib, json, time
from dataclasses import dataclass, field
from urllib.parse import urlparse

@dataclass
class FapiRequest:
    client_id: str
    redirect_uri: str | None = None
    response_type: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    scope: str = ""
    dpop_jti: str | None = None
    dpop_iat: int | None = None
    dpop_htu: str | None = None
    dpop_htm: str | None = None

@dataclass
class FapiVerdict:
    allowed: bool
    reasons: list[dict] = field(default_factory=list)

class FapiPolicy:
    """Fail-closed FAPI 2.0 request policy; cryptographic proof is delegated to the configured AS/gateway."""
    MAX_DPOP_AGE = 300
    def __init__(self, client: dict):
        self.client = client

    def validate(self, req: FapiRequest, method: str = "POST", url: str | None = None, now: int | None = None) -> FapiVerdict:
        reasons=[]
        if self.client.get("status") != "active":
            reasons.append({"code":"client_revoked"})
        if req.client_id != self.client.get("client_id"):
            reasons.append({"code":"client_mismatch"})
        if req.redirect_uri is not None and req.redirect_uri not in (self.client.get("redirect_uris") or []):
            reasons.append({"code":"redirect_uri_not_registered"})
        if req.response_type and req.response_type != "code":
            reasons.append({"code":"response_type_not_allowed"})
        if self.client.get("require_pkce", True):
            if not req.code_challenge or req.code_challenge_method != "S256":
                reasons.append({"code":"pkce_s256_required"})
        requested=set(filter(None,req.scope.split()))
        allowed=set(self.client.get("scopes") or [])
        if not requested.issubset(allowed):
            reasons.append({"code":"scope_not_allowed","scopes":sorted(requested-allowed)})
        if self.client.get("require_dpop"):
            if not req.dpop_jti or not req.dpop_iat or not req.dpop_htu or not req.dpop_htm:
                reasons.append({"code":"dpop_proof_required"})
            else:
                t=int(time.time()) if now is None else now
                if abs(t-int(req.dpop_iat)) > self.MAX_DPOP_AGE:
                    reasons.append({"code":"dpop_iat_expired"})
                if req.dpop_htm.upper() != method.upper():
                    reasons.append({"code":"dpop_htm_mismatch"})
                if url and req.dpop_htu != url:
                    reasons.append({"code":"dpop_htu_mismatch"})
        return FapiVerdict(not reasons,reasons)

def hash_state(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()

def validate_https_uri(uri: str) -> bool:
    p=urlparse(uri)
    return p.scheme=="https" and bool(p.netloc)

def parse_jwt_payload_untrusted(token: str) -> dict:
    """Decode only for routing/telemetry. Never treat this as signature verification."""
    parts=token.split(".")
    if len(parts)!=3:
        raise ValueError("invalid compact JWT")
    raw=parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(raw))
