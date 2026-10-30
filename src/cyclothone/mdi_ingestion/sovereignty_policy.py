"""Deterministic, fail-closed MDI data-sovereignty policy decisions.

Country hints are inputs, not proof of physical location or legal jurisdiction.
This module does not claim legal advice or choose a data region by GPS alone.
"""
from __future__ import annotations
import hashlib, hmac, json, re
from dataclasses import dataclass
from typing import Iterable

_SCHEMA = "cyclothone.mdi.sovereignty-decision.v1"
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_PROFILES = {
    "AE": {"profile": "ae-minimization-v1", "allowed": frozenset({"integrity_status","policy_version","adapter_version","evidence_hash","coarse_country","event_time_bucket"})},
    "FR": {"profile": "eu-minimization-v1", "allowed": frozenset({"integrity_status","policy_version","adapter_version","evidence_hash","event_time_bucket"})},
    "DE": {"profile": "eu-minimization-v1", "allowed": frozenset({"integrity_status","policy_version","adapter_version","evidence_hash","event_time_bucket"})},
    "US": {"profile": "us-minimization-v1", "allowed": frozenset({"integrity_status","policy_version","adapter_version","evidence_hash","coarse_country","event_time_bucket"})},
}
_RESTRICTIVE = {"profile": "unknown-jurisdiction-local-only-v1", "allowed": frozenset({"integrity_status","policy_version","adapter_version","evidence_hash"})}

class SovereigntyPolicyError(ValueError):
    """Malformed policy input."""

@dataclass(frozen=True)
class SovereigntyDecision:
    schema: str
    profile_id: str
    policy_version: str
    jurisdiction_status: str
    allowed_fields: tuple[str, ...]
    masked_fields: tuple[str, ...]
    transmission: str
    evidence_hash: str
    limitations: tuple[str, ...]

def resolve_sovereignty_policy(*, country_candidates: Iterable[str], jurisdiction_verified: bool, policy_version: str = "mdi-sovereignty-1") -> SovereigntyDecision:
    """Resolve a reproducible decision; GPS/MCC hints cannot verify jurisdiction."""
    if not isinstance(jurisdiction_verified, bool):
        raise SovereigntyPolicyError("jurisdiction_verified must be boolean")
    if not isinstance(policy_version, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", policy_version):
        raise SovereigntyPolicyError("invalid policy_version")
    try:
        candidates = list(country_candidates)
    except TypeError as exc:
        raise SovereigntyPolicyError("country_candidates must be iterable") from exc
    if len(candidates) > 16:
        raise SovereigntyPolicyError("too many country candidates")
    normalized = []
    for candidate in candidates:
        if not isinstance(candidate, str) or not _COUNTRY.fullmatch(candidate.upper()):
            raise SovereigntyPolicyError("country candidates must be ISO alpha-2 codes")
        normalized.append(candidate.upper())
    unique = sorted(set(normalized))
    if not jurisdiction_verified or len(unique) != 1 or unique[0] not in _PROFILES:
        profile, status, transmission = _RESTRICTIVE, "unverified_or_conflicting", "local_only"
    else:
        profile, status, transmission = _PROFILES[unique[0]], "verified_by_trusted_control_plane", "minimized_fields_only"
    allowed = tuple(sorted(profile["allowed"]))
    payload = {"schema":_SCHEMA,"profile_id":profile["profile"],"policy_version":policy_version,"jurisdiction_status":status,"allowed_fields":allowed,"transmission":transmission}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return SovereigntyDecision(_SCHEMA,profile["profile"],policy_version,status,allowed,("device_fingerprint","raw_location","installed_app_inventory"),transmission,digest,
        ("Country hints are not authoritative legal-jurisdiction evidence.","No cloud-region selection or legal-compliance guarantee is made by this module.","Unverified or conflicting jurisdiction remains local-only."))

def pseudonymize_identifier(identifier: str, tenant_secret: bytes) -> str:
    """Tenant-keyed HMAC pseudonym; plain salted SHA-256 is not used."""
    if not isinstance(identifier,str) or not identifier or len(identifier)>512:
        raise SovereigntyPolicyError("identifier must be a non-empty bounded string")
    if not isinstance(tenant_secret,bytes) or len(tenant_secret)<32:
        raise SovereigntyPolicyError("tenant_secret must be at least 32 bytes")
    return hmac.new(tenant_secret,identifier.encode("utf-8"),hashlib.sha256).hexdigest()
