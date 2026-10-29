"""Cyclothone-owned, evidence-bounded app-hash intelligence primitives.

This module does not fetch third-party feeds, inspect apps, or quarantine them.
Only trusted, source-backed records may be promoted into a signed registry.
"""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Iterable

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_VERDICTS = {"malicious","benign","unknown","revoked"}

class ThreatHashError(ValueError):
    """Invalid hash intelligence record."""

@dataclass(frozen=True)
class HashIntelRecord:
    app_sha256: str
    verdict: str
    confidence: int
    source_ids: tuple[str, ...]
    rule_version: str
    evidence_hash: str
    action: str

def build_hash_intel_record(*, app_sha256: str, verdict: str, source_ids: Iterable[str], rule_version: str) -> HashIntelRecord:
    if not isinstance(app_sha256,str) or not _HEX64.fullmatch(app_sha256):
        raise ThreatHashError("app_sha256 must be lowercase SHA-256 hex")
    if verdict not in _ALLOWED_VERDICTS:
        raise ThreatHashError("unsupported verdict")
    if not isinstance(rule_version,str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",rule_version):
        raise ThreatHashError("invalid rule_version")
    ids = list(source_ids)
    if len(ids)>32 or any(not isinstance(x,str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}",x) for x in ids):
        raise ThreatHashError("source_ids must be bounded stable identifiers")
    if len(set(ids)) != len(ids):
        raise ThreatHashError("duplicate source identifier")
    ids = sorted(ids)
    if verdict=="malicious" and len(ids)<2:
        confidence,action = 0,"monitor_and_collect_evidence"
    elif verdict=="malicious":
        confidence,action = 100,"recommend_corporate_app_quarantine_pending_policy"
    elif verdict=="revoked":
        confidence,action = 100,"reject_registry_contract_and_require_review"
    elif verdict=="benign":
        confidence,action = 50,"allow_only_under_tenant_policy"
    else:
        confidence,action = 0,"monitor_and_collect_evidence"
    payload = {"app_sha256":app_sha256,"verdict":verdict,"confidence":confidence,"source_ids":ids,"rule_version":rule_version,"action":action}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return HashIntelRecord(app_sha256,verdict,confidence,tuple(ids),rule_version,digest,action)
