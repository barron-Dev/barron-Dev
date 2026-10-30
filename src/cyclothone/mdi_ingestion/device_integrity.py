"""Deterministic, evidence-bounded mobile device integrity evaluation.
Evaluates observations from a trusted platform adapter; does not claim zero-click detection.
"""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Any

_SCHEMA = "cyclothone.mdi.device-integrity.v1"
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_ALLOWED = {"root_indicator","jailbreak_indicator","debugger_detected","app_signature_mismatch","device_attestation_failed","known_malware_match","tls_validation_failure","dns_configuration_changed","arp_conflict_observed","developer_mode_enabled"}
_MEDIUM = {"root_indicator","jailbreak_indicator","debugger_detected"}

class DeviceIntegrityError(ValueError):
    """Malformed or ambiguous evidence."""

@dataclass(frozen=True)
class DeviceIntegrityResult:
    schema: str
    device_key: str
    disposition: str
    severity: int
    signals: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    evidence_hash: str
    recommended_action: str
    rule_version: str

def evaluate_device_integrity(*, tenant_id: str, device_key: str, observations: list[dict[str, Any]], platform: str, adapter_version: str, coverage: str = "complete") -> DeviceIntegrityResult:
    """Produce a reproducible assessment. device_key is an opaque tenant-scoped SHA-256, never a raw hardware ID."""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", tenant_id):
        raise DeviceIntegrityError("tenant_id must be UUID-shaped")
    if not _HEX64.fullmatch(device_key):
        raise DeviceIntegrityError("device_key must be SHA-256 hex")
    if platform not in {"android", "ios"}:
        raise DeviceIntegrityError("unsupported platform")
    if not adapter_version or len(adapter_version) > 64:
        raise DeviceIntegrityError("adapter_version required")
    if coverage not in {"complete", "partial", "unavailable"}:
        raise DeviceIntegrityError("invalid coverage")
    if not isinstance(observations, list) or len(observations) > 256:
        raise DeviceIntegrityError("observations must be a list of at most 256")
    normalized, seen = [], set()
    for item in observations:
        if not isinstance(item, dict) or set(item) - {"signal","observed","source","detail_hash"}:
            raise DeviceIntegrityError("invalid observation shape")
        signal, observed, source = item.get("signal"), item.get("observed"), item.get("source")
        if signal not in _ALLOWED or not isinstance(observed, bool):
            raise DeviceIntegrityError("unknown signal or invalid observed value")
        if source not in {"os_adapter","attestation","network_adapter","local_policy"}:
            raise DeviceIntegrityError("untrusted observation source")
        detail_hash = item.get("detail_hash")
        if detail_hash is not None and (not isinstance(detail_hash, str) or not _HEX64.fullmatch(detail_hash)):
            raise DeviceIntegrityError("detail_hash must be SHA-256 hex")
        if (signal, source) in seen:
            raise DeviceIntegrityError("duplicate signal/source pair")
        seen.add((signal, source))
        normalized.append({"signal":signal,"observed":observed,"source":source,"detail_hash":detail_hash})
    normalized.sort(key=lambda x:(x["signal"],x["source"],x["observed"],x["detail_hash"] or ""))
    active = {x["signal"] for x in normalized if x["observed"]}
    # Source labels are caller-controlled metadata here, not verified provenance.
    # This evaluator must never promote a client observation into a confirmed
    # threat or authorize quarantine. Trusted server-side verifiers own promotion.
    if active & {"device_attestation_failed","app_signature_mismatch"}:
        severity, disposition, action = 5, "human_review_required", "restrict_sensitive_access_and_require_review"
    elif "known_malware_match" in active:
        severity, disposition, action = 4, "human_review_required", "require_trusted_hash_verdict_before_quarantine"
    elif active & (_MEDIUM | {"tls_validation_failure","dns_configuration_changed","arp_conflict_observed"}):
        severity, disposition, action = 3, "human_review_required", "step_up_authentication_and_collect_fresh_evidence"
    elif coverage != "complete" or not normalized:
        severity, disposition, action = 1, ("source_unavailable" if coverage == "unavailable" else "partial_coverage"), "preserve_access_policy_and_report_coverage_gap"
    else:
        severity, disposition, action = 1, "unknown", "continue_policy_checks_without_claiming_device_clean"
    limitations = [
        "Client-reported signals are evidence, not cryptographic proof by themselves.",
        "A normal result does not rule out zero-click exploits, kernel compromise, or unknown spyware.",
        "Consumer iOS apps cannot enumerate other apps or inspect arbitrary process trees.",
        "Battery drain is not treated as a spyware indicator because it is non-specific.",
        "This evaluator does not wipe devices, quarantine operating systems, or block networks.",
    ]
    if platform == "ios":
        limitations.append("iOS network filtering and attestation depend on approved OS capabilities and entitlements.")
    if coverage != "complete":
        limitations.append("Coverage is incomplete; this result cannot be represented as verified clean.")
    payload = {"schema":_SCHEMA,"tenant_id":tenant_id.lower(),"device_key":device_key,"platform":platform,"adapter_version":adapter_version,"coverage":coverage,"signals":normalized,"disposition":disposition,"severity":severity,"recommended_action":action,"rule_version":"mdi-device-rules-1"}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return DeviceIntegrityResult(_SCHEMA,device_key,disposition,severity,tuple(normalized),tuple(limitations),digest,action,"mdi-device-rules-1")
