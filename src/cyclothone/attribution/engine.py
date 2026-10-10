from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

# Weights intentionally sum to 1.0. Infrastructure has the highest single weight.
ATTRIBUTION_WEIGHTS = {
    "infrastructure": 0.25, "ttp": 0.20, "malware": 0.15,
    "behaviour": 0.15, "victimology": 0.10, "identity": 0.10,
    "temporal": 0.05,
}
CONFIDENCE_TIERS = (
    (0.75, "CONFIRMED"), (0.50, "SUSPECTED"),
    (0.30, "POSSIBLE"), (0.0, "INSUFFICIENT"),
)
ATTACK_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
CAPEC_ID = re.compile(r"^CAPEC-[0-9]{1,5}$")
DIAMOND_VERTICES = ("adversary", "capability", "infrastructure", "victim")
KILL_CHAIN_PHASES = {
    "reconnaissance": ("forum_target_mention", "scanning_activity", "target_research"),
    "weaponization": ("exploit_advertisement", "malware_sale", "payload_preparation"),
    "delivery": ("phishing_infrastructure", "malicious_attachment", "malicious_link"),
    "exploitation": ("vulnerability_exploited", "exploit_execution", "cve_exploitation"),
    "installation": ("malware_sample", "loader_detected", "persistence_artifact"),
    "command_and_control": ("c2_infrastructure", "beaconing", "c2_domain"),
    "actions_on_objectives": ("credential_dump", "data_exfiltration", "ransomware_deployment"),
}


def _strings(values: Iterable[Any] | None) -> set[str]:
    if values is None or isinstance(values, (str, bytes, dict)):
        return set()
    try:
        return {str(v).strip().lower() for v in values if str(v).strip()}
    except TypeError:
        return set()


def _jaccard(left: Iterable[Any] | None, right: Iterable[Any] | None) -> float:
    a, b = _strings(left), _strings(right)
    return len(a & b) / len(a | b) if a and b else 0.0


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number):
        return 0.0
    return min(1.0, max(0.0, number))


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except ValueError:
        return None


UNIFIED_KILL_CHAIN_PHASES = {
    "reconnaissance": ("forum_target_mention", "scanning_activity", "target_research"),
    "weaponization": ("exploit_advertisement", "malware_sale", "payload_preparation"),
    "delivery": ("phishing_infrastructure", "malicious_attachment", "malicious_link"),
    "social_engineering": ("social_engineering", "spearphishing", "pretext"),
    "exploitation": ("vulnerability_exploited", "exploit_execution", "cve_exploitation"),
    "persistence": ("persistence_artifact", "autorun", "scheduled_task"),
    "defense_evasion": ("defense_evasion", "obfuscation", "log_tampering"),
    "command_and_control": ("c2_infrastructure", "beaconing", "c2_domain"),
    "pivoting": ("proxy_chaining", "pivoting", "port_forwarding"),
    "discovery": ("internal_discovery", "network_discovery", "account_discovery"),
    "privilege_escalation": ("privilege_escalation", "exploit_privilege"),
    "execution": ("process_execution", "powershell", "script_execution"),
    "credential_access": ("credential_dump", "credential_theft", "stealer_log"),
    "lateral_movement": ("lateral_movement", "rdp", "smb"),
    "collection": ("data_collection", "archive_staging"),
    "exfiltration": ("data_exfiltration", "exfiltration"),
    "impact": ("ransomware_deployment", "data_destruction", "extortion"),
}


def map_unified_kill_chain_phase(signals: Iterable[str] | None) -> list[str]:
    observed = _strings(signals)
    return [phase for phase, indicators in UNIFIED_KILL_CHAIN_PHASES.items() if observed.intersection(indicators)]


def validate_attack_techniques(values: Iterable[Any] | None) -> list[str]:
    """Keep syntactically valid ATT&CK technique IDs; unknown IDs still need catalogue validation."""
    return sorted({str(v).strip().upper() for v in (values or []) if ATTACK_ID.fullmatch(str(v).strip().upper())})


def validate_capec_ids(values: Iterable[Any] | None) -> list[str]:
    return sorted({str(v).strip().upper() for v in (values or []) if CAPEC_ID.fullmatch(str(v).strip().upper())})


def map_kill_chain_phase(signals: Iterable[str] | None) -> list[str]:
    observed = _strings(signals)
    return [phase for phase, indicators in KILL_CHAIN_PHASES.items() if observed.intersection(indicators)]


def build_diamond_model(activity: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Always return all four Diamond Model vertices, explicitly marking unknowns."""
    adversary = activity.get("adversary") or {}
    capability = activity.get("capability") or {}
    infrastructure = activity.get("infrastructure") or {}
    victim = activity.get("victim") or {}
    return {
        "adversary": {"handles": sorted(_strings(adversary.get("handles"))), "aliases": sorted(_strings(adversary.get("aliases"))), "known_associations": sorted(_strings(adversary.get("known_associations"))), "status": "observed" if adversary else "unknown"},
        "capability": {"malware_hashes": sorted(_strings(capability.get("malware_hashes"))), "malware_families": sorted(_strings(capability.get("malware_families"))), "tools": sorted(_strings(capability.get("tools"))), "exploit_ids": sorted(_strings(capability.get("exploit_ids"))), "attack_techniques": validate_attack_techniques(capability.get("attack_techniques")), "capec_ids": validate_capec_ids(capability.get("capec_ids")), "status": "observed" if capability else "unknown"},
        "infrastructure": {"domains": sorted(_strings(infrastructure.get("domains"))), "ips": sorted(_strings(infrastructure.get("ips"))), "hosting_providers": sorted(_strings(infrastructure.get("hosting_providers"))), "tls_certificates": sorted(_strings(infrastructure.get("tls_certificates"))), "c2_frameworks": sorted(_strings(infrastructure.get("c2_frameworks"))), "status": "observed" if infrastructure else "unknown"},
        "victim": {"sectors": sorted(_strings(victim.get("sectors"))), "regions": sorted(_strings(victim.get("regions"))), "organisation_sizes": sorted(_strings(victim.get("organisation_sizes"))), "status": "observed" if victim else "unknown"},
    }


def _identity_overlap(activity: dict[str, Any], profile: dict[str, Any]) -> float:
    left = _strings(activity.get("aliases")) | _strings(activity.get("emails")) | _strings(activity.get("pgp_fingerprints")) | _strings(activity.get("wallets"))
    right = _strings(profile.get("aliases")) | _strings(profile.get("emails")) | _strings(profile.get("pgp_fingerprints")) | _strings(profile.get("wallets"))
    return len(left & right) / len(left | right) if left and right else 0.0


def _temporal_similarity(left: Iterable[Any] | None, right: Iterable[Any] | None) -> float:
    a = [_timestamp(v) for v in (left or [])]
    b = [_timestamp(v) for v in (right or [])]
    a = [v for v in a if v is not None]
    b = [v for v in b if v is not None]
    if not a or not b:
        return 0.0
    # Compare UTC hour-of-week histograms, not inferred geographic time zones.
    ah = Counter(v.weekday() * 24 + v.hour for v in a)
    bh = Counter(v.weekday() * 24 + v.hour for v in b)
    keys = set(ah) | set(bh)
    numerator = sum(min(ah[k] / len(a), bh[k] / len(b)) for k in keys)
    return _clamp(numerator)


def _behaviour_similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    # Exact categorical overlap + bounded numeric similarity. Language/style can be
    # spoofed; this is a weak clue and must never identify a real-world person.
    categorical = ("active_hours", "active_days", "hosting_providers", "registrars", "malware_families", "operational_tempo", "negotiation_style", "recruitment_phrases")
    scores = [_jaccard(left.get(k, []), right.get(k, [])) for k in categorical if left.get(k) and right.get(k)]
    for key in ("vocabulary_richness", "avg_sentence_length"):
        if isinstance(left.get(key), (int, float)) and isinstance(right.get(key), (int, float)):
            x, y = float(left[key]), float(right[key])
            scores.append(1.0 - min(1.0, abs(x-y) / max(abs(x), abs(y), 1.0)))
    return sum(scores) / len(scores) if scores else 0.0


@dataclass(slots=True)
class AttributionEvidence:
    infrastructure: dict[str, list[str]] = field(default_factory=dict)
    attack_techniques: list[str] = field(default_factory=list)
    capec_ids: list[str] = field(default_factory=list)
    malware_hashes: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    behavioural_features: dict[str, Any] = field(default_factory=dict)
    target_sectors: list[str] = field(default_factory=list)
    target_regions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    pgp_fingerprints: list[str] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)
    activity_timestamps: list[str] = field(default_factory=list)
    observed_actions: list[str] = field(default_factory=list)
    source_evidence_ids: list[str] = field(default_factory=list)
    independent_sources: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AttributionEvidence":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: value[k] for k in allowed if k in value})


@dataclass(slots=True)
class ActorProfile:
    actor_id: str
    primary_name: str
    actor_type: str = "UNKNOWN"
    aliases: list[str] = field(default_factory=list)
    attributed_to: str | None = None
    attribution_confidence: str = "INSUFFICIENT"
    infrastructure: dict[str, list[str]] = field(default_factory=dict)
    attack_techniques: list[str] = field(default_factory=list)
    capec_ids: list[str] = field(default_factory=list)
    malware_hashes: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    behavioural_features: dict[str, Any] = field(default_factory=dict)
    target_sectors: list[str] = field(default_factory=list)
    target_regions: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    pgp_fingerprints: list[str] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)
    activity_timestamps: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_activity: str | None = None
    major_campaigns: list[str] = field(default_factory=list)
    evolution_notes: list[str] = field(default_factory=list)
    analyst_review_required: bool = True
    profile_version: int = 1

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ActorProfile":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: value[k] for k in allowed if k in value})


def compute_attribution(activity: AttributionEvidence | dict[str, Any], profile: ActorProfile | dict[str, Any]) -> dict[str, Any]:
    """Score association probabilistically. This is not proof of actor identity."""
    a = asdict(activity) if isinstance(activity, AttributionEvidence) else dict(activity)
    p = asdict(profile) if isinstance(profile, ActorProfile) else dict(profile)
    ai, pi = a.get("infrastructure") or {}, p.get("infrastructure") or {}
    infra_parts = [_jaccard(ai.get(k), pi.get(k)) for k in ("domains", "ips", "hosting_providers", "tls_certificates", "c2_frameworks") if ai.get(k) and pi.get(k)]
    infra = sum(infra_parts) / len(infra_parts) if infra_parts else 0.0
    signals = {
        "infrastructure": _clamp(infra),
        "ttp": _jaccard(_strings(a.get("attack_techniques")) | _strings(a.get("capec_ids")), _strings(p.get("attack_techniques")) | _strings(p.get("capec_ids"))),
        "malware": max((_jaccard(a.get("malware_hashes"), p.get("malware_hashes")), _jaccard(a.get("malware_families"), p.get("malware_families"))), default=0.0),
        "behaviour": _behaviour_similarity(a.get("behavioural_features") or {}, p.get("behavioural_features") or {}),
        "victimology": (_jaccard(a.get("target_sectors"), p.get("target_sectors")) + _jaccard(a.get("target_regions"), p.get("target_regions"))) / 2,
        "identity": _identity_overlap(a, p),
        "temporal": _temporal_similarity(a.get("activity_timestamps"), p.get("activity_timestamps")),
    }
    composite = round(sum(signals[k] * ATTRIBUTION_WEIGHTS[k] for k in ATTRIBUTION_WEIGHTS), 3)
    tier = next(name for threshold, name in CONFIDENCE_TIERS if composite >= threshold)
    evidence_present = [k for k, value in signals.items() if value > 0]
    independent_sources = _strings(a.get("independent_sources"))
    # High numerical similarity alone cannot establish attribution. At least two
    # independent evidence families and two source records are required; analyst
    # review remains mandatory even when the score crosses the highest threshold.
    guardrail_reasons = []
    if len(evidence_present) < 2:
        guardrail_reasons.append("fewer_than_two_independent_signal_families")
    if len(independent_sources) < 2:
        guardrail_reasons.append("fewer_than_two_independent_sources")
    if signals["infrastructure"] <= 0 and signals["identity"] <= 0:
        guardrail_reasons.append("no_infrastructure_or_identity_overlap")
    if guardrail_reasons and tier in {"CONFIRMED", "SUSPECTED"}:
        tier = "POSSIBLE" if composite >= 0.30 else "INSUFFICIENT"
    explanation = [f"{name} overlap={value:.3f} (weight={ATTRIBUTION_WEIGHTS[name]:.2f})" for name, value in signals.items()]
    explanation.extend(guardrail_reasons)
    return {
        "score": composite, "tier": tier, "raw_score_tier": next(name for threshold, name in CONFIDENCE_TIERS if composite >= threshold),
        "signals": signals, "explanation": explanation, "guardrail_reasons": guardrail_reasons,
        "independent_signal_families": evidence_present,
        "independent_source_count": len(independent_sources),
        "analyst_review_required": True,
        "reporting_language": {
            "CONFIRMED": "Cyclothone DW assesses this activity is associated with the actor with high confidence; analyst confirmation is required.",
            "SUSPECTED": "Cyclothone DW assesses this activity is likely associated with the actor; uncertainty remains.",
            "POSSIBLE": "Cyclothone DW identifies a possible association; analyst review is required.",
            "INSUFFICIENT": "Cyclothone DW has insufficient evidence to attribute this activity.",
        }[tier],
    }


def extract_behavioural_fingerprint(activity: dict[str, Any]) -> dict[str, Any]:
    """Summarize observable campaign behaviour without trying to identify a person."""
    timestamps = [_timestamp(v) for v in activity.get("timestamps", [])]
    timestamps = [v for v in timestamps if v is not None]
    hours = Counter(str(v.hour) for v in timestamps)
    days = Counter(str(v.weekday()) for v in timestamps)
    messages = [str(v) for v in activity.get("messages", []) if isinstance(v, str) and v.strip()]
    words = [re.findall(r"[\w'-]+", m.lower()) for m in messages]
    flat = [w for row in words for w in row]
    features: dict[str, Any] = {
        "active_hours": sorted(hours, key=int), "active_days": sorted(days, key=int),
        "message_count": len(messages), "sample_count": len(timestamps),
        "vocabulary_richness": round(len(set(flat)) / len(flat), 4) if flat else None,
        "avg_sentence_length": round(sum(len(row) for row in words) / len(words), 2) if words else None,
        "hosting_providers": sorted(_strings(activity.get("hosting_providers"))),
        "registrars": sorted(_strings(activity.get("registrars"))),
        "malware_families": sorted(_strings(activity.get("malware_families"))),
        "operational_tempo": str(activity.get("operational_tempo") or "unknown")[:80],
        "negotiation_style": str(activity.get("negotiation_style") or "unknown")[:80],
        "recruitment_phrases": sorted(_strings(activity.get("recruitment_phrases"))),
        "limitations": ["Stylometry and operating-hour patterns are spoofable and are not person-identification evidence."],
    }
    # Never store message text, typo signatures, inferred timezone, or biometric data.
    return features


def build_attribution_assessment(activity: dict[str, Any], profile: ActorProfile | dict[str, Any]) -> dict[str, Any]:
    evidence = AttributionEvidence.from_dict(activity)
    profile_obj = profile if isinstance(profile, ActorProfile) else ActorProfile.from_dict(profile)
    score = compute_attribution(evidence, profile_obj)
    return {
        "actor_id": profile_obj.actor_id,
        "actor_name": profile_obj.primary_name,
        "diamond_model": build_diamond_model(activity.get("diamond_model") or {}),
        "attack_techniques": validate_attack_techniques(evidence.attack_techniques),
        "kill_chain_phases": map_kill_chain_phase(evidence.observed_actions),
        **score,
    }
