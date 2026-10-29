"""Evidence-grounded multi-agent threat review orchestration primitives.

Agent narratives are hypotheses, not authoritative evidence. The adjudicator never parses
opinion text into a threat verdict; it checks provenance, coverage, corroboration and
policy gates and returns a review disposition.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal
import hashlib
import json
import re

_HEX = re.compile(r"^[0-9a-f]{64}$")
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    tenant_id: str
    source_service: str
    content_sha256: str
    verified: bool
    observed_at: str
    coverage_status: str


@dataclass(frozen=True, slots=True)
class AgentHypothesis:
    agent_id: str
    stance: Literal["support", "challenge", "uncertain"]
    summary: str
    evidence_ids: tuple[str, ...]


def adjudicate_evidence(*, tenant_id: str, evidence: tuple[EvidenceRef, ...],
                        hypotheses: tuple[AgentHypothesis, ...],
                        minimum_independent_sources: int = 2) -> dict:
    if not tenant_id or not 1 <= minimum_independent_sources <= 10:
        raise ValueError("invalid_adjudication_parameters")
    ids: set[str] = set()
    valid: list[EvidenceRef] = []
    gaps: list[str] = []
    for item in evidence:
        if item.evidence_id in ids:
            raise ValueError("duplicate_evidence_id")
        ids.add(item.evidence_id)
        if item.tenant_id != tenant_id:
            raise ValueError("cross_tenant_evidence")
        if not _HEX.fullmatch(item.content_sha256):
            gaps.append(f"invalid_hash:{item.evidence_id}")
            continue
        if not item.verified:
            gaps.append(f"unverified_evidence:{item.evidence_id}")
            continue
        if item.coverage_status != "complete":
            gaps.append(f"source_coverage_{item.coverage_status}:{item.evidence_id}")
            continue
        valid.append(item)
    cited: set[str] = set()
    for hypothesis in hypotheses:
        if not hypothesis.agent_id or not hypothesis.summary.strip():
            raise ValueError("invalid_agent_hypothesis")
        unknown = set(hypothesis.evidence_ids) - ids
        if unknown:
            raise ValueError("hypothesis_cites_unknown_evidence")
        cited.update(hypothesis.evidence_ids)
    corroborating = [item for item in valid if item.evidence_id in cited]
    independent_sources = {item.source_service for item in corroborating}
    support = sum(1 for h in hypotheses if h.stance == "support" and
                  set(h.evidence_ids).intersection(item.evidence_id for item in corroborating))
    challenge = sum(1 for h in hypotheses if h.stance == "challenge")
    enough = len(independent_sources) >= minimum_independent_sources
    if not corroborating:
        disposition, confidence = "insufficient_evidence", "none"
    elif not enough or gaps:
        disposition, confidence = "human_review_required", "limited"
    elif support == 0 or challenge > 0:
        disposition, confidence = "human_review_required", "contested"
    else:
        disposition, confidence = "corroborated_for_review", "corroborated"
    payload = {"schema":"cyclothone.ai-security-adjudication.v1","tenant_id":tenant_id,
               "disposition":disposition,"confidence_class":confidence,
               "evidence_ids":sorted(item.evidence_id for item in corroborating),
               "independent_sources":sorted(independent_sources),
               "coverage_gaps":sorted(gaps),"hypothesis_count":len(hypotheses),
               "automatic_enforcement_permitted":False}
    payload["decision_sha256"] = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return payload
