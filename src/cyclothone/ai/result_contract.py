"""Typed, honest result contracts for multi-source AI operations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

OverallStatus = Literal["complete", "partial_coverage", "blocked", "failed"]
SourceStatus = Literal["succeeded", "failed", "unavailable", "not_checked", "blocked"]


@dataclass(frozen=True, slots=True)
class SourceOutcome:
    source: str
    status: SourceStatus
    evidence_count: int = 0
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"succeeded", "failed", "unavailable", "not_checked", "blocked"}:
            raise ValueError("invalid_source_status")
        if not self.source.strip():
            raise ValueError("source_required")
        if self.evidence_count < 0:
            raise ValueError("evidence_count_must_be_nonnegative")
        if self.status == "succeeded" and self.reason_code is not None:
            raise ValueError("successful_source_must_not_have_failure_reason")
        if self.status != "succeeded" and not self.reason_code:
            raise ValueError("non_successful_source_requires_reason_code")


@dataclass(frozen=True, slots=True)
class ResultContract:
    request_id: str
    status: OverallStatus
    sources: tuple[SourceOutcome, ...]
    result: Mapping[str, Any]
    schema_version: str = "1"

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial_coverage", "blocked", "failed"}:
            raise ValueError("invalid_overall_status")
        if not self.request_id.strip():
            raise ValueError("request_id_required")
        if self.schema_version != "1":
            raise ValueError("unsupported_result_contract_version")
        if len({s.source for s in self.sources}) != len(self.sources):
            raise ValueError("duplicate_source_outcome")
        if self.status in ("complete", "partial_coverage") and not self.sources:
            raise ValueError("coverage_result_requires_source_outcomes")
        incomplete = any(s.status != "succeeded" for s in self.sources)
        if self.status == "complete" and incomplete:
            raise ValueError("complete_result_cannot_hide_incomplete_sources")
        if self.status == "partial_coverage" and not incomplete:
            raise ValueError("partial_coverage_requires_incomplete_source")
        if self.status == "blocked" and self.result:
            raise ValueError("blocked_result_must_not_claim_results")
        if self.status == "failed" and not any(s.status == "failed" for s in self.sources):
            raise ValueError("failed_result_requires_failed_source")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "status": self.status,
            "sources": [
                {
                    "source": s.source,
                    "status": s.status,
                    "evidence_count": s.evidence_count,
                    "reason_code": s.reason_code,
                }
                for s in self.sources
            ],
            "result": dict(self.result),
        }
