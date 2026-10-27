""""Versioned, evidence-oriented result contracts for Cyclothone integrations.

These models define the API contract only. They do not claim that a session,
coverage receipt, signature, or collector execution exists until a runtime
implementation persists and verifies the corresponding records.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, root_validator


class ResultDisposition(str, Enum):
    EXPOSED = "exposed"
    NO_MATCH_IN_COMPLETED_SCOPE = "no_match_in_completed_scope"
    PARTIAL_COVERAGE = "partial_coverage"
    BLOCKED = "blocked"
    FAILED = "failed"


class TaskOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    NO_MATCH = "no_match"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    BLOCKED = "blocked"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


class IntegrityState(str, Enum):
    UNSIGNED = "unsigned"
    SIGNED = "signed"
    VERIFIED = "verified"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


class EvidenceProvenance(BaseModel):
    """Minimal provenance attached to a result's evidence reference."""

    evidence_id: str = Field(min_length=1, max_length=200)
    source_id: str = Field(min_length=1, max_length=128)
    source_reference: str | None = Field(default=None, max_length=2048)
    collected_at: datetime | None = None
    parser_version: str | None = Field(default=None, max_length=128)
    content_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    verification_state: VerificationState = VerificationState.UNVERIFIED


class ServiceTaskReceipt(BaseModel):
    """Recorded outcome for one service task within a result session."""

    task_id: str = Field(min_length=1, max_length=200)
    service_id: str = Field(min_length=1, max_length=128)
    outcome: TaskOutcome
    attempted_at: datetime | None = None
    completed_at: datetime | None = None
    lease_id: str | None = Field(default=None, max_length=200)
    source_attempt_count: int = Field(default=0, ge=0)
    evidence: list[EvidenceProvenance] = Field(default_factory=list)
    failure_code: str | None = Field(default=None, max_length=128)
    coverage_reason: str | None = Field(default=None, max_length=1000)


class CoverageReceipt(BaseModel):
    """Coverage summary; integrity must remain explicit until cryptographically verified."""

    schema_version: Literal["1.0"] = "1.0"
    receipt_id: str = Field(min_length=1, max_length=200)
    session_id: str = Field(min_length=1, max_length=200)
    asset_id: str = Field(min_length=1, max_length=200)
    issued_at: datetime
    coverage_until: datetime | None = None
    disposition: ResultDisposition
    tasks: list[ServiceTaskReceipt] = Field(default_factory=list)
    integrity_state: IntegrityState = IntegrityState.UNSIGNED
    signing_key_id: str | None = Field(default=None, max_length=200)
    signature: str | None = Field(default=None, max_length=4096)

    @root_validator(skip_on_failure=True)
    def signed_receipt_requires_signature_metadata(cls, values: dict) -> dict:
        state = values.get("integrity_state")
        signature = values.get("signature")
        key_id = values.get("signing_key_id")
        if state in {IntegrityState.SIGNED, IntegrityState.VERIFIED} and not (signature and key_id):
            raise ValueError("signed or verified receipts require signature and signing_key_id")
        if state == IntegrityState.UNSIGNED and (signature or key_id):
            raise ValueError("unsigned receipts cannot include signature metadata")
        return values


class ResultContract(BaseModel):
    """Stable top-level result envelope for API, SDK, and event delivery."""

    schema_version: Literal["1.0"] = "1.0"
    result_id: str = Field(min_length=1, max_length=200)
    session_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    asset_id: str = Field(min_length=1, max_length=200)
    generated_at: datetime
    disposition: ResultDisposition
    tasks: list[ServiceTaskReceipt] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    coverage_receipt_id: str = Field(min_length=1, max_length=200)
    integrity_state: IntegrityState = IntegrityState.UNSIGNED

    @root_validator(skip_on_failure=True)
    def prevent_false_clean_results(cls, values: dict) -> dict:
        disposition = values.get("disposition")
        tasks = values.get("tasks") or []
        finding_ids = values.get("finding_ids") or []

        if disposition == ResultDisposition.NO_MATCH_IN_COMPLETED_SCOPE:
            if not tasks:
                raise ValueError("no_match_in_completed_scope requires at least one task receipt")
            incomplete = [
                task.task_id
                for task in tasks
                if (
                    task.outcome not in {TaskOutcome.SUCCEEDED, TaskOutcome.NO_MATCH}
                    or task.attempted_at is None
                    or task.completed_at is None
                    or task.completed_at < task.attempted_at
                )
            ]
            if incomplete:
                raise ValueError(
                    "no_match_in_completed_scope requires every task to be attempted "
                    "and completed with valid timestamps; incomplete tasks: "
                    f"{', '.join(incomplete)}"
                )
            if finding_ids:
                raise ValueError("no_match_in_completed_scope cannot contain finding IDs")

        if disposition == ResultDisposition.EXPOSED and not finding_ids:
            raise ValueError("exposed disposition requires at least one finding ID")

        return values
