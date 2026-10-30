from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from cyclothone.compliance.effectiveness import EffectivenessReceipt
from cyclothone.storage.supabase_client import supabase


def receipt_to_row(receipt: EffectivenessReceipt) -> dict[str, Any]:
    """Convert an already-signed receipt to its immutable persistence form."""
    return {
        "tenant_id": receipt.tenant_id,
        "assessment_id": receipt.assessment_id,
        "control_id": receipt.control_id,
        "probe_id": receipt.probe_id,
        "probe_version": receipt.probe_version,
        "scope_digest": receipt.scope_digest,
        "input_digest": receipt.input_digest,
        "observations": receipt.signed_payload()["observations"],
        "expected_outcome": receipt.expected_outcome,
        "observed_outcome": receipt.observed_outcome,
        "status": receipt.status,
        "coverage": receipt.coverage,
        "evidence_digest": receipt.evidence_digest,
        "signer_key_id": receipt.signer_key_id,
        "signature_b64": receipt.signature_b64,
        "receipt_digest": receipt.receipt_digest,
        "issued_at": receipt.issued_at.isoformat(),
    }


async def persist_effectiveness_receipt(receipt: EffectivenessReceipt) -> dict[str, Any]:
    """Persist a signed receipt. Call only from a trusted, authorized probe runner."""
    async def _insert():
        return await (
            await supabase._ensure()
        ).table("compliance_effectiveness_receipts").insert(receipt_to_row(receipt)).execute()

    rows = (await supabase._retry(_insert, attempts=2)).data or []
    if not rows:
        raise RuntimeError("effectiveness_receipt_persistence_failed")
    return rows[0]


def receipt_from_row(row: dict[str, Any]) -> EffectivenessReceipt:
    issued_at = row["issued_at"]
    if isinstance(issued_at, str):
        issued_at = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    return EffectivenessReceipt(
        tenant_id=str(UUID(str(row["tenant_id"]))),
        assessment_id=str(UUID(str(row["assessment_id"]))),
        control_id=str(row["control_id"]),
        probe_id=str(row["probe_id"]),
        probe_version=str(row["probe_version"]),
        scope_digest=str(row["scope_digest"]),
        input_digest=str(row["input_digest"]),
        observations=dict(row["observations"]),
        expected_outcome=str(row["expected_outcome"]),
        observed_outcome=str(row["observed_outcome"]),
        status=row["status"],
        coverage=float(row["coverage"]),
        evidence_digest=str(row["evidence_digest"]),
        signer_key_id=str(row["signer_key_id"]),
        signature_b64=str(row["signature_b64"]),
        receipt_digest=str(row["receipt_digest"]),
        issued_at=issued_at,
    )


async def list_effectiveness_receipts(
    tenant_id: UUID,
    *,
    assessment_id: UUID | None = None,
    control_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    async def _select():
        query = (
            await supabase._ensure()
        ).table("compliance_effectiveness_receipts").select(
            "id,tenant_id,assessment_id,control_id,probe_id,probe_version,"
            "scope_digest,input_digest,observations,expected_outcome,observed_outcome,"
            "status,coverage,evidence_digest,signer_key_id,signature_b64,"
            "receipt_digest,issued_at,created_at"
        ).eq("tenant_id", str(tenant_id))
        if assessment_id is not None:
            query = query.eq("assessment_id", str(assessment_id))
        if control_id is not None:
            query = query.eq("control_id", control_id)
        return await query.order("issued_at", desc=True).limit(limit).execute()

    return list((await supabase._retry(_select, attempts=2)).data or [])


async def get_effectiveness_receipt(
    tenant_id: UUID, receipt_id: UUID
) -> dict[str, Any] | None:
    async def _select():
        return await (
            await supabase._ensure()
        ).table("compliance_effectiveness_receipts").select(
            "id,tenant_id,assessment_id,control_id,probe_id,probe_version,"
            "scope_digest,input_digest,observations,expected_outcome,observed_outcome,"
            "status,coverage,evidence_digest,signer_key_id,signature_b64,"
            "receipt_digest,issued_at,created_at"
        ).eq("tenant_id", str(tenant_id)).eq("id", str(receipt_id)).limit(1).execute()

    rows = (await supabase._retry(_select, attempts=2)).data or []
    return rows[0] if rows else None
