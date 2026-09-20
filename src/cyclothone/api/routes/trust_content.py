from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _write(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:write",))
    return principal


class ContentVerificationRequest(BaseModel):
    content_base64: str = Field(min_length=1, max_length=12_000_000)
    verifier_type: str = Field(min_length=1, max_length=128)
    verifier_id: str = Field(min_length=1, max_length=256)
    verifier_version: str | None = Field(default=None, max_length=128)
    verification_method: str = Field(default="CONTROLLED_BYTES_SHA256", min_length=1, max_length=128)


@router.post("/evidence/{evidence_id}/verify-content")
def verify_content(
    evidence_id: str,
    body: ContentVerificationRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict[str, Any]:
    evidence = supabase.select_one(
        "trust_evidence",
        {"id": evidence_id, "tenant_id": principal.tenant_id},
    )
    if not evidence:
        raise HTTPException(status_code=404, detail="trust_evidence_not_found")

    try:
        raw = base64.b64decode(body.content_base64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_base64_content") from exc

    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="content_too_large")

    observed_hash = hashlib.sha256(raw).hexdigest()
    expected_hash = str(evidence.get("content_hash") or "").lower()
    if observed_hash != expected_hash:
        try:
            supabase.rpc(
                "trust_commit_evidence_content_verification",
                {
                    "p_evidence_id": evidence_id,
                    "p_verification_status": "FAILED",
                    "p_verifier_type": body.verifier_type,
                    "p_verifier_id": body.verifier_id,
                    "p_verifier_version": body.verifier_version,
                    "p_verification_method": body.verification_method,
                    "p_observed_content_hash": observed_hash,
                    "p_verified_at": datetime.now(timezone.utc).isoformat(),
                    "p_reason": "content_hash_mismatch",
                },
            )
        except Exception:
            pass
        raise HTTPException(status_code=400, detail="content_hash_mismatch")

    try:
        event = supabase.rpc(
            "trust_commit_evidence_content_verification",
            {
                "p_evidence_id": evidence_id,
                "p_verification_status": "VERIFIED",
                "p_verifier_type": body.verifier_type,
                "p_verifier_id": body.verifier_id,
                "p_verifier_version": body.verifier_version,
                "p_verification_method": body.verification_method,
                "p_observed_content_hash": observed_hash,
                "p_verified_at": datetime.now(timezone.utc).isoformat(),
                "p_reason": None,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail="content_verification_commit_failed") from exc

    return {
        "evidence_id": evidence_id,
        "status": "VERIFIED",
        "content_hash": observed_hash,
        "event": event,
    }


@router.get("/evidence/{evidence_id}/content-verification")
def get_content_verification(
    evidence_id: str,
    principal: DeveloperPrincipal = Depends(authenticate_request),
) -> dict[str, Any]:
    principal.require(("console:read",))
    evidence = supabase.select_one(
        "trust_evidence",
        {"id": evidence_id, "tenant_id": principal.tenant_id},
    )
    if not evidence:
        raise HTTPException(status_code=404, detail="trust_evidence_not_found")

    return {
        "evidence_id": evidence_id,
        "content_verification_status": evidence.get("content_verification_status"),
        "content_verification_method": evidence.get("content_verification_method"),
        "content_verified_payload_hash": evidence.get("content_verified_payload_hash"),
        "content_verification_hash": evidence.get("content_verification_hash"),
        "content_verified_at": evidence.get("content_verified_at"),
        "content_verification_failure_reason": evidence.get("content_verification_failure_reason"),
    }
