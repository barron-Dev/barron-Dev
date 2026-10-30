from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from cyclothone.api.routes.customer_identity import principal as customer_principal
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.global_integrity.crypto import (
    GlobalIntegrityError, canonical_json, context_hash, device_fingerprint,
    principal_fingerprint, public_key_fingerprint, sha256_hex, verify_ed25519,
)
from cyclothone.global_integrity.attestation_verifier import verify_verifier_assertion
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/global-integrity", tags=["global-execution-integrity"])
_SCHEMA = "cyclothone.global-execution.v1"


async def _principal(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> DeveloperPrincipal:
    try:
        return await authenticate_request(authorization=authorization, x_api_key=x_api_key)
    except HTTPException as exc:
        if exc.status_code != 401 or not authorization:
            raise
        return await customer_principal(authorization=authorization)


async def _global_principal(p: DeveloperPrincipal) -> tuple[str, str, str]:
    if not p.tenant_id:
        raise HTTPException(403, "tenant_identity_required")
    p.require(("console:read",))
    if p.auth_type == "customer":
        kind = "external_client"
        external = p.user_id
    elif p.user_id:
        kind = "developer"
        external = p.user_id
    else:
        kind = "system"
        external = p.app_id
    if not external:
        raise HTTPException(403, "canonical_principal_required")
    fingerprint = principal_fingerprint(p.tenant_id, kind, str(external))
    try:
        principal_id = await supabase.rpc(
            "global_resolve_principal",
            {"p_tenant_id": p.tenant_id, "p_principal_kind": kind, "p_subject_fingerprint": fingerprint},
        )
    except Exception as exc:
        raise HTTPException(503, "global_principal_resolution_unavailable") from exc
    if isinstance(principal_id, list):
        principal_id = principal_id[0] if principal_id else None
    if isinstance(principal_id, dict):
        principal_id = principal_id.get("global_resolve_principal") or principal_id.get("id")
    if not principal_id:
        raise HTTPException(503, "global_principal_resolution_failed")
    return str(principal_id), kind, fingerprint



async def _platform_device_id(p: DeveloperPrincipal, device_ref: str) -> str:
    try:
        canonical_id = str(UUID(device_ref))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "device_ref_must_be_an_enrolled_device_uuid") from exc
    try:
        row = await supabase.select_one(
            "devices", "id,status", id=canonical_id, tenant_id=p.tenant_id
        )
    except Exception as exc:
        raise HTTPException(503, "platform_device_registry_unavailable") from exc
    if not row or row.get("status") != "active":
        raise HTTPException(403, "platform_device_not_active_or_not_found")
    return canonical_id


def _challenge_payload(
    *, tenant_id: str, principal_id: str, device_fp: str, challenge_id: str,
    nonce: str, purpose: str, context: dict[str, Any], context_sha: str,
) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "device_fingerprint": device_fp,
        "challenge_id": challenge_id,
        "challenge_nonce": nonce,
        "purpose": purpose,
        "context_sha256": context_sha,
        "context": context,
    }


class ChallengeRequest(BaseModel):
    device_ref: str = Field(min_length=8, max_length=256)
    purpose: str
    context: dict[str, Any] = Field(default_factory=dict)


class DeviceAttestationRequest(BaseModel):
    device_ref: str = Field(min_length=8, max_length=256)
    platform: str
    attestation_format: str = "proof_of_possession"
    public_key_pem: str = Field(min_length=80, max_length=4096)
    signature_b64: str = Field(min_length=80, max_length=256)
    challenge_id: str
    challenge_nonce: str = Field(min_length=64, max_length=64)
    context: dict[str, Any]
    attestation_evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class ActionAuthorizationRequest(BaseModel):
    device_ref: str = Field(min_length=8, max_length=256)
    action_type: str = Field(min_length=2, max_length=120)
    action_payload: dict[str, Any]
    challenge_id: str
    challenge_nonce: str = Field(min_length=64, max_length=64)
    signature_b64: str = Field(min_length=80, max_length=256)


class SbomScanRequest(BaseModel):
    device_ref: str = Field(min_length=8, max_length=256)
    project_ref: str = Field(min_length=1, max_length=240)
    sbom: dict[str, Any]
    challenge_id: str
    challenge_nonce: str = Field(min_length=64, max_length=64)
    signature_b64: str = Field(min_length=80, max_length=256)


class BlastRadiusRequest(BaseModel):
    device_ref: str = Field(min_length=8, max_length=256)
    purl: str = Field(min_length=8, max_length=2048)
    version: str = Field(min_length=1, max_length=256)
    challenge_id: str
    challenge_nonce: str = Field(min_length=64, max_length=64)
    signature_b64: str = Field(min_length=80, max_length=256)


async def _consume(
    *, challenge_id: str, p: DeveloperPrincipal, principal_id: str, device_fp: str,
    purpose: str, context_sha: str, nonce: str,
) -> bool:
    try:
        result = await supabase.rpc(
            "global_consume_device_challenge",
            {
                "p_challenge_id": challenge_id, "p_tenant_id": p.tenant_id,
                "p_principal_id": principal_id, "p_device_fingerprint": device_fp,
                "p_purpose": purpose, "p_context_sha256": context_sha, "p_nonce": nonce,
            },
        )
        return result is True
    except Exception:
        return False


async def _receipt(
    *, p: DeveloperPrincipal, principal_id: str, device_id: str | None, challenge_id: str | None,
    action_type: str, payload_sha: str, signature_b64: str | None, decision: str, reason: str,
) -> None:
    row = {
        "tenant_id": p.tenant_id, "principal_id": principal_id, "device_id": device_id,
        "challenge_id": challenge_id, "action_type": action_type, "action_payload_sha256": payload_sha,
        "signature_sha256": sha256_hex(signature_b64.encode()) if signature_b64 else None,
        "decision": decision, "reason_code": reason,
    }
    try:
        await supabase.insert_one("global_execution_receipts", row)
    except Exception as exc:
        # A missing audit receipt is a hard failure, not a successful authorization.
        raise HTTPException(503, "execution_receipt_persistence_failed") from exc


@router.post("/challenges", status_code=201)
async def issue_challenge(body: ChallengeRequest, p: DeveloperPrincipal = Depends(_principal)):
    principal_id, _, _ = await _global_principal(p)
    if body.purpose not in {"device_attestation", "sensitive_action", "sbom_submission"}:
        raise HTTPException(422, "unsupported_challenge_purpose")
    platform_device_id = await _platform_device_id(p, body.device_ref)
    device_fp = device_fingerprint(p.tenant_id, platform_device_id)
    context_sha = context_hash(body.context)
    try:
        result = await supabase.rpc(
            "global_issue_device_challenge",
            {
                "p_tenant_id": p.tenant_id, "p_principal_id": principal_id,
                "p_device_fingerprint": device_fp, "p_purpose": body.purpose,
                "p_context_sha256": context_sha,
            },
        )
    except Exception as exc:
        raise HTTPException(503, "device_challenge_unavailable") from exc
    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict):
        raise HTTPException(503, "device_challenge_invalid_response")
    challenge_id = str(row.get("challenge_id") or "")
    nonce = str(row.get("challenge_nonce") or "")
    if not challenge_id or len(nonce) != 64:
        raise HTTPException(503, "device_challenge_invalid_response")
    payload = _challenge_payload(
        tenant_id=p.tenant_id, principal_id=principal_id, device_fp=device_fp,
        challenge_id=challenge_id, nonce=nonce, purpose=body.purpose,
        context=body.context, context_sha=context_sha,
    )
    return {"challenge_id": challenge_id, "nonce": nonce, "expires_at": row.get("expires_at"), "signing_payload": payload}


@router.post("/devices/attest", status_code=201)
async def attest_device(body: DeviceAttestationRequest, p: DeveloperPrincipal = Depends(_principal)):
    principal_id, _, _ = await _global_principal(p)
    platform_device_id = await _platform_device_id(p, body.device_ref)
    device_fp = device_fingerprint(p.tenant_id, platform_device_id)
    context_sha = context_hash(body.context)
    try:
        key_fp = public_key_fingerprint(body.public_key_pem)
        if body.context.get("public_key_fingerprint") != key_fp:
            raise GlobalIntegrityError("public key fingerprint does not match signed context")
        if body.context.get("platform") != body.platform or body.context.get("attestation_format") != body.attestation_format:
            raise GlobalIntegrityError("attestation context mismatch")
        if body.context.get("attestation_evidence_sha256") != body.attestation_evidence_sha256:
            raise GlobalIntegrityError("attestation evidence hash mismatch")
        # The server signs/validates the exact challenge envelope; the client cannot
        # promote its own device to VERIFIED by selecting an attestation_format.
        challenge = await supabase.select_one(
            "global_device_challenges", "id,nonce,expires_at,consumed_at,purpose,context_sha256",
            id=body.challenge_id, tenant_id=p.tenant_id, principal_id=principal_id,
            device_fingerprint=device_fp,
        )
        if not challenge or challenge.get("purpose") != "device_attestation" or challenge.get("context_sha256") != context_sha:
            raise HTTPException(403, "device_challenge_mismatch")
        if challenge.get("consumed_at") or datetime.fromisoformat(str(challenge["expires_at"]).replace("Z", "+00:00")) <= datetime.now(UTC):
            raise HTTPException(403, "device_challenge_expired_or_replayed")
        payload = _challenge_payload(
            tenant_id=p.tenant_id, principal_id=principal_id, device_fp=device_fp,
            challenge_id=body.challenge_id, nonce=body.challenge_nonce, purpose="device_attestation",
            context=body.context, context_sha=context_sha,
        )
        if challenge.get("nonce") != body.challenge_nonce or not verify_ed25519(body.public_key_pem, body.signature_b64, payload):
            raise HTTPException(403, "device_signature_invalid")
        if not await _consume(
            challenge_id=body.challenge_id, p=p, principal_id=principal_id, device_fp=device_fp,
            purpose="device_attestation", context_sha=context_sha, nonce=body.challenge_nonce,
        ):
            raise HTTPException(403, "device_challenge_replayed_or_expired")
        device_id = await supabase.rpc(
            "global_register_device_key",
            {
                "p_tenant_id": p.tenant_id, "p_principal_id": principal_id,
                "p_platform_device_id": platform_device_id,
                "p_device_fingerprint": device_fp, "p_public_key": body.public_key_pem,
                "p_platform": body.platform, "p_attestation_format": body.attestation_format,
                "p_attestation_evidence_sha256": body.attestation_evidence_sha256,
            },
        )
    except HTTPException:
        raise
    except GlobalIntegrityError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "device_attestation_registration_unavailable") from exc
    if isinstance(device_id, dict):
        device_id = device_id.get("global_register_device_key") or device_id.get("id")
    return {
        "device_id": str(device_id), "attestation_state": "UNVERIFIED",
        "assurance_level": "key_possession",
        "reason": "signature proves key possession only; trusted platform attestation is not yet verified",
    }


@router.post("/authorize")
async def authorize_action(body: ActionAuthorizationRequest, p: DeveloperPrincipal = Depends(_principal)):
    principal_id, _, _ = await _global_principal(p)
    platform_device_id = await _platform_device_id(p, body.device_ref)
    device_fp = device_fingerprint(p.tenant_id, platform_device_id)
    payload_sha = sha256_hex(canonical_json(body.action_payload))
    context = {"action_type": body.action_type, "action_payload_sha256": payload_sha}
    context_sha = context_hash(context)
    device = await supabase.select_one(
        "global_device_attestations", "id,platform_device_id,hardware_public_key,attestation_state,last_attested_at,valid_until",
        tenant_id=p.tenant_id, principal_id=principal_id, platform_device_id=platform_device_id, device_fingerprint=device_fp,
    )
    if not device:
        await _receipt(p=p, principal_id=principal_id, device_id=None, challenge_id=None,
                       action_type=body.action_type, payload_sha=payload_sha, signature_b64=body.signature_b64,
                       decision="BLOCKED", reason="device_not_registered")
        raise HTTPException(403, "device_not_registered")
    challenge = await supabase.select_one(
        "global_device_challenges", "id,nonce,expires_at,consumed_at,purpose,context_sha256",
        id=body.challenge_id, tenant_id=p.tenant_id, principal_id=principal_id, device_fingerprint=device_fp,
    )
    envelope = _challenge_payload(
        tenant_id=p.tenant_id, principal_id=principal_id, device_fp=device_fp,
        challenge_id=body.challenge_id, nonce=body.challenge_nonce, purpose="sensitive_action",
        context=context, context_sha=context_sha,
    )
    try:
        signature_ok = bool(challenge and challenge.get("nonce") == body.challenge_nonce
                            and challenge.get("purpose") == "sensitive_action"
                            and challenge.get("context_sha256") == context_sha
                            and verify_ed25519(device["hardware_public_key"], body.signature_b64, envelope))
    except GlobalIntegrityError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        gate_result = await supabase.rpc(
            "global_authorize_execution_atomic",
            {
                "p_tenant_id": p.tenant_id,
                "p_principal_id": principal_id,
                "p_device_id": str(device["id"]),
                "p_challenge_id": body.challenge_id,
                "p_device_fingerprint": device_fp,
                "p_context_sha256": context_sha,
                "p_nonce": body.challenge_nonce,
                "p_action_type": body.action_type,
                "p_payload_sha256": payload_sha,
                "p_signature_sha256": sha256_hex(body.signature_b64.encode()),
                "p_signature_valid": signature_ok,
            },
        )
    except Exception as exc:
        raise HTTPException(503, "atomic_execution_gate_unavailable") from exc
    gate_row = gate_result[0] if isinstance(gate_result, list) and gate_result else gate_result
    if not isinstance(gate_row, dict):
        raise HTTPException(503, "atomic_execution_gate_invalid_response")
    decision = str(gate_row.get("decision") or "")
    reason = str(gate_row.get("reason_code") or "atomic_execution_gate_denied")
    if decision != "AUTHORIZED":
        raise HTTPException(403, {"status": "blocked", "reason": reason})
    return {"status": "authorized", "receipt": "persisted", "action_payload_sha256": payload_sha}


def _component(component: dict[str, Any]) -> dict[str, Any]:
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:") or "@" not in purl:
        raise HTTPException(422, "every SBOM component must include a versioned package URL")
    base, version = purl.rsplit("@", 1)
    if not version or len(purl) > 2048:
        raise HTTPException(422, "invalid package URL")
    path = base[4:].split("/", 1)
    ecosystem = path[0].lower()
    name = path[-1].split("#", 1)[0]
    if not ecosystem or not name:
        raise HTTPException(422, "invalid package URL")
    digest = None
    for item in component.get("hashes") or []:
        if isinstance(item, dict) and str(item.get("alg", "")).upper() in {"SHA-256", "SHA256"}:
            value = str(item.get("content", "")).lower()
            if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                digest = value
                break
    return {"purl": purl, "version": version, "ecosystem": ecosystem, "name": name,
            "package_sha256": digest}


@router.post("/sbom/scan", status_code=201)
async def scan_sbom(body: SbomScanRequest, p: DeveloperPrincipal = Depends(_principal)):
    principal_id, _, _ = await _global_principal(p)
    platform_device_id = await _platform_device_id(p, body.device_ref)
    device_fp = device_fingerprint(p.tenant_id, platform_device_id)
    canonical_sbom = canonical_json(body.sbom)
    sbom_sha = sha256_hex(canonical_sbom)
    context = {"project_ref": body.project_ref, "sbom_sha256": sbom_sha}
    context_sha = context_hash(context)
    device = await supabase.select_one(
        "global_device_attestations", "id,platform_device_id,hardware_public_key,attestation_state,last_attested_at,valid_until",
        tenant_id=p.tenant_id, principal_id=principal_id, platform_device_id=platform_device_id, device_fingerprint=device_fp,
    )
    if not device or device.get("attestation_state") != "VERIFIED":
        raise HTTPException(403, "verified_hardware_attestation_required")
    try:
        attested = datetime.fromisoformat(str(device.get("last_attested_at")).replace("Z", "+00:00"))
        valid_until = device.get("valid_until")
        age_seconds = (datetime.now(UTC) - attested).total_seconds()
        if age_seconds < 0 or age_seconds > 300 or (valid_until and datetime.fromisoformat(str(valid_until).replace("Z", "+00:00")) <= datetime.now(UTC)):
            raise HTTPException(403, "hardware_attestation_stale")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(403, "hardware_attestation_stale") from exc
    challenge = await supabase.select_one(
        "global_device_challenges", "id,nonce,expires_at,consumed_at,purpose,context_sha256",
        id=body.challenge_id, tenant_id=p.tenant_id, principal_id=principal_id, device_fingerprint=device_fp,
    )
    envelope = _challenge_payload(
        tenant_id=p.tenant_id, principal_id=principal_id, device_fp=device_fp,
        challenge_id=body.challenge_id, nonce=body.challenge_nonce, purpose="sbom_submission",
        context=context, context_sha=context_sha,
    )
    if not challenge or challenge.get("nonce") != body.challenge_nonce or challenge.get("purpose") != "sbom_submission" or challenge.get("context_sha256") != context_sha:
        raise HTTPException(403, "sbom_challenge_mismatch")
    if not verify_ed25519(device["hardware_public_key"], body.signature_b64, envelope):
        raise HTTPException(403, "sbom_signature_invalid")
    if not await _consume(challenge_id=body.challenge_id, p=p, principal_id=principal_id, device_fp=device_fp,
                          purpose="sbom_submission", context_sha=context_sha, nonce=body.challenge_nonce):
        raise HTTPException(403, "sbom_challenge_replayed_or_expired")
    if body.sbom.get("bomFormat") != "CycloneDX" or not isinstance(body.sbom.get("specVersion"), str):
        raise HTTPException(422, "cyclonedx_sbom_required")
    components_raw = body.sbom.get("components") or []
    if not isinstance(components_raw, list) or len(components_raw) > 50000:
        raise HTTPException(422, "invalid_sbom_component_count")
    components = [_component(item) for item in components_raw if isinstance(item, dict)]
    if len(components) != len(components_raw):
        raise HTTPException(422, "invalid_sbom_component")
    intel_rows = []
    for item in components:
        try:
            response = await (await supabase._ensure()).table("global_package_intel").select(
                "status,evidence_sha256,valid_until"
            ).eq("purl", item["purl"]).eq("version", item["version"]).execute()
            rows = response.data or []
        except Exception as exc:
            raise HTTPException(503, "package_intelligence_unavailable") from exc
        valid = []
        for row in rows:
            until = row.get("valid_until")
            if not until or datetime.fromisoformat(str(until).replace("Z", "+00:00")) > datetime.now(UTC):
                valid.append(row)
        statuses = {r["status"] for r in valid}
        status = "malicious" if "malicious" in statuses else "compromised" if "compromised" in statuses else "suspicious" if "suspicious" in statuses else "unknown"
        evidence = next((r.get("evidence_sha256") for r in valid if r.get("status") in {"malicious","compromised","suspicious"}), None)
        intel_rows.append({**item, "intel_status": status, "intel_evidence_sha256": evidence})
    blocked = [x for x in intel_rows if x["intel_status"] in {"malicious","compromised"}]
    summary = {
        "malicious_or_compromised": len(blocked),
        "suspicious": sum(x["intel_status"] == "suspicious" for x in intel_rows),
        "unknown": sum(x["intel_status"] == "unknown" for x in intel_rows),
        "sources_checked": "configured_package_intel_records",
    }
    decision = "BLOCKED" if blocked else "REVIEW_REQUIRED"
    signature_sha = sha256_hex(body.signature_b64.encode())
    component_payload = [
        {
            "purl": x["purl"], "ecosystem": x["ecosystem"], "name": x["name"],
            "version": x["version"], "package_sha256": x["package_sha256"],
            "intel_status": x["intel_status"], "intel_evidence_sha256": x["intel_evidence_sha256"],
        }
        for x in intel_rows
    ]
    try:
        committed = await supabase.rpc(
            "global_commit_sbom_scan",
            {
                "p_tenant_id": p.tenant_id,
                "p_principal_id": principal_id,
                "p_device_id": device["id"],
                "p_project_ref": body.project_ref,
                "p_spec_version": body.sbom["specVersion"],
                "p_sbom_sha256": sbom_sha,
                "p_signature_sha256": signature_sha,
                "p_component_count": len(components),
                "p_gate_decision": decision,
                "p_scan_summary": summary,
                "p_components": component_payload,
            },
        )
        if isinstance(committed, list):
            committed = committed[0] if committed else None
        if isinstance(committed, dict):
            committed = committed.get("global_commit_sbom_scan") or committed.get("id")
        if not committed:
            raise RuntimeError("SBOM commit RPC returned no artifact id")
        artifact_id = str(committed)
    except Exception as exc:
        raise HTTPException(503, "sbom_atomic_evidence_commit_failed") from exc
    return {"status": "blocked" if blocked else "review_required", "gate_decision": decision,
            "artifact_id": artifact_id, "sbom_sha256": sbom_sha, "summary": summary,
            "affected_components": [{"purl": x["purl"], "version": x["version"], "status": x["intel_status"]} for x in intel_rows if x["intel_status"] != "unknown"]}


@router.post("/supply-chain/blast-radius")
async def tenant_blast_radius(body: BlastRadiusRequest, p: DeveloperPrincipal = Depends(_principal)):
    principal_id, _, _ = await _global_principal(p)
    platform_device_id = await _platform_device_id(p, body.device_ref)
    device_fp = device_fingerprint(p.tenant_id, platform_device_id)
    action_type = "supply_chain_blast_radius_read"
    action_payload = {"purl": body.purl, "version": body.version}
    payload_sha = sha256_hex(canonical_json(action_payload))
    context = {"action_type": action_type, "action_payload_sha256": payload_sha}
    context_sha = context_hash(context)
    device = await supabase.select_one(
        "global_device_attestations",
        "id,platform_device_id,hardware_public_key,attestation_state,last_attested_at,valid_until",
        tenant_id=p.tenant_id, principal_id=principal_id,
        platform_device_id=platform_device_id, device_fingerprint=device_fp,
    )
    if not device:
        await _receipt(p=p, principal_id=principal_id, device_id=None, challenge_id=None,
                       action_type=action_type, payload_sha=payload_sha, signature_b64=body.signature_b64,
                       decision="BLOCKED", reason="device_not_registered")
        raise HTTPException(403, "device_not_registered")
    challenge = await supabase.select_one(
        "global_device_challenges", "id,nonce,expires_at,consumed_at,purpose,context_sha256",
        id=body.challenge_id, tenant_id=p.tenant_id, principal_id=principal_id,
        device_fingerprint=device_fp,
    )
    envelope = _challenge_payload(
        tenant_id=p.tenant_id, principal_id=principal_id, device_fp=device_fp,
        challenge_id=body.challenge_id, nonce=body.challenge_nonce, purpose="sensitive_action",
        context=context, context_sha=context_sha,
    )
    try:
        signature_ok = bool(
            challenge
            and challenge.get("nonce") == body.challenge_nonce
            and challenge.get("purpose") == "sensitive_action"
            and challenge.get("context_sha256") == context_sha
            and verify_ed25519(device["hardware_public_key"], body.signature_b64, envelope)
        )
    except GlobalIntegrityError as exc:
        raise HTTPException(422, str(exc)) from exc
    consumed = await _consume(
        challenge_id=body.challenge_id, p=p, principal_id=principal_id, device_fp=device_fp,
        purpose="sensitive_action", context_sha=context_sha, nonce=body.challenge_nonce,
    ) if signature_ok else False
    fresh = False
    try:
        attested = datetime.fromisoformat(str(device.get("last_attested_at")).replace("Z", "+00:00"))
        age_seconds = (datetime.now(UTC) - attested).total_seconds()
        valid_until = device.get("valid_until")
        fresh = 0 <= age_seconds <= 300 and (
            not valid_until or datetime.fromisoformat(str(valid_until).replace("Z", "+00:00")) > datetime.now(UTC)
        )
    except Exception:
        fresh = False
    reason = (
        "signature_invalid_or_challenge_replayed" if not signature_ok or not consumed
        else "hardware_attestation_missing_or_stale"
        if device.get("attestation_state") != "VERIFIED" or not fresh
        else "authorized"
    )
    decision = "AUTHORIZED" if reason == "authorized" else "BLOCKED"
    await _receipt(
        p=p, principal_id=principal_id, device_id=str(device["id"]),
        challenge_id=(body.challenge_id if challenge else None), action_type=action_type,
        payload_sha=payload_sha, signature_b64=body.signature_b64,
        decision=decision, reason=reason,
    )
    if decision != "AUTHORIZED":
        raise HTTPException(403, {"status": "blocked", "reason": reason})
    try:
        response = await (await supabase._ensure()).table("global_sbom_components").select(
            "artifact_id,intel_status,purl,version"
        ).eq("tenant_id", p.tenant_id).eq("purl", body.purl).eq("version", body.version).execute()
        components = response.data or []
        ids = list({str(x["artifact_id"]) for x in components})
        artifacts = []
        if ids:
            result = await (await supabase._ensure()).table("global_sbom_artifacts").select(
                "id,project_ref,principal_id,created_at,gate_decision"
            ).eq("tenant_id", p.tenant_id).in_("id", ids).execute()
            artifacts = result.data or []
    except Exception as exc:
        raise HTTPException(503, "blast_radius_query_unavailable") from exc
    return {
        "purl": body.purl,
        "version": body.version,
        "tenant_scope": "current_tenant_only",
        "affected_projects": len(artifacts),
        "artifacts": artifacts,
        "evidence": components,
        "global_cross_tenant_graph": "not_exposed_to_tenant_api",
        "execution_receipt": "persisted",
    }



class VerifierAssertionRequest(BaseModel):
    assertion: dict[str, Any]
    signature_b64: str = Field(min_length=80, max_length=256)
\n\nclass DeviceRevocationRequest(BaseModel):
    device_id: UUID
    reason_code: str = Field(pattern=r"^[a-z0-9_]{3,80}$")
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


@router.post("/devices/revoke", status_code=202)
async def revoke_global_device(body: DeviceRevocationRequest, p: DeveloperPrincipal = Depends(_principal)):
    if not p.tenant_id:
        raise HTTPException(403, "tenant_identity_required")
    p.require(("global:device:revoke",))
    principal_id, _, _ = await _global_principal(p)
    actor_ref = p.user_id or p.app_id
    if not actor_ref:
        raise HTTPException(403, "canonical_revocation_actor_required")
    actor_fp = sha256_hex(f"cyclothone:device-revocation-actor:v1:{p.tenant_id}:{actor_ref}".encode())
    try:
        result = await supabase.rpc(
            "global_revoke_device",
            {
                "p_tenant_id": p.tenant_id,
                "p_principal_id": principal_id,
                "p_device_id": str(body.device_id),
                "p_actor_fingerprint_sha256": actor_fp,
                "p_reason_code": body.reason_code,
                "p_evidence_sha256": body.evidence_sha256,
            },
        )
    except Exception as exc:
        raise HTTPException(503, "device_revocation_unavailable") from exc
    event_id = result[0] if isinstance(result, list) and result else result
    if isinstance(event_id, dict):
        event_id = event_id.get("global_revoke_device") or event_id.get("id")
    if not event_id:
        raise HTTPException(503, "device_revocation_receipt_missing")
    return {"status": "revoked", "device_id": str(body.device_id), "trust_event_id": str(event_id),
            "effect": "all outstanding device challenges invalidated; future sensitive actions denied"}

@router.post("/devices/verify-attestation", status_code=200)
async def verify_device_attestation(body: VerifierAssertionRequest, p: DeveloperPrincipal = Depends(_principal)):
    if not p.tenant_id:
        raise HTTPException(403, "tenant_identity_required")
    p.require(("global:attestation:verify",))
    principal_id, _, _ = await _global_principal(p)
    assertion = body.assertion
    try:
        device_id = str(UUID(assertion.get("device_id", "")))
        verifier_key_id = str(UUID(assertion.get("verifier_key_id", "")))
        challenge_id = str(UUID(assertion.get("challenge_id", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "attestation_assertion_ids_invalid") from exc
    if assertion.get("tenant_id") != str(p.tenant_id) or assertion.get("principal_id") != principal_id:
        raise HTTPException(403, "attestation_assertion_identity_mismatch")
    try:
        device = await supabase.select_one(
            "global_device_attestations",
            "id,platform_device_id,device_fingerprint,hardware_public_key,platform,attestation_format,revoked_at",
            id=device_id, tenant_id=p.tenant_id, principal_id=principal_id,
        )
        if not device:
            raise HTTPException(404, "global_device_not_found")
        if device.get("revoked_at"):
            raise HTTPException(403, "device_revoked_requires_new_enrollment")
        device_key_fp = public_key_fingerprint(device["hardware_public_key"])
        if assertion.get("device_fingerprint") != device.get("device_fingerprint") or assertion.get("public_key_fingerprint") != device_key_fp:
            raise HTTPException(403, "attestation_device_key_binding_mismatch")
        if assertion.get("platform") != device.get("platform") or (device.get("attestation_format") != "proof_of_possession" and assertion.get("attestation_format") != device.get("attestation_format")):
            raise HTTPException(403, "attestation_platform_format_mismatch")
        challenge = await supabase.select_one(
            "global_device_challenges", "id,nonce,expires_at,consumed_at,purpose,context_sha256",
            id=challenge_id, tenant_id=p.tenant_id, principal_id=principal_id,
            device_fingerprint=device["device_fingerprint"],
        )
        if not challenge or challenge.get("purpose") != "device_attestation":
            raise HTTPException(403, "attestation_challenge_not_found")
        if challenge.get("consumed_at") or datetime.fromisoformat(str(challenge["expires_at"]).replace("Z", "+00:00")) <= datetime.now(UTC):
            raise HTTPException(403, "attestation_challenge_expired_or_replayed")
        if assertion.get("challenge_nonce") != challenge.get("nonce") or assertion.get("context_sha256") != challenge.get("context_sha256"):
            raise HTTPException(403, "attestation_challenge_binding_mismatch")
        verifier = await supabase.select_one(
            "global_attestation_verifier_keys",
            "id,public_key_pem,key_fingerprint_sha256,platform,policy_version,status,not_before,not_after",
            id=verifier_key_id,
        )
        if not verifier or verifier.get("status") != "ACTIVE":
            raise HTTPException(403, "attestation_verifier_not_trusted")
        if verifier.get("platform") != assertion.get("platform") or verifier.get("policy_version") != assertion.get("policy_version"):
            raise HTTPException(403, "attestation_verifier_policy_mismatch")
        assertion_sha, valid_until = verify_verifier_assertion(
            assertion, body.signature_b64, verifier["public_key_pem"]
        )
        verifier_fp = public_key_fingerprint(verifier["public_key_pem"])
        if verifier_fp != verifier.get("key_fingerprint_sha256"):
            raise HTTPException(503, "attestation_verifier_key_integrity_failure")
        result = await supabase.rpc(
            "global_promote_attested_device_atomic",
            {
                "p_tenant_id": p.tenant_id, "p_principal_id": principal_id,
                "p_device_id": device_id, "p_challenge_id": challenge_id,
                "p_device_fingerprint": device["device_fingerprint"],
                "p_context_sha256": challenge["context_sha256"], "p_nonce": challenge["nonce"],
                "p_verifier_key_id": verifier_key_id, "p_platform": assertion["platform"],
                "p_attestation_format": assertion["attestation_format"],
                "p_assurance_level": assertion["assurance_level"],
                "p_evidence_sha256": assertion["evidence_sha256"],
                "p_assertion_sha256": assertion_sha, "p_valid_until": valid_until,
                "p_policy_version": assertion["policy_version"],
            },
        )
    except HTTPException:
        raise
    except GlobalIntegrityError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "trusted_attestation_verification_unavailable") from exc
    row = result[0] if isinstance(result, list) and result else result
    if not isinstance(row, dict):
        raise HTTPException(503, "trusted_attestation_verifier_invalid_response")
    if row.get("decision") != "VERIFIED":
        raise HTTPException(403, {"status": "blocked", "reason": row.get("reason_code") or "attestation_denied"})
    return {
        "status": "verified", "device_id": device_id,
        "assurance_level": assertion["assurance_level"],
        "valid_until": valid_until, "decision_id": str(row.get("decision_id")),
        "evidence_sha256": assertion["evidence_sha256"],
    }
\n