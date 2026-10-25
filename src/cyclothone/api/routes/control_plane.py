from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

import httpx

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.routing.region_router import current_region_code, region_cache
from cyclothone.scam.messages import MessageScamDetector, text_hash
from cyclothone.scam.voice import VoiceDeepfakeDetector

router = APIRouter(tags=["control-plane"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/platform/settings")
async def platform_settings(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    region = current_region_code()
    region_entry = region_cache.get(region)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "region": region,
        "region_registered": region_entry is not None,
        "residency": "strict",
        "api": {"version": "0.1.0", "health": "runtime"},
        "configuration": {
            "cyclothone_region": bool(os.getenv("CYCLOTHONE_REGION")),
            "supabase_url": bool(os.getenv("SUPABASE_URL")),
            "supabase_service_key": bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
        },
    }


@router.get("/assurance/recovery")
async def recovery_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "status": "configuration_required",
        "immutable_object_lock_required": True,
        "object_lock_mode": "COMPLIANCE",
        "verification": "SHA-256 before restore",
        "rpo_minutes": 15,
        "note": "Recovery restore is fail-closed until an immutable vault implementation is configured.",
    }


@router.get("/intelligence/scam")
async def scam_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "status": "ready",
        "detectors": {
            "message": {"available": True, "type": "deterministic_signal_generator"},
            "voice": {"available": True, "type": "acoustic_feature_heuristic"},
        },
        "verdicts": ["safe", "suspicious", "malicious"],
        "note": "Detectors emit signals; final policy decisions remain in the canonical security boundary.",
    }

class ScamMessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    sender: str | None = Field(default=None, max_length=64)


@router.post("/intelligence/scam/message")
async def analyze_scam_message(
    body: ScamMessageRequest,
    principal: DeveloperPrincipal = Depends(_principal),
) -> dict:
    try:
        result = MessageScamDetector().analyze(body.text, body.sender)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "tenant_id": principal.tenant_id,
        "input_sha256": text_hash(body.text),
        "score": result.score,
        "verdict": result.verdict,
        "category": result.category,
        "signals": result.signals,
        "urls": result.urls,
        "wallets": result.wallets,
        "raw_text_persisted": False,
    }


@router.post("/intelligence/scam/voice")
async def analyze_scam_voice(
    audio: UploadFile = File(...),
    principal: DeveloperPrincipal = Depends(_principal),
) -> dict:
    if audio.content_type not in {"audio/L16", "application/octet-stream", "audio/raw", "audio/pcm"}:
        raise HTTPException(status_code=415, detail="expected 16-bit PCM audio")
    data = await audio.read(10 * 1024 * 1024 + 1)
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="audio exceeds 10 MiB limit")
    if len(data) % 2:
        raise HTTPException(status_code=400, detail="PCM payload must contain 16-bit samples")
    try:
        result = VoiceDeepfakeDetector().analyze(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "tenant_id": principal.tenant_id,
        "input_bytes": len(data),
        "verdict": result.verdict,
        "score": result.score,
        "features": result.features,
        "reasons": result.reasons,
        "raw_audio_persisted": False,
    }


class EngineeringChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=12_000)


class EngineeringChatRequest(BaseModel):
    thread_id: UUID
    message: str = Field(min_length=1, max_length=12_000)
    history: list[EngineeringChatTurn] = Field(default_factory=list, max_length=20)


@router.post("/kontrol/engineering/chat")
async def engineering_chat(
    body: EngineeringChatRequest,
    principal: DeveloperPrincipal = Depends(_principal),
) -> dict:
    """Authenticated engineering chat; never imply tool access that is not wired."""
    if not principal.tenant_id:
        raise HTTPException(status_code=403, detail="workspace_not_admitted")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="engineering_ai_provider_not_configured")
    model = os.getenv("CYCLOTHONE_ENGINEERING_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.6-mini"
    system = (
        "You are Cyclothone Engineering AI, the engineering assistant for a zero-trust security platform. "
        "Help reason about code, architecture, tests, deployments, database migrations, security and incident diagnosis. "
        "Be direct and evidence-oriented. Never claim you inspected GitHub, Vercel, Supabase, Railway, logs, production data, "
        "or ran commands unless tool results are explicitly supplied in this conversation. This endpoint currently provides "
        "language-model conversation only; it has no direct infrastructure tools. Clearly state when live verification or a "
        "tool integration is needed. Never invent results, commits, deployments, migration readbacks, security findings or evidence. "
        "Do not treat AI output as authorization. Sensitive writes, production deployments, restarts, secrets and destructive actions "
        "require explicit human approval and a separately authenticated execution path."
    )
    messages = [{"role": "system", "content": system}]
    messages.extend({"role": turn.role, "content": turn.content} for turn in body.history[-20:])
    if not body.history or body.history[-1].role != "user" or body.history[-1].content != body.message:
        messages.append({"role": "user", "content": body.message})
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages, "temperature": 0.1},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="engineering_ai_provider_unavailable") from exc
    if response.status_code != 200:
        # Do not forward provider payloads or credentials to the client.
        raise HTTPException(status_code=502, detail="engineering_ai_generation_failed")
    try:
        payload = response.json()
        answer = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="engineering_ai_invalid_provider_response") from exc
    if not isinstance(answer, str) or not answer.strip():
        raise HTTPException(status_code=502, detail="engineering_ai_empty_response")
    return {
        "thread_id": str(body.thread_id),
        "answer": answer.strip(),
        "mode": "conversation_only",
        "infrastructure_tools_connected": False,
        "note": "Live infrastructure access and execution are not connected to this endpoint.",
    }
