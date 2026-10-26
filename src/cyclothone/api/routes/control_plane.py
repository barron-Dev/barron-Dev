from __future__ import annotations

import json
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


def _engineering_tool_specs() -> list[dict]:
    return [
        {"type": "function", "function": {"name": "get_integration_configuration", "description": "Check whether read-only credentials are configured for the engineering integrations. Never return secret values.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
        {"type": "function", "function": {"name": "get_github_repository", "description": "Read the configured Cyclothone GitHub repository metadata and latest push time.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
        {"type": "function", "function": {"name": "get_github_pull_requests", "description": "List up to ten currently open pull requests in the configured Cyclothone repository.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
        {"type": "function", "function": {"name": "get_vercel_deployments", "description": "Read the five latest deployments for the configured Vercel project.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
        {"type": "function", "function": {"name": "get_supabase_api_health", "description": "Perform a read-only Supabase REST API reachability check. Do not query or return application records.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
        {"type": "function", "function": {"name": "get_railway_projects", "description": "Read the names and IDs of Railway projects available to the configured Railway API token.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
    ]


def _integration_configuration() -> dict:
    return {
        "github": bool(os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")),
        "vercel": bool(os.getenv("VERCEL_TOKEN") and (os.getenv("VERCEL_PROJECT_ID") or os.getenv("CYCLOTHONE_VERCEL_PROJECT_ID"))),
        "supabase": bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
        "railway": bool(os.getenv("RAILWAY_API_TOKEN") or os.getenv("RAILWAY_TOKEN")),
    }


async def _run_engineering_tool(name: str) -> dict:
    timeout = httpx.Timeout(15.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        if name == "get_integration_configuration":
            configured = _integration_configuration()
            return {"configured": configured, "note": "Credential presence only; this is not a successful connectivity check."}

        if name in {"get_github_repository", "get_github_pull_requests"}:
            token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
            if not token:
                return {"available": False, "reason": "github_token_not_configured"}
            repo = os.getenv("CYCLOTHONE_GITHUB_REPO", "barron-Dev/barron-Dev")
            endpoint = f"https://api.github.com/repos/{repo}"
            if name == "get_github_pull_requests":
                endpoint += "/pulls?state=open&per_page=10"
            response = await client.get(endpoint, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
            if response.status_code != 200:
                return {"available": False, "http_status": response.status_code, "reason": "github_read_failed"}
            data = response.json()
            if name == "get_github_repository":
                return {"available": True, "repository": data.get("full_name"), "default_branch": data.get("default_branch"), "pushed_at": data.get("pushed_at"), "private": data.get("private")}
            return {"available": True, "pull_requests": [{"number": pr.get("number"), "title": pr.get("title"), "state": pr.get("state"), "draft": pr.get("draft"), "head": (pr.get("head") or {}).get("ref"), "updated_at": pr.get("updated_at"), "url": pr.get("html_url")} for pr in data]}

        if name == "get_vercel_deployments":
            token = os.getenv("VERCEL_TOKEN")
            project = os.getenv("VERCEL_PROJECT_ID") or os.getenv("CYCLOTHONE_VERCEL_PROJECT_ID")
            if not token or not project:
                return {"available": False, "reason": "vercel_token_or_project_id_not_configured"}
            response = await client.get("https://api.vercel.com/v6/deployments", params={"projectId": project, "limit": "5"}, headers={"Authorization": f"Bearer {token}"})
            if response.status_code != 200:
                return {"available": False, "http_status": response.status_code, "reason": "vercel_read_failed"}
            data = response.json()
            return {"available": True, "deployments": [{"id": item.get("uid") or item.get("id"), "url": item.get("url"), "state": item.get("state"), "target": item.get("target"), "created": item.get("created"), "meta": {"gitCommitRef": (item.get("meta") or {}).get("githubCommitRef"), "gitCommitSha": (item.get("meta") or {}).get("githubCommitSha"), "gitCommitMessage": (item.get("meta") or {}).get("githubCommitMessage")}} for item in data.get("deployments", [])]}

        if name == "get_supabase_api_health":
            url = (os.getenv("SUPABASE_URL") or "").rstrip("/")
            key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
            if not url or not key:
                return {"available": False, "reason": "supabase_url_or_service_key_not_configured"}
            response = await client.get(url + "/rest/v1/", headers={"apikey": key, "Authorization": f"Bearer {key}"})
            return {"available": response.status_code == 200, "http_status": response.status_code, "reachable": response.status_code not in {502, 503, 504}, "note": "REST endpoint reachability only; no schema, migration or row state was inspected."}

        if name == "get_railway_projects":
            token = os.getenv("RAILWAY_API_TOKEN") or os.getenv("RAILWAY_TOKEN")
            if not token:
                return {"available": False, "reason": "railway_token_not_configured"}
            response = await client.post("https://backboard.railway.app/graphql/v2", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json={"query": "query EngineeringAIProjects { me { projects { edges { node { id name } } } } }"})
            if response.status_code != 200:
                return {"available": False, "http_status": response.status_code, "reason": "railway_read_failed"}
            payload = response.json()
            if payload.get("errors"):
                return {"available": False, "reason": "railway_query_failed", "details": payload["errors"][:2]}
            edges = (((payload.get("data") or {}).get("me") or {}).get("projects") or {}).get("edges") or []
            return {"available": True, "projects": [{"id": (edge.get("node") or {}).get("id"), "name": (edge.get("node") or {}).get("name")} for edge in edges]}

    return {"available": False, "reason": "unknown_or_disallowed_tool"}


@router.post("/kontrol/engineering/chat")
async def engineering_chat(
    body: EngineeringChatRequest,
    principal: DeveloperPrincipal = Depends(_principal),
) -> dict:
    """Authenticated engineering chat with a bounded read-only infrastructure toolset."""
    if not principal.tenant_id:
        raise HTTPException(status_code=403, detail="workspace_not_admitted")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="engineering_ai_provider_not_configured")
    model = os.getenv("CYCLOTHONE_ENGINEERING_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.6-mini"
    system = (
        "You are Cyclothone Engineering AI, the engineering assistant for a zero-trust security platform. "
        "Use available read-only tools when live infrastructure facts are requested. Report tool failures and missing credentials honestly; "
        "credential presence is not proof of connectivity. Never claim a repository, deployment, database schema, migration, worker, log, "
        "or production state was inspected unless a tool result explicitly supports it. The Supabase tool checks API reachability only, not "
        "schema or data. The Railway tool lists projects only, not service/deployment health. Never invent commits, deployments, findings, "
        "test results or evidence. This endpoint exposes read-only tools only: it cannot change code, merge PRs, modify databases, deploy, "
        "restart services, or change secrets. Sensitive writes require explicit approval and a separately authenticated execution path. "
        "Cite the specific tool result in prose and distinguish verified, blocked, and unverified facts."
    )
    messages: list[dict] = [{"role": "system", "content": system}]
    messages.extend({"role": turn.role, "content": turn.content} for turn in body.history[-20:])
    if not body.history or body.history[-1].role != "user" or body.history[-1].content != body.message:
        messages.append({"role": "user", "content": body.message})
    used: list[str] = []
    connected_tools: list[str] = []
    tools = _engineering_tool_specs()
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            for _ in range(5):
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={"model": model, "messages": messages, "tools": tools, "tool_choice": "auto", "temperature": 0.1},
                )
                if response.status_code != 200:
                    raise HTTPException(status_code=502, detail="engineering_ai_generation_failed")
                payload = response.json()
                choice = (payload.get("choices") or [{}])[0].get("message") or {}
                tool_calls = choice.get("tool_calls") or []
                if not tool_calls:
                    answer = choice.get("content")
                    if not isinstance(answer, str) or not answer.strip():
                        raise HTTPException(status_code=502, detail="engineering_ai_empty_response")
                    return {
                        "thread_id": str(body.thread_id),
                        "answer": answer.strip(),
                        "mode": "read_only_tools",
                        "tools_used": used,
                        "infrastructure_tools_connected": bool(connected_tools),
                        "connected_tools": connected_tools,
                        "note": "Only the explicitly listed read-only tool calls are available; no write or execution tools are exposed.",
                    }
                messages.append({"role": "assistant", "content": choice.get("content"), "tool_calls": tool_calls})
                for call in tool_calls:
                    function = call.get("function") or {}
                    name = function.get("name") or ""
                    if name not in {"get_integration_configuration", "get_github_repository", "get_github_pull_requests", "get_vercel_deployments", "get_supabase_api_health", "get_railway_projects"}:
                        result = {"available": False, "reason": "tool_not_allowed"}
                    else:
                        try:
                            result = await _run_engineering_tool(name)
                        except httpx.HTTPError:
                            result = {"available": False, "reason": f"{name}_network_error"}
                        except (ValueError, TypeError):
                            result = {"available": False, "reason": f"{name}_invalid_response"}
                    used.append(name)
                    if name != "get_integration_configuration" and result.get("available") is True:
                        connected_tools.append(name)
                    messages.append({"role": "tool", "tool_call_id": call.get("id"), "content": json.dumps(result, separators=(",", ":"))})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="engineering_ai_provider_unavailable") from exc
    raise HTTPException(status_code=502, detail="engineering_ai_tool_turn_limit")
