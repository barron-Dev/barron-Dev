from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.ai.injection import PromptInjectionDetector
from cyclothone.ai.model_router import ModelRouteRequest, ModelRoutingDenied, SupabaseModelRouter
from cyclothone.ai.tool_policy import ToolPolicyEngine
from cyclothone.ai.trust_graph import AgentTrustGraph
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/ai", tags=["ai-security"])
_injection = PromptInjectionDetector()
_tools = ToolPolicyEngine()
_graph = AgentTrustGraph()
_router = SupabaseModelRouter()

class PromptCheck(BaseModel):
    agent_id: UUID
    content: str = Field(min_length=1, max_length=1_000_000)
    direction: str = Field(default="in", pattern="^(in|out)$")
    trace_id: UUID | None = None
    store_preview: bool = False

class ToolCallCheck(BaseModel):
    agent_id: UUID
    tool_name: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    trace_id: UUID | None = None

class ToolResultCheck(BaseModel):
    agent_id: UUID
    tool_name: str = Field(min_length=1, max_length=128)
    result: str = Field(max_length=1_000_000)
    trace_id: UUID | None = None

class AgentCall(BaseModel):
    source_agent_id: UUID
    target_agent_id: UUID
    trace_id: UUID | None = None

class ModelRouteRequestBody(BaseModel):
    workload_layer: str = Field(min_length=1, max_length=64)
    risk_level: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    required_capabilities: list[str] = Field(default_factory=list, max_length=100)
    mission_id: str | None = Field(default=None, min_length=1, max_length=256)
    mission_version: int | None = Field(default=None, ge=1)
    mission_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    framework: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=500)
    declared_tools: list[str] = Field(default_factory=list, max_length=500)
    data_scopes: list[str] = Field(default_factory=list, max_length=100)
    trust_level: str = Field(default="untrusted", pattern="^(untrusted|limited|trusted|system)$")

async def _owned(tenant_id: UUID, agent_id: UUID) -> bool:
    return bool(await supabase.select_one("ai_agents", "id,status", id=str(agent_id), tenant_id=str(tenant_id)))

async def _log(
    tenant_id: UUID, agent_id: UUID, kind: str, content: str, risk: float,
    reasons: list, blocked: bool, tool_name: str | None, trace_id: UUID | None,
    store_preview: bool = False,
) -> int:
    if not await _owned(tenant_id, agent_id):
        raise HTTPException(404, "agent not found")
    row = {
        "tenant_id": str(tenant_id), "agent_id": str(agent_id),
        "trace_id": str(trace_id or uuid4()), "kind": kind, "tool_name": tool_name,
        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
        "content_preview": content[:500] if store_preview else None,
        "risk_score": min(max(float(risk), 0.0), 1.0), "risk_reasons": reasons, "blocked": blocked,
    }
    async def do():
        client = await supabase._ensure()
        return await client.table("agent_actions").insert(row).execute()
    resp = await supabase._retry(do)
    data = resp.data or []
    if not data:
        raise RuntimeError("agent action was not recorded")
    return int(data[0]["id"])

async def _incident(tenant_id: UUID, agent_id: UUID, action_id: int, category: str, severity: str, details: dict[str, Any]) -> None:
    async def do():
        client = await supabase._ensure()
        return await client.table("agent_incidents").insert({
            "tenant_id": str(tenant_id), "agent_id": str(agent_id), "trigger_action": action_id,
            "category": category, "severity": severity, "action_taken": "blocked", "details": details,
        }).execute()
    await supabase._retry(do)

@router.post("/route")
async def resolve_model_route(
    body: ModelRouteRequestBody,
    principal: DeveloperPrincipal = Depends(authenticate_request),
):
    principal.require(("ai:inspect",))
    if (body.mission_id is None) != (body.mission_version is None):
        raise HTTPException(400, "mission identity must be complete")
    try:
        route = await _router.resolve(
            ModelRouteRequest(
                tenant_id=UUID(principal.tenant_id),
                workload_layer=body.workload_layer,
                risk_level=body.risk_level,
                required_capabilities=tuple(body.required_capabilities),
                mission_id=body.mission_id,
                mission_version=body.mission_version,
                mission_hash=body.mission_hash,
            )
        )
    except ModelRoutingDenied as exc:
        raise HTTPException(409, str(exc)) from exc
    return {
        "route_id": str(route.route_id),
        "route_name": route.route_name,
        "workload_layer": route.workload_layer,
        "model_id": route.model_id,
        "model_version": route.model_version,
        "provider_id": route.provider_id,
        "priority": route.priority,
        "max_risk_level": route.max_risk_level,
        "capabilities": list(route.capabilities),
        "constraints": route.constraints,
        "tenant_specific": route.tenant_specific,
    }


@router.post("/check-prompt")
async def check_prompt(body: PromptCheck, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:inspect",))
    tenant = UUID(principal.tenant_id)
    verdict = _injection.detect(body.content)
    action_id = await _log(tenant, body.agent_id, "prompt_in" if body.direction == "in" else "prompt_out", body.content, verdict.score, verdict.signals, verdict.verdict == "malicious", None, body.trace_id, body.store_preview)
    if verdict.verdict == "malicious":
        await _record_injections(tenant, body.agent_id, action_id, verdict)
    return {"verdict": verdict.verdict, "score": verdict.score, "categories": verdict.categories, "signals": verdict.signals, "allow": verdict.verdict != "malicious", "action_id": action_id}

@router.post("/check-tool")
async def check_tool(body: ToolCallCheck, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:tool",))
    tenant = UUID(principal.tenant_id)
    result = await _tools.check(tenant, body.agent_id, body.tool_name, body.args)
    content = json.dumps(body.args, sort_keys=True, default=str)
    action_id = await _log(tenant, body.agent_id, "tool_call", content, float(result.get("score", 0)), result.get("signals", []), not result["allowed"], body.tool_name, body.trace_id)
    if not result["allowed"] and result.get("reason") == "malicious_tool_args":
        await _record_injections(tenant, body.agent_id, action_id, _injection.check_tool_call(body.tool_name, body.args))
    return {**result, "action_id": action_id}

@router.post("/check-tool-result")
async def check_tool_result(body: ToolResultCheck, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:inspect",))
    tenant = UUID(principal.tenant_id)
    verdict = _injection.detect(body.result)
    action_id = await _log(tenant, body.agent_id, "tool_result", body.result, verdict.score, verdict.signals, False, body.tool_name, body.trace_id)
    if verdict.verdict == "malicious":
        await _record_injections(tenant, body.agent_id, action_id, verdict, "indirect_injection")
    return {"verdict": verdict.verdict, "score": verdict.score, "categories": verdict.categories, "signals": verdict.signals, "sanitize": verdict.verdict == "malicious", "action_id": action_id}

@router.post("/agent-call")
async def agent_call(body: AgentCall, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:agent-call",))
    return await _graph.record_call(UUID(principal.tenant_id), body.source_agent_id, body.target_agent_id)

@router.post("/agents", status_code=201)
async def create_agent(body: AgentCreate, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:manage",))
    row = {"tenant_id": principal.tenant_id, "name": body.name, "framework": body.framework, "model": body.model, "description": body.description, "declared_tools": body.declared_tools, "data_scopes": body.data_scopes, "trust_level": body.trust_level}
    async def do():
        client = await supabase._ensure()
        return await client.table("ai_agents").insert(row).execute()
    resp = await supabase._retry(do)
    data = resp.data or []
    if not data: raise RuntimeError("agent was not created")
    return data[0]

@router.get("/agents")
async def list_agents(principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:inspect",))
    async def do():
        client = await supabase._ensure()
        return await client.table("ai_agents").select("*").eq("tenant_id", principal.tenant_id).order("created_at", desc=True).execute()
    resp = await supabase._retry(do)
    return list(resp.data or [])

@router.get("/incidents")
async def list_incidents(limit: int = 100, principal: DeveloperPrincipal = Depends(authenticate_request)):
    principal.require(("ai:inspect",))
    limit = min(max(limit, 1), 1000)
    async def do():
        client = await supabase._ensure()
        return await client.table("agent_incidents").select("*").eq("tenant_id", principal.tenant_id).order("created_at", desc=True).limit(limit).execute()
    resp = await supabase._retry(do)
    return list(resp.data or [])

async def _record_injections(tenant: UUID, agent: UUID, action_id: int, verdict, category_override: str | None = None) -> None:
    category = category_override or (verdict.categories[0] if verdict.categories else "instruction_override")
    allowed = {"instruction_override", "role_hijack", "system_prompt_leak", "tool_abuse", "data_exfil", "jailbreak", "context_poison", "indirect_injection", "prompt_leak", "encoding_evasion"}
    if category not in allowed: category = "instruction_override"
    severity = "critical" if verdict.score >= .9 else "high"
    await _incident(tenant, agent, action_id, category, severity, {"score": verdict.score, "signals": verdict.signals})
    async def do():
        client = await supabase._ensure()
        return await client.table("prompt_injections").insert({"tenant_id": str(tenant), "agent_id": str(agent), "action_id": action_id, "category": category, "severity": severity, "pattern": category, "snippet": (verdict.signals[0].get("snippet", "") if verdict.signals else "")[:500], "blocked": True}).execute()
    await supabase._retry(do)
