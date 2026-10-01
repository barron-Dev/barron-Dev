from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from cyclothone.ai.envelope_issuer import AIEnvelopeIssuer
from cyclothone.ai.execution_gate import AgentExecutionGate, SupabaseReplayStore
from cyclothone.ai.mission_authority import SupabaseMissionAuthority
from cyclothone.ai.provider_binding import SupabaseProviderBinding
from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.response.dispatcher import SupabaseCommandDispatcher
from cyclothone.response.orchestrator import ResponseOrchestrator
from cyclothone.response.playbook_runtime import PlaybookRunner, SupabaseActionStore
from cyclothone.response.rollback import RollbackService
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/console/response", tags=["response"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


def _write(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:write",))
    return principal


class RunPlaybookRequest(BaseModel):
    case_id: UUID
    device_id: UUID | None = None
    dry_run: bool = False


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _runner() -> PlaybookRunner:
    dispatcher = SupabaseCommandDispatcher()
    envelope_issuer = AIEnvelopeIssuer(
        SupabaseProviderBinding(),
        SupabaseMissionAuthority(),
    )
    execution_gate = AgentExecutionGate(SupabaseReplayStore())
    orchestrator = ResponseOrchestrator(
        dispatcher,
        SupabaseActionStore(),
        execution_gate=execution_gate,
        envelope_issuer=envelope_issuer,
    )
    return PlaybookRunner(orchestrator)


@router.get("/playbooks")
async def list_playbooks(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    client = await supabase._ensure()
    response = await (
        client.table("playbooks")
        .select("id,name,description,enabled,trigger,steps,created_at,updated_at")
        .eq("tenant_id", principal.tenant_id)
        .order("updated_at", desc=True)
        .limit(100)
        .execute()
    )
    return {"items": list(response.data or [])}


@router.get("/runs")
async def list_runs(principal: DeveloperPrincipal = Depends(_read)) -> dict:
    client = await supabase._ensure()
    response = await (
        client.table("playbook_runs")
        .select("id,playbook_id,case_id,device_id,detection_id,status,current_step,log,started_at,ended_at")
        .eq("tenant_id", principal.tenant_id)
        .order("started_at", desc=True)
        .limit(100)
        .execute()
    )
    return {"items": list(response.data or [])}


@router.get("/cases/{case_id}/actions")
async def case_actions(case_id: UUID, principal: DeveloperPrincipal = Depends(_read)) -> dict:
    client = await supabase._ensure()
    response = await (
        client.table("case_actions")
        .select("*")
        .eq("tenant_id", principal.tenant_id)
        .eq("case_id", str(case_id))
        .order("created_at", desc=False)
        .limit(200)
        .execute()
    )
    return {"items": list(response.data or [])}


@router.post("/playbooks/{playbook_id}/runs")
async def run_playbook(
    playbook_id: UUID,
    body: RunPlaybookRequest,
    principal: DeveloperPrincipal = Depends(_write),
) -> dict:
    case = await supabase.select_one(
        "crime_cases", "id,tenant_id,device_id",
        id=str(body.case_id), tenant_id=principal.tenant_id,
    )
    if not case:
        raise HTTPException(404, {"error": "case_not_found"})

    playbook = await supabase.select_one(
        "playbooks", "id,tenant_id,enabled",
        id=str(playbook_id), tenant_id=principal.tenant_id,
    )
    if not playbook:
        raise HTTPException(404, {"error": "playbook_not_found"})
    if not playbook.get("enabled"):
        raise HTTPException(409, {"error": "playbook_disabled"})

    device_id = body.device_id or (UUID(str(case["device_id"])) if case.get("device_id") else None)
    try:
        return await _runner().run(
            tenant_id=UUID(principal.tenant_id),
            playbook_id=playbook_id,
            case_id=body.case_id,
            device_id=device_id,
            issued_by=f"console:{principal.app_id}",
            dry_run=body.dry_run,
        )
    except ValueError as exc:
        raise HTTPException(422, {"error": str(exc)}) from exc
    except Exception as exc:
        raise HTTPException(503, {"error": "playbook execution unavailable"}) from exc


@router.post("/actions/{case_action_id}/approve")
async def approve(case_action_id: UUID, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    row = await supabase.select_one(
        "case_actions", "id,tenant_id,status",
        id=str(case_action_id), tenant_id=principal.tenant_id,
    )
    if not row:
        raise HTTPException(404, {"error": "case_action_not_found"})
    try:
        dispatcher = SupabaseCommandDispatcher()
        envelope_issuer = AIEnvelopeIssuer(
            SupabaseProviderBinding(),
            SupabaseMissionAuthority(),
        )
        execution_gate = AgentExecutionGate(SupabaseReplayStore())
        orchestrator = ResponseOrchestrator(
            dispatcher,
            SupabaseActionStore(),
            execution_gate=execution_gate,
            envelope_issuer=envelope_issuer,
        )
        return await orchestrator.approve(case_action_id, UUID(principal.app_id))
    except RuntimeError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc
    except Exception as exc:
        raise HTTPException(503, {"error": "approval dispatch unavailable"}) from exc


@router.post("/actions/{case_action_id}/reject")
async def reject(case_action_id: UUID, body: RejectRequest, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    row = await supabase.select_one(
        "case_actions", "id,tenant_id,status",
        id=str(case_action_id), tenant_id=principal.tenant_id,
    )
    if not row:
        raise HTTPException(404, {"error": "case_action_not_found"})
    try:
        dispatcher = SupabaseCommandDispatcher()
        orchestrator = ResponseOrchestrator(dispatcher, SupabaseActionStore())
        return await orchestrator.reject(case_action_id, UUID(principal.app_id), body.reason)
    except RuntimeError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc


@router.post("/actions/{case_action_id}/rollback")
async def rollback(case_action_id: UUID, principal: DeveloperPrincipal = Depends(_write)) -> dict:
    row = await supabase.select_one(
        "case_actions", "id,tenant_id,status",
        id=str(case_action_id), tenant_id=principal.tenant_id,
    )
    if not row:
        raise HTTPException(404, {"error": "case_action_not_found"})
    try:
        service = RollbackService(SupabaseCommandDispatcher(), SupabaseActionStore())
        return await service.rollback(
            tenant_id=UUID(principal.tenant_id),
            case_action_id=case_action_id,
            actor=principal.app_id,
        )
    except ValueError as exc:
        raise HTTPException(422, {"error": str(exc)}) from exc
    except RuntimeError as exc:
        raise HTTPException(409, {"error": str(exc)}) from exc
    except Exception as exc:
        raise HTTPException(503, {"error": "rollback unavailable"}) from exc
