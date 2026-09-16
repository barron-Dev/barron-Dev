from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from sentinel.compliance.lifecycle import ComplianceLifecycle, ComplianceLifecycleError
from sentinel.developer.auth import DeveloperPrincipal, authenticate_request

router = APIRouter(prefix="/compliance", tags=["compliance-lifecycle"])
_lifecycle = ComplianceLifecycle()


class OwnerRequest(BaseModel):
    control_id: UUID
    user_id: UUID
    role: str = Field(default="owner", pattern="^(owner|backup|reviewer)$")


class ExceptionRequest(BaseModel):
    control_id: UUID
    reason: str = Field(min_length=1, max_length=10000)
    compensating: str | None = Field(default=None, max_length=10000)
    remediation_due: str | None = None


class ExceptionTransition(BaseModel):
    status: str = Field(pattern="^(open|remediating|resolved|accepted)$")
    approver: UUID | None = None


class RemediationRequest(BaseModel):
    control_id: UUID | None = None
    title: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=10000)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    assignee: UUID | None = None
    due_at: str | None = None


class RemediationTransition(BaseModel):
    status: str = Field(pattern="^(backlog|todo|in_progress|review|done)$")


def _tenant(principal: DeveloperPrincipal) -> UUID:
    return UUID(principal.tenant_id)


@router.get("/owners")
async def owners(control_id: UUID | None = Query(default=None), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    return await _lifecycle.list_owners(_tenant(principal), control_id)


@router.post("/owners", status_code=status.HTTP_201_CREATED)
async def assign_owner(body: OwnerRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:manage",))
    try:
        return await _lifecycle.assign_owner(_tenant(principal), body.control_id, body.user_id, body.role)
    except ComplianceLifecycleError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.get("/exceptions")
async def exceptions(control_id: UUID | None = Query(default=None), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    return await _lifecycle.list_exceptions(_tenant(principal), control_id)


@router.post("/exceptions", status_code=status.HTTP_201_CREATED)
async def create_exception(body: ExceptionRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:manage",))
    try:
        return await _lifecycle.create_exception(_tenant(principal), body.control_id, body.reason, body.compensating, body.remediation_due)
    except ComplianceLifecycleError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/exceptions/{exception_id}/transition")
async def transition_exception(exception_id: UUID, body: ExceptionTransition, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:manage",))
    try:
        return await _lifecycle.transition_exception(_tenant(principal), exception_id, body.status, body.approver)
    except ComplianceLifecycleError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.get("/remediation")
async def remediation(control_id: UUID | None = Query(default=None), principal: DeveloperPrincipal = Depends(authenticate_request)) -> list[dict]:
    principal.require(("compliance:read",))
    return await _lifecycle.list_remediation(_tenant(principal), control_id)


@router.post("/remediation", status_code=status.HTTP_201_CREATED)
async def create_remediation(body: RemediationRequest, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:manage",))
    try:
        return await _lifecycle.create_remediation(_tenant(principal), body.control_id, body.title, body.description, body.severity, body.assignee, body.due_at)
    except ComplianceLifecycleError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/remediation/{task_id}/transition")
async def transition_remediation(task_id: UUID, body: RemediationTransition, principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("compliance:manage",))
    try:
        return await _lifecycle.transition_remediation(_tenant(principal), task_id, body.status)
    except ComplianceLifecycleError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
