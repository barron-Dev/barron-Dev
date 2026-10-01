from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from cyclothone.storage.supabase_client import supabase


class ModelRoutingDenied(RuntimeError):
    """Raised when no approved model/provider route can satisfy the workload."""


@dataclass(frozen=True, slots=True)
class ModelRouteRequest:
    tenant_id: UUID
    workload_layer: str
    risk_level: str
    required_capabilities: tuple[str, ...] = ()
    mission_id: str | None = None
    mission_version: int | None = None
    mission_hash: str | None = None


@dataclass(frozen=True, slots=True)
class ModelRoute:
    route_id: UUID
    route_name: str
    workload_layer: str
    model_id: str
    model_version: int
    provider_id: str
    priority: int
    max_risk_level: str
    capabilities: tuple[str, ...]
    constraints: dict[str, Any]
    tenant_specific: bool


class ModelRouteResolver(Protocol):
    async def resolve(self, request: ModelRouteRequest) -> ModelRoute: ...


class SupabaseModelRouter:
    """Resolve workload-layer routing without creating execution authority.

    The database route resolver chooses only an approved candidate. If mission
    identity is supplied, the resolver additionally requires an exact active
    execution binding for that model/provider. ai_start_run and the execution
    authority remain the final enforcement boundary.
    """

    async def resolve(self, request: ModelRouteRequest) -> ModelRoute:
        layer = request.workload_layer.strip().upper()
        risk = request.risk_level.strip().upper()
        if layer not in {
            "GENERAL",
            "CUSTOMER_OPERATIONS",
            "REASONING",
            "SECURITY",
            "WEB_RESEARCH",
            "THREAT_INTELLIGENCE",
            "DARK_WEB",
            "CRITICAL",
        }:
            raise ModelRoutingDenied("unsupported workload layer")
        if risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ModelRoutingDenied("unsupported risk level")
        if (request.mission_version is None) != (request.mission_id is None):
            raise ModelRoutingDenied("mission identity must be complete")
        if request.mission_id is not None and (
            not request.mission_hash
            or len(request.mission_hash) != 64
            or any(c not in "0123456789abcdef" for c in request.mission_hash)
        ):
            raise ModelRoutingDenied("invalid mission binding")

        async def do():
            client = await supabase._ensure()
            return await client.rpc(
                "ai_resolve_model_route",
                {
                    "p_tenant_id": str(request.tenant_id),
                    "p_workload_layer": layer,
                    "p_risk_level": risk,
                    "p_required_capabilities": list(request.required_capabilities),
                    "p_mission_id": request.mission_id,
                    "p_mission_version": request.mission_version,
                    "p_mission_hash": request.mission_hash,
                },
            ).execute()

        try:
            response = await supabase._retry(do, attempts=2)
        except Exception as exc:
            raise ModelRoutingDenied("model route resolution failed") from exc

        data = response.data
        if isinstance(data, list):
            data = data[0] if data else None
        if not isinstance(data, dict):
            raise ModelRoutingDenied("no approved model route available")

        try:
            return ModelRoute(
                route_id=UUID(str(data["route_id"])),
                route_name=str(data["route_name"]),
                workload_layer=str(data["workload_layer"]),
                model_id=str(data["model_id"]),
                model_version=int(data["model_version"]),
                provider_id=str(data["provider_id"]),
                priority=int(data["priority"]),
                max_risk_level=str(data["max_risk_level"]),
                capabilities=tuple(str(x) for x in (data.get("capabilities") or [])),
                constraints=dict(data.get("constraints") or {}),
                tenant_specific=bool(data.get("tenant_specific")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelRoutingDenied("invalid model route response") from exc
