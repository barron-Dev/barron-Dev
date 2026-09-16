from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from sentinel.api.routes.agent_events import router as agent_events_router
from sentinel.api.routes.agent_model import router as agent_model_router
from sentinel.api.routes.ai_gateway import router as ai_gateway_router
from sentinel.api.routes.auditor_portal import router as auditor_portal_router
from sentinel.api.routes.compliance import router as compliance_router
from sentinel.api.routes.compliance_lifecycle import router as compliance_lifecycle_router
from sentinel.api.routes.data_trust import router as data_trust_router
from sentinel.api.routes.data_trust_channels import router as data_trust_channels_router
from sentinel.api.routes.deception import router as deception_router
from sentinel.api.routes.hunts import router as hunts_router
from sentinel.api.routes.investigation import router as investigation_router
from sentinel.api.routes.trust_center import public_router as trust_center_public_router
from sentinel.api.routes.trust_center import router as trust_center_router
from sentinel.api.routes.vendor_risk import router as vendor_risk_router
from sentinel.compliance.scheduler import ComplianceScheduler
from sentinel.routing.region_router import current_region_code, enforce_device_region, region_cache


@asynccontextmanager
async def lifespan(application: FastAPI):
    region = current_region_code()
    await region_cache.load(force=True)
    if region_cache.get(region) is None:
        raise RuntimeError(f"SENTINEL_REGION {region!r} is not present in the active region registry")
    scheduler = ComplianceScheduler()
    scheduler.start()
    application.state.compliance_scheduler = scheduler
    try:
        yield
    finally:
        await scheduler.stop()


def create_app() -> FastAPI:
    application = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)
    application.include_router(agent_model_router, prefix="/api/v1", dependencies=[Depends(enforce_device_region)])
    application.include_router(agent_events_router, prefix="/api/v1", dependencies=[Depends(enforce_device_region)])
    application.include_router(investigation_router, prefix="/api/v1")
    application.include_router(deception_router, prefix="/api/v1")
    application.include_router(data_trust_router, prefix="/api/v1")
    application.include_router(data_trust_channels_router, prefix="/api/v1")
    application.include_router(ai_gateway_router, prefix="/api/v1", tags=["ai-security"])
    application.include_router(hunts_router, prefix="/api/v1", tags=["hunting"])
    application.include_router(compliance_router, prefix="/api/v1")
    application.include_router(compliance_lifecycle_router, prefix="/api/v1")
    application.include_router(auditor_portal_router, prefix="/api/v1")
    application.include_router(trust_center_router, prefix="/api/v1")
    application.include_router(trust_center_public_router, prefix="/api/v1")
    application.include_router(vendor_risk_router, prefix="/api/v1")
    return application


app = create_app()
