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
from sentinel.api.routes.darkweb import router as darkweb_router
from sentinel.api.routes.hunts import router as hunts_router
from sentinel.api.routes.investigation import router as investigation_router
from sentinel.api.routes.trust_center import public_router as trust_center_public_router
from sentinel.api.routes.trust_center import router as trust_center_router
from sentinel.api.routes.vendor_risk import router as vendor_risk_router
from sentinel.api.routes.web_intel import router as web_intel_router
from sentinel.api.routes.brand import router as brand_router
from sentinel.api.routes.federation import router as federation_router
from sentinel.compliance.scheduler import ComplianceScheduler
from sentinel.darkweb.scheduler import DarkWebScheduler
from sentinel.brand.scheduler import BrandScheduler
from sentinel.federation.scheduler import FederationScheduler
from sentinel.routing.region_router import current_region_code,enforce_device_region,region_cache
from sentinel.web.scheduler import WebIntelligenceScheduler


@asynccontextmanager
async def lifespan(application:FastAPI):
    region=current_region_code();await region_cache.load(force=True)
    if region_cache.get(region) is None:raise RuntimeError(f'SENTINEL_REGION {region!r} is not present in the active region registry')
    compliance_scheduler=ComplianceScheduler();darkweb_scheduler=DarkWebScheduler();web_intelligence_scheduler=WebIntelligenceScheduler();brand_scheduler=BrandScheduler();federation_scheduler=FederationScheduler()
    compliance_scheduler.start();darkweb_scheduler.start();web_intelligence_scheduler.start();brand_scheduler.start();federation_scheduler.start()
    application.state.compliance_scheduler=compliance_scheduler;application.state.darkweb_scheduler=darkweb_scheduler;application.state.web_intelligence_scheduler=web_intelligence_scheduler;application.state.brand_scheduler=brand_scheduler;application.state.federation_scheduler=federation_scheduler
    try:yield
    finally:
        await federation_scheduler.stop();await brand_scheduler.stop();await web_intelligence_scheduler.stop();await darkweb_scheduler.stop();await compliance_scheduler.stop()


def create_app()->FastAPI:
    application=FastAPI(title='Sentinel API',version='0.1.0',lifespan=lifespan)
    application.include_router(agent_model_router,prefix='/api/v1',dependencies=[Depends(enforce_device_region)]);application.include_router(agent_events_router,prefix='/api/v1',dependencies=[Depends(enforce_device_region)])
    application.include_router(investigation_router,prefix='/api/v1');application.include_router(deception_router,prefix='/api/v1');application.include_router(data_trust_router,prefix='/api/v1');application.include_router(data_trust_channels_router,prefix='/api/v1');application.include_router(ai_gateway_router,prefix='/api/v1',tags=['ai-security']);application.include_router(hunts_router,prefix='/api/v1',tags=['hunting']);application.include_router(compliance_router,prefix='/api/v1');application.include_router(compliance_lifecycle_router,prefix='/api/v1');application.include_router(auditor_portal_router,prefix='/api/v1');application.include_router(trust_center_router,prefix='/api/v1');application.include_router(trust_center_public_router,prefix='/api/v1');application.include_router(vendor_risk_router,prefix='/api/v1');application.include_router(darkweb_router,prefix='/api/v1');application.include_router(web_intel_router,prefix='/api/v1');application.include_router(brand_router,prefix='/api/v1');application.include_router(federation_router,prefix='/api/v1')
    return application


app=create_app()
