from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from cyclothone.api.routes.agent_events import router as agent_events_router
from cyclothone.api.routes.agent_commands import router as agent_commands_router
from cyclothone.api.routes.agent_enrollment import router as agent_enrollment_router
from cyclothone.api.routes.device_enrollment_tokens import router as device_enrollment_tokens_router
from cyclothone.api.routes.developer import router as developer_router
from cyclothone.api.routes.bounty import router as bounty_router
from cyclothone.api.routes.twin import router as twin_router
from cyclothone.api.routes.knowledge import router as knowledge_router
from cyclothone.api.routes.workforce_ai import router as workforce_ai_router
from cyclothone.api.routes.control_plane import router as control_plane_router
from cyclothone.api.routes.customer_identity import router as customer_identity_router
from cyclothone.api.routes.response import router as response_router
from cyclothone.api.routes.agent_model import router as agent_model_router
from cyclothone.api.routes.ai_gateway import router as ai_gateway_router
from cyclothone.api.routes.auditor_portal import router as auditor_portal_router
from cyclothone.api.routes.compliance import router as compliance_router
from cyclothone.api.routes.compliance_lifecycle import router as compliance_lifecycle_router
from cyclothone.api.routes.console import router as console_router
from cyclothone.api.routes.data_trust import router as data_trust_router
from cyclothone.api.routes.data_trust_channels import router as data_trust_channels_router
from cyclothone.api.routes.deception import router as deception_router
from cyclothone.api.routes.darkweb import router as darkweb_router
from cyclothone.api.routes.hunts import router as hunts_router
from cyclothone.api.routes.investigation import router as investigation_router
from cyclothone.api.routes.trust_center import public_router as trust_center_public_router
from cyclothone.api.routes.trust_center import router as trust_center_router
from cyclothone.api.routes.trust import router as trust_router
from cyclothone.api.routes.trust_content import router as trust_content_router
from cyclothone.api.routes.trust_public import router as trust_public_router
from cyclothone.api.routes.trust_worker_health import router as trust_worker_health_router
from cyclothone.api.routes.vendor_risk import router as vendor_risk_router
from cyclothone.api.routes.web_intel import router as web_intel_router
from cyclothone.api.routes.brand import router as brand_router
from cyclothone.api.routes.federation import router as federation_router
from cyclothone.api.routes.physical import router as physical_router
from cyclothone.api.routes.chauliodus import router as chauliodus_router
from cyclothone.api.routes import gsma as gsma_routes
from cyclothone.api.routes import robotics as robotics_routes
from cyclothone.api.routes import lens as lens_routes
from cyclothone.api.routes import catalog as catalog_routes
from cyclothone.api.routes import banking_fapi as banking_fapi_routes
from cyclothone.compliance.scheduler import ComplianceScheduler
from cyclothone.darkweb.scheduler import DarkWebScheduler
from cyclothone.brand.scheduler import BrandScheduler
from cyclothone.federation.scheduler import FederationScheduler
from cyclothone.physical.scheduler import PhysicalScheduler
from cyclothone.routing.region_router import current_region_code,enforce_device_region,region_cache
from cyclothone.web.scheduler import WebIntelligenceScheduler
from cyclothone.trust.scheduler import TrustReevaluationScheduler

@asynccontextmanager
async def lifespan(application:FastAPI):
    region=current_region_code();await region_cache.load(force=True)
    if region_cache.get(region) is None:raise RuntimeError(f'CYCLOTHONE_REGION {region!r} is not present in the active region registry')
    compliance_scheduler=ComplianceScheduler();darkweb_scheduler=DarkWebScheduler();web_intelligence_scheduler=WebIntelligenceScheduler();brand_scheduler=BrandScheduler();federation_scheduler=FederationScheduler();physical_scheduler=PhysicalScheduler();trust_scheduler=TrustReevaluationScheduler()
    compliance_scheduler.start();darkweb_scheduler.start();web_intelligence_scheduler.start();brand_scheduler.start();federation_scheduler.start();physical_scheduler.start();trust_scheduler.start()
    application.state.compliance_scheduler=compliance_scheduler;application.state.darkweb_scheduler=darkweb_scheduler;application.state.web_intelligence_scheduler=web_intelligence_scheduler;application.state.brand_scheduler=brand_scheduler;application.state.federation_scheduler=federation_scheduler;application.state.physical_scheduler=physical_scheduler;application.state.trust_scheduler=trust_scheduler
    try:yield
    finally:
        await trust_scheduler.stop();await physical_scheduler.stop();await federation_scheduler.stop();await brand_scheduler.stop();await web_intelligence_scheduler.stop();await darkweb_scheduler.stop();await compliance_scheduler.stop()

def create_app()->FastAPI:
    application=FastAPI(title='Cyclothone API',version='0.1.0',lifespan=lifespan)
    @application.get('/health',include_in_schema=False)
    async def health():
        return {'status':'ok'}
    application.include_router(agent_enrollment_router,prefix='/api/v1')
    application.include_router(agent_model_router,prefix='/api/v1',dependencies=[Depends(enforce_device_region)])
    application.include_router(agent_events_router,prefix='/api/v1',dependencies=[Depends(enforce_device_region)])
    application.include_router(agent_commands_router,prefix='/api/v1',dependencies=[Depends(enforce_device_region)])
    application.include_router(investigation_router,prefix='/api/v1');application.include_router(deception_router,prefix='/api/v1');application.include_router(data_trust_router,prefix='/api/v1');application.include_router(data_trust_channels_router,prefix='/api/v1');application.include_router(ai_gateway_router,prefix='/api/v1',tags=['ai-security']);application.include_router(hunts_router,prefix='/api/v1',tags=['hunting']);application.include_router(compliance_router,prefix='/api/v1');application.include_router(compliance_lifecycle_router,prefix='/api/v1');application.include_router(auditor_portal_router,prefix='/api/v1');application.include_router(trust_center_router,prefix='/api/v1');application.include_router(trust_router,prefix='/api/v1');application.include_router(trust_content_router,prefix='/api/v1');application.include_router(trust_public_router,prefix='/api/v1');application.include_router(trust_worker_health_router,prefix='/api/v1');application.include_router(trust_center_public_router,prefix='/api/v1');application.include_router(vendor_risk_router,prefix='/api/v1');application.include_router(darkweb_router,prefix='/api/v1');application.include_router(web_intel_router,prefix='/api/v1');application.include_router(brand_router,prefix='/api/v1');application.include_router(federation_router,prefix='/api/v1');application.include_router(physical_router,prefix='/api/v1');application.include_router(chauliodus_router,prefix='/api/v1');application.include_router(gsma_routes.router,prefix='/api/v1/gsma',tags=['gsma']);application.include_router(robotics_routes.router,prefix='/api/v1/robotics',tags=['robotics']);application.include_router(lens_routes.router,prefix='/api/v1/lens',tags=['lens']);application.include_router(catalog_routes.router,prefix='/api/v1/catalog',tags=['catalog']);application.include_router(banking_fapi_routes.router,prefix='/api/v1/banking',tags=['banking-fapi']);application.include_router(console_router,prefix='/api/v1');application.include_router(response_router,prefix='/api/v1');application.include_router(device_enrollment_tokens_router,prefix='/api/v1');application.include_router(developer_router,prefix='/api/v1');application.include_router(bounty_router,prefix='/api/v1');application.include_router(twin_router,prefix='/api/v1');application.include_router(knowledge_router,prefix='/api/v1');application.include_router(workforce_ai_router,prefix='/api/v1');application.include_router(control_plane_router,prefix='/api/v1');application.include_router(customer_identity_router,prefix='/api/v1')
    return application

app=create_app()
