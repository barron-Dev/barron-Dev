from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from sentinel.api.routes.agent_events import router as agent_events_router
from sentinel.api.routes.agent_model import router as agent_model_router
from sentinel.api.routes.data_trust import router as data_trust_router
from sentinel.api.routes.data_trust_channels import router as data_trust_channels_router
from sentinel.api.routes.deception import router as deception_router
from sentinel.api.routes.investigation import router as investigation_router
from sentinel.routing.region_router import current_region_code, enforce_device_region, region_cache


@asynccontextmanager
async def lifespan(application: FastAPI):
    region = current_region_code()
    await region_cache.load(force=True)
    if region_cache.get(region) is None:
        raise RuntimeError(f"SENTINEL_REGION {region!r} is not present in the active region registry")
    yield


def create_app() -> FastAPI:
    application = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)
    application.include_router(agent_model_router, prefix="/api/v1", dependencies=[Depends(enforce_device_region)])
    application.include_router(agent_events_router, prefix="/api/v1", dependencies=[Depends(enforce_device_region)])
    application.include_router(investigation_router, prefix="/api/v1")
    application.include_router(deception_router, prefix="/api/v1")
    application.include_router(data_trust_router, prefix="/api/v1")
    application.include_router(data_trust_channels_router, prefix="/api/v1")
    return application


app = create_app()
