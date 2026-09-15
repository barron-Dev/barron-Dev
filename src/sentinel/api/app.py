from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from sentinel.api.routes.agent_events import router as agent_events_router
from sentinel.api.routes.agent_model import router as agent_model_router
from sentinel.routing.region_router import enforce_device_region, region_cache


@asynccontextmanager
async def lifespan(application: FastAPI):
    # A data plane must know its own region before accepting tenant traffic.
    # If the replicated region registry cannot be loaded, startup fails rather
    # than silently running with an unsafe residency configuration.
    await region_cache.load(force=True)
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="Sentinel API",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.include_router(
        agent_model_router,
        prefix="/api/v1",
        dependencies=[Depends(enforce_device_region)],
    )
    application.include_router(
        agent_events_router,
        prefix="/api/v1",
        dependencies=[Depends(enforce_device_region)],
    )
    return application


app = create_app()
