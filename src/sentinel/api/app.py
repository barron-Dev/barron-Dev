from __future__ import annotations

from fastapi import FastAPI

from sentinel.api.routes.agent_events import router as agent_events_router
from sentinel.api.routes.agent_model import router as agent_model_router


def create_app() -> FastAPI:
    application = FastAPI(title="Sentinel API", version="0.1.0")
    application.include_router(agent_model_router, prefix="/api/v1")
    application.include_router(agent_events_router, prefix="/api/v1")
    return application


app = create_app()
