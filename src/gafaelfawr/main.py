"""Application definition for Gafaelfawr."""

from __future__ import annotations

from fastapi import FastAPI

from gafaelfawr.dependencies import redis
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.handlers import init_router, router
from gafaelfawr.middleware.state import StateMiddleware
from gafaelfawr.middleware.x_forwarded import XForwardedMiddleware

app = FastAPI()
init_router()
app.include_router(router)


@app.on_event("startup")
async def startup_event() -> None:
    config = config_dependency()
    app.add_middleware(XForwardedMiddleware, proxies=config.proxies)
    app.add_middleware(StateMiddleware)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await redis.close()
