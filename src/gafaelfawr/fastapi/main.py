"""Application definition for Gafaelfawr."""

from __future__ import annotations

from fastapi import FastAPI

from gafaelfawr.fastapi.dependencies import redis
from gafaelfawr.fastapi.handlers import init_router, router
from gafaelfawr.fastapi.middleware.state import StateMiddleware
from gafaelfawr.fastapi.middleware.x_forwarded import XForwardedMiddleware

app = FastAPI()
init_router()
app.include_router(router)
app.add_middleware(StateMiddleware)
app.add_middleware(XForwardedMiddleware)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await redis.close()
