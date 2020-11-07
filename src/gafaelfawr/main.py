"""Application definition for Gafaelfawr."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from fastapi_sqlalchemy import DBSessionMiddleware

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.handlers import (
    analyze,
    api,
    auth,
    index,
    influxdb,
    login,
    logout,
    oidc,
    userinfo,
    well_known,
)
from gafaelfawr.middleware.state import StateMiddleware
from gafaelfawr.middleware.x_forwarded import XForwardedMiddleware
from gafaelfawr.models.state import State

if TYPE_CHECKING:
    from fastapi import Request

__all__ = ["app"]


app = FastAPI()
"""The Gafaelfawr application."""

app.include_router(analyze.router)
app.include_router(api.router, prefix="/auth/api/v1")
app.include_router(auth.router)
app.include_router(index.router)
app.include_router(influxdb.router)
app.include_router(login.router)
app.include_router(logout.router)
app.include_router(oidc.router)
app.include_router(userinfo.router)
app.include_router(well_known.router)


@app.on_event("startup")
async def startup_event() -> None:
    config = config_dependency()
    app.add_middleware(
        DBSessionMiddleware,
        db_url=config.database_url,
        engine_args={"connect_args": {"check_same_thread": False}},
    )
    app.add_middleware(XForwardedMiddleware, proxies=config.proxies)
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await redis_dependency.close()


@app.exception_handler(PermissionDeniedError)
async def permission_exception_handler(
    request: Request, exc: PermissionDeniedError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": {"msg": str(exc), "type": "permission_denied"}},
    )
