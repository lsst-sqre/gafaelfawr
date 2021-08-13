"""Application definition for Gafaelfawr."""

from __future__ import annotations

import os
from importlib.metadata import metadata
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi_sqlalchemy import DBSessionMiddleware
from safir.dependencies.http_client import http_client_dependency
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.exceptions import PermissionDeniedError, ValidationError
from gafaelfawr.handlers import (
    analyze,
    api,
    auth,
    index,
    influxdb,
    login,
    logout,
    oidc,
)
from gafaelfawr.middleware.state import StateMiddleware
from gafaelfawr.models.state import State

if TYPE_CHECKING:
    from fastapi import Request

__all__ = ["app"]


app = FastAPI(
    title="Gafaelfawr",
    description=(
        "Gafaelfawr is a FastAPI application for the authorization and"
        " management of tokens, including their issuance and revocation."
    ),
    version=metadata("gafaelfawr").get("Version", "0.0.0"),
    tags_metadata=[
        {
            "name": "user",
            "description": "APIs that can be used by regular users.",
        },
        {
            "name": "admin",
            "description": "APIs that can only be used by administrators.",
        },
        {
            "name": "oidc",
            "description": (
                "OpenID Connect routes used by protected applications."
            ),
        },
        {
            "name": "browser",
            "description": "Routes intended only for use from a web browser.",
        },
        {
            "name": "internal",
            "description": (
                "Internal routes used only by the ingress or by health checks."
            ),
        },
    ],
    openapi_url="/auth/openapi.json",
    docs_url="/auth/docs",
    redoc_url="/auth/redoc",
)

app.include_router(analyze.router)
app.include_router(
    api.router,
    prefix="/auth/api/v1",
    responses={
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied", "model": ErrorModel},
    },
)
app.include_router(auth.router)
app.include_router(index.router)
app.include_router(influxdb.router)
app.include_router(login.router)
app.include_router(logout.router)
app.include_router(oidc.router)

static_path = os.getenv(
    "GAFAELFAWR_UI_PATH", Path(__file__).parent.parent.parent / "ui" / "public"
)
app.mount(
    "/auth/tokens",
    StaticFiles(directory=str(static_path), html=True, check_dir=False),
)


@app.on_event("startup")
async def startup_event() -> None:
    config = await config_dependency()
    engine_args = {}
    if urlparse(config.database_url).scheme == "sqlite":
        engine_args["connect_args"] = {"check_same_thread": False}
    app.add_middleware(
        DBSessionMiddleware,
        db_url=config.database_url,
        engine_args=engine_args,
    )
    app.add_middleware(XForwardedMiddleware, proxies=config.proxies)
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await http_client_dependency.aclose()
    await redis_dependency.close()


@app.exception_handler(PermissionDeniedError)
async def permission_exception_handler(
    request: Request, exc: PermissionDeniedError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": [{"msg": str(exc), "type": "permission_denied"}]},
    )


@app.exception_handler(ValidationError)
async def validation_exception_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code, content={"detail": [exc.to_dict()]}
    )
