"""Application definition for Gafaelfawr."""

from __future__ import annotations

import os
from importlib.metadata import metadata
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel

from .constants import COOKIE_NAME
from .dependencies.config import config_dependency
from .dependencies.redis import redis_dependency
from .dependencies.token_cache import token_cache_dependency
from .exceptions import (
    NotConfiguredException,
    PermissionDeniedError,
    ValidationError,
)
from .handlers import analyze, api, auth, index, influxdb, login, logout, oidc
from .middleware.state import StateMiddleware
from .models.state import State

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

# Add static path serving to support the JavaScript UI.
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
    await db_session_dependency.initialize(
        config.database_url, config.database_password
    )

    # This middleware unfortunately depends on the configuration, which is not
    # available until application start.  This means that any tests need to
    # clear the middleware stack during shutdown or multiple copies of this
    # middleware will stack up and make the tests unnecessarily slow.
    #
    # That in turn means that we have to add the StateMiddleware here as well,
    # even though it could be added unconditionally during import, since
    # otherwise it is cleared along with XForwardedMiddleware and then not
    # reinstated.
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )
    app.add_middleware(XForwardedMiddleware, proxies=config.proxies)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await http_client_dependency.aclose()
    await db_session_dependency.aclose()
    await redis_dependency.aclose()
    await token_cache_dependency.aclose()


@app.exception_handler(NotConfiguredException)
async def not_configured_exception_handler(
    request: Request, exc: NotConfiguredException
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": [{"type": "not_supported", "msg": str(exc)}]},
    )


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
