"""Application definition for Gafaelfawr."""

from __future__ import annotations

import os
from importlib.metadata import version
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel

from .constants import COOKIE_NAME
from .dependencies.cache import id_cache_dependency, token_cache_dependency
from .dependencies.config import config_dependency
from .dependencies.ldap import ldap_pool_dependency
from .dependencies.redis import redis_dependency
from .exceptions import (
    NotConfiguredError,
    PermissionDeniedError,
    ValidationError,
)
from .handlers import analyze, api, auth, index, influxdb, login, logout, oidc
from .middleware.state import StateMiddleware
from .models.state import State

__all__ = ["create_app"]


def create_app() -> FastAPI:
    """Create the FastAPI application.

    This is in a function rather than using a global variable (as is more
    typical for FastAPI) because some middleware depends on configuration
    settings and we therefore want to recreate the application between tests.
    """
    app = FastAPI(
        title="Gafaelfawr",
        description=(
            "Gafaelfawr is a FastAPI application for the authorization and"
            " management of tokens, including their issuance and revocation."
        ),
        version=version("gafaelfawr"),
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
                "description": "Routes intended for use from a web browser.",
            },
            {
                "name": "internal",
                "description": (
                    "Internal routes used by the ingress and health checks."
                ),
            },
        ],
        openapi_url="/auth/openapi.json",
        docs_url="/auth/docs",
        redoc_url="/auth/redoc",
    )

    # Add all of the routes.
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
        "GAFAELFAWR_UI_PATH",
        Path(__file__).parent.parent.parent / "ui" / "public",
    )
    app.mount(
        "/auth/tokens",
        StaticFiles(directory=str(static_path), html=True, check_dir=False),
    )

    # Install the middleware.
    config = config_dependency.config()
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )
    app.add_middleware(XForwardedMiddleware, proxies=config.proxies)

    # Register lifecycle handlers.
    app.on_event("startup")(startup_event)
    app.on_event("shutdown")(shutdown_event)

    # Register exception handlers.
    app.exception_handler(NotConfiguredError)(not_configured_handler)
    app.exception_handler(PermissionDeniedError)(permission_handler)
    app.exception_handler(ValidationError)(validation_handler)

    return app


async def startup_event() -> None:
    config = config_dependency.config()
    await db_session_dependency.initialize(
        config.database_url, config.database_password
    )


async def shutdown_event() -> None:
    await http_client_dependency.aclose()
    await db_session_dependency.aclose()
    await ldap_pool_dependency.aclose()
    await redis_dependency.aclose()
    await id_cache_dependency.aclose()
    await token_cache_dependency.aclose()


async def not_configured_handler(
    request: Request, exc: NotConfiguredError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": [{"type": "not_supported", "msg": str(exc)}]},
    )


async def permission_handler(
    request: Request, exc: PermissionDeniedError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": [{"msg": str(exc), "type": "permission_denied"}]},
    )


async def validation_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code, content={"detail": [exc.to_dict()]}
    )
