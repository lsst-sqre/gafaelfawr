"""Application definition for Gafaelfawr."""

from __future__ import annotations

import os
from importlib.metadata import version
from pathlib import Path

import structlog
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.logging import Profile, configure_logging, configure_uvicorn_logging
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel
from safir.slack.webhook import SlackRouteErrorHandler

from .constants import COOKIE_NAME
from .dependencies.config import config_dependency
from .dependencies.context import context_dependency
from .exceptions import (
    NotConfiguredError,
    PermissionDeniedError,
    ValidationError,
)
from .handlers import analyze, api, auth, index, login, logout, oidc
from .middleware.state import StateMiddleware
from .models.state import State

__all__ = ["create_app"]


def create_app(*, load_config: bool = True) -> FastAPI:
    """Create the FastAPI application.

    This is in a function rather than using a global variable (as is more
    typical for FastAPI) because some middleware depends on configuration
    settings and we therefore want to recreate the application between tests.

    Parameters
    ----------
    load_config
        If set to `False`, do not try to load the configuration.  Configure
        `~safir.middleware.x_forwarded.XForwardedMiddleware` with the default
        set of proxy IP addresses.  This is used primarily for OpenAPI
        schema generation, where constructing the app is required but the
        configuration won't matter.
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
                    "OpenID Connect routes used by protected services."
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
    app.include_router(login.router)
    app.include_router(logout.router)
    app.include_router(oidc.router)

    # Add static path serving to support the JavaScript UI.  This does not use
    # importlib.resources because the UI files are not shipped with the Python
    # package, but instead written to a specific location in the Docker image.
    # This will go away in the future when the Gafaelfawr UI is moved into a
    # pure UI package and is no longer distributed with and served from the
    # Python API webapp.
    static_path = os.getenv(
        "GAFAELFAWR_UI_PATH",
        Path(__file__).parent.parent.parent / "ui" / "public",
    )
    app.mount(
        "/auth/tokens",
        StaticFiles(directory=str(static_path), html=True, check_dir=False),
    )

    # Install the middleware.
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )
    if load_config:
        config = config_dependency.config()
        app.add_middleware(XForwardedMiddleware, proxies=config.proxies)
    else:
        app.add_middleware(XForwardedMiddleware)

    # Configure Slack alerts.
    if load_config and config.slack_webhook:
        logger = structlog.get_logger("gafaelfawr")
        SlackRouteErrorHandler.initialize(
            config.slack_webhook, "Gafaelfawr", logger
        )
        logger.debug("Initialized Slack webhook")

    # Register lifecycle handlers.
    app.on_event("startup")(startup_event)
    app.on_event("shutdown")(shutdown_event)

    # Register exception handlers.
    app.exception_handler(NotConfiguredError)(not_configured_handler)
    app.exception_handler(PermissionDeniedError)(permission_handler)
    app.exception_handler(ValidationError)(validation_handler)

    # Configure logging.
    if load_config:
        configure_logging(
            profile=Profile.production,
            log_level=config.loglevel,
            name="gafaelfawr",
            add_timestamp=True,
        )

    # Customize uvicorn logging to use the same structlog configuration as
    # main application logging.
    configure_uvicorn_logging()

    return app


async def startup_event() -> None:
    config = config_dependency.config()
    await context_dependency.initialize(config)
    await db_session_dependency.initialize(
        config.database_url, config.database_password
    )


async def shutdown_event() -> None:
    await http_client_dependency.aclose()
    await db_session_dependency.aclose()
    await context_dependency.aclose()


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
