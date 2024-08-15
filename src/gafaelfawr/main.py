"""Application definition for Gafaelfawr."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from importlib.metadata import version
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from opentelemetry.sdk.metrics.export import MetricReader
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.fastapi import ClientRequestError, client_request_error_handler
from safir.logging import configure_uvicorn_logging
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel
from safir.slack.webhook import SlackRouteErrorHandler

from .constants import COOKIE_NAME
from .database import is_database_current
from .dependencies.config import config_dependency
from .dependencies.context import context_dependency
from .exceptions import DatabaseSchemaError
from .handlers import api, auth, cadc, internal, login, logout, oidc
from .middleware.state import StateMiddleware
from .models.state import State

__all__ = ["create_app"]


def create_app(
    *,
    load_config: bool = True,
    extra_startup: Coroutine[None, None, None] | None = None,
    metric_reader: MetricReader | None = None,
    validate_schema: bool = True,
) -> FastAPI:
    """Create the FastAPI application.

    This is in a function rather than using a global variable (as is more
    typical for FastAPI) because some middleware depends on configuration
    settings and we therefore want to recreate the application between tests.

    Parameters
    ----------
    load_config
        If set to `False`, do not try to load the configuration. Configure
        `~safir.middleware.x_forwarded.XForwardedMiddleware` with the default
        set of proxy IP addresses. This is used primarily for OpenAPI
        schema generation, where constructing the app is required but the
        configuration won't matter.
    extra_startup
        If provided, an additional coroutine to run as part of the startup
        section of the lifespan context manager, used by the test suite.
    metric_reader
        Override the metric reader with the provided object. This is used by
        the test suite to store metrics in memory where they can be queried
        and checked.
    validate_schema
        If set to `True`, verify, with Alembic, that the schema is up to date
        and raise `~gafaelfawr.exceptions.DatabaseSchemaError` if it is not.

    Raises
    ------
    DatabaseSchemaError
        Raised if schema validation was requested and the current schema is
        out of date.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        config = config_dependency.config()
        if validate_schema:
            logger = structlog.get_logger("gafaelfawr")
            if not await is_database_current(config, logger):
                raise DatabaseSchemaError("Database schema out of date")
        await context_dependency.initialize(config, metric_reader)
        await db_session_dependency.initialize(
            str(config.database_url), config.database_password
        )
        if extra_startup:
            await extra_startup

        yield

        await http_client_dependency.aclose()
        await db_session_dependency.aclose()
        await context_dependency.aclose()

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
        lifespan=lifespan,
    )

    # Add all of the routes.
    app.include_router(
        api.router,
        responses={
            401: {"description": "Unauthenticated"},
            403: {"description": "Permission denied", "model": ErrorModel},
        },
    )
    app.include_router(auth.router)
    app.include_router(cadc.router)
    app.include_router(internal.router)
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
        str(Path(__file__).parent.parent.parent / "ui" / "public"),
    )
    app.mount(
        "/auth/tokens",
        StaticFiles(directory=static_path, html=True, check_dir=False),
    )

    # Load configuration if it is available to us and configure Uvicorn
    # logging.
    config = None
    if load_config:
        config = config_dependency.config()
        configure_uvicorn_logging()

    # Install the middleware.
    app.add_middleware(
        StateMiddleware, cookie_name=COOKIE_NAME, state_class=State
    )
    if config:
        app.add_middleware(XForwardedMiddleware, proxies=config.proxies)
    else:
        app.add_middleware(XForwardedMiddleware)

    # Configure Slack alerts.
    if config and config.slack_alerts and config.slack_webhook:
        logger = structlog.get_logger("gafaelfawr")
        SlackRouteErrorHandler.initialize(
            config.slack_webhook, "Gafaelfawr", logger
        )
        logger.debug("Initialized Slack webhook")

    # Handle exceptions descended from ClientRequestError.
    app.exception_handler(ClientRequestError)(client_request_error_handler)

    return app
