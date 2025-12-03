"""Application definition for Gafaelfawr."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from importlib.metadata import version

import structlog
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from safir.database import create_database_engine, is_database_current
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.fastapi import ClientRequestError, client_request_error_handler
from safir.logging import configure_uvicorn_logging
from safir.middleware.x_forwarded import XForwardedMiddleware
from safir.models import ErrorModel
from safir.sentry import initialize_sentry
from safir.slack.webhook import SlackRouteErrorHandler

from . import __version__
from .constants import COOKIE_NAME
from .dependencies.config import config_dependency
from .dependencies.context import context_dependency
from .exceptions import DatabaseSchemaError
from .handlers import api, ingress, internal, login, logout, oidc
from .middleware.state import StateMiddleware
from .models.state import State

__all__ = ["create_app"]


def create_app(
    *,
    load_config: bool = True,
    extra_startup: Callable[[FastAPI], Awaitable[None]] | None = None,
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
    validate_schema
        If set to `True`, verify, with Alembic, that the schema is up to date
        and raise `~gafaelfawr.exceptions.DatabaseSchemaError` if it is not.

    Raises
    ------
    DatabaseSchemaError
        Raised if schema validation was requested and the current schema is
        out of date.
    """
    # Configure Sentry. If the SENTRY_DSN environment variable is not set, then
    # the Sentry integration won't be enabled.
    initialize_sentry(release=__version__)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        config = config_dependency.config()
        if validate_schema:
            logger = structlog.get_logger("gafaelfawr")
            engine = create_database_engine(
                config.database_url, config.database_password
            )
            if not await is_database_current(engine, logger):
                raise DatabaseSchemaError("Database schema out of date")
            await engine.dispose()
        event_manager = config.metrics.make_manager()
        await event_manager.initialize()
        await context_dependency.initialize(config, event_manager)
        await db_session_dependency.initialize(
            config.database_url, config.database_password
        )
        if extra_startup:
            await extra_startup(app)

        yield

        await http_client_dependency.aclose()
        await db_session_dependency.aclose()
        await context_dependency.aclose()
        await event_manager.aclose()

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
    app.include_router(ingress.router)
    app.include_router(internal.router)
    app.include_router(login.router)
    app.include_router(logout.router)
    app.include_router(oidc.router)

    # Load configuration if it is available to us and configure Uvicorn
    # logging.
    config = None
    if load_config:
        config = config_dependency.config()
        configure_uvicorn_logging()

    # Install the middleware.
    if config:
        app.add_middleware(
            XForwardedMiddleware,
            proxies=config.proxies,  # type: ignore[arg-type] # needs Safir fix
        )

        # There is currently a deep typing mismatch inside Starlette. See
        # https://github.com/encode/starlette/issues/2912
        app.add_middleware(
            StateMiddleware,  # type: ignore[arg-type]
            cookie_name=COOKIE_NAME,
            state_class=State,
            parameters=config.cookie_parameters,
        )

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


def create_openapi(*, add_back_link: bool = False) -> str:
    """Generate the OpenAPI schema.

    Parameters
    ----------
    add_back_link
        Whether to add a back link to the parent page to the description.
        This is useful when the schema will be rendered as part of the
        documentation.

    Returns
    -------
    str
        OpenAPI schema as serialized JSON.
    """
    app = create_app(load_config=False, validate_schema=False)
    description = app.description
    if add_back_link:
        description += "\n\n[Return to Gafaelfawr documentation](.)."
    schema = get_openapi(
        title=app.title,
        description=description,
        version=app.version,
        routes=app.routes,
    )
    return json.dumps(schema)
