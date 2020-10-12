"""FastAPI route tables."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
"""All routes for the application."""


def init_router() -> None:
    """Initialize the route table for the routes."""
    # Import handlers so that they are registered with the routes table via
    # decorators. This isn't a global import to avoid circular dependencies.
    import gafaelfawr.fastapi.handlers.analyze  # noqa: F401
    import gafaelfawr.fastapi.handlers.auth  # noqa: F401
    import gafaelfawr.fastapi.handlers.index  # noqa: F401
    import gafaelfawr.fastapi.handlers.influxdb  # noqa: F401
    import gafaelfawr.fastapi.handlers.login  # noqa: F401
    import gafaelfawr.fastapi.handlers.logout  # noqa: F401
    import gafaelfawr.fastapi.handlers.oidc  # noqa: F401
    import gafaelfawr.fastapi.handlers.tokens  # noqa: F401
    import gafaelfawr.fastapi.handlers.userinfo  # noqa: F401
    import gafaelfawr.fastapi.handlers.well_known  # noqa: F401
