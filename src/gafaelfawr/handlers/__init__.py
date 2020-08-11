"""HTTP API route tables."""

from __future__ import annotations

import aiohttp

__all__ = [
    "init_routes",
    "routes",
]

routes = aiohttp.web.RouteTableDef()
"""All routes for the application."""


def init_routes() -> aiohttp.web.RouteTableDef:
    """Initialize the route table for the routes."""
    # Import handlers so that they are registered with the routes table via
    # decorators. This isn't a global import to avoid circular dependencies.
    import gafaelfawr.handlers.analyze  # noqa: F401
    import gafaelfawr.handlers.auth  # noqa: F401
    import gafaelfawr.handlers.index  # noqa: F401
    import gafaelfawr.handlers.login  # noqa: F401
    import gafaelfawr.handlers.logout  # noqa: F401
    import gafaelfawr.handlers.oidc  # noqa: F401
    import gafaelfawr.handlers.tokens  # noqa: F401
    import gafaelfawr.handlers.userinfo  # noqa: F401
    import gafaelfawr.handlers.well_known  # noqa: F401

    return routes
