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
    import jwt_authorizer.handlers.analyze  # noqa: F401
    import jwt_authorizer.handlers.auth  # noqa: F401
    import jwt_authorizer.handlers.index  # noqa: F401
    import jwt_authorizer.handlers.login  # noqa: F401
    import jwt_authorizer.handlers.tokens  # noqa: F401

    return routes
