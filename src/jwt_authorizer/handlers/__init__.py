"""HTTP API route tables."""

from __future__ import annotations

from aiohttp import web

__all__ = [
    "internal_routes",
    "routes",
    "init_internal_routes",
    "init_external_routes",
]


internal_routes = web.RouteTableDef()
"""Routes for the root application that serves from ``/``

Application-specific routes don't get attached here. In practice, only routes
for metrics and health checks get attached to this table. Attach public APIs
to ``routes`` instead since those are accessible from the public API gateway
and are prefixed with the application name.
"""

routes = web.RouteTableDef()
"""Routes for the public API that serves from ``/auth``."""


def init_external_routes() -> web.RouteTableDef:
    """Initialize the route table for the routes served at ``/auth``."""
    # Import handlers so that they are registered with the routes table via
    # decorators. This isn't a global import to avoid circular dependencies.
    import jwt_authorizer.handlers.external  # noqa: F401

    return routes


def init_internal_routes() -> web.RouteTableDef:
    """Initialize the route table the root APIs (not the public ones)."""
    # Import handlers so that they are registered with the routes table via
    # decorators. This isn't a global import to avoid circular dependencies.
    import jwt_authorizer.handlers.internal  # noqa: F401

    return internal_routes
