"""HTTP client dependency for FastAPI."""

from __future__ import annotations

from typing import AsyncIterator

from httpx import AsyncClient

from gafaelfawr.constants import HTTP_TIMEOUT

__all__ = ["http_client_dependency"]


async def http_client_dependency() -> AsyncIterator[AsyncClient]:
    """Provides an `httpx.AsyncClient` as a dependency.

    Notes
    -----
    This is provided as a function rather than using the class as a callable
    directly so that the session can be explicitly closed and to avoid
    exposing the constructor parameters to FastAPI and possibly confusing it.

    This dependency should eventually move into the Safir framework.
    """
    async with AsyncClient(timeout=HTTP_TIMEOUT) as client:
        yield client
