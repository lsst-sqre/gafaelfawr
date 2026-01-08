"""FastAPI dependencies providing a Gafaelfawr client."""

from typing import Annotated

from fastapi import Depends
from httpx import AsyncClient
from rubin.repertoire import DiscoveryClient, discovery_dependency
from safir.dependencies.http_client import http_client_dependency

from ._client import GafaelfawrClient

__all__ = ["GafaelfawrDependency", "gafaelfawr_dependency"]


class GafaelfawrDependency:
    """Maintain a global Gafaelfawr client.

    This is structured as a dependency that creates and caches the client on
    first use to delay client creation until runtime so that the test suite
    has a chance to initialize environment variables.
    """

    def __init__(self) -> None:
        self._http_client: AsyncClient | None = None
        self._client: GafaelfawrClient | None = None

    async def __call__(
        self,
        discovery: Annotated[DiscoveryClient, Depends(discovery_dependency)],
        http_client: Annotated[AsyncClient, Depends(http_client_dependency)],
    ) -> GafaelfawrClient:
        if not self._client or self._http_client != http_client:
            self._client = GafaelfawrClient(
                http_client, discovery_client=discovery
            )
            self._http_client = http_client
        return self._client


gafaelfawr_dependency = GafaelfawrDependency()
"""The cached Gafaelfawr client as a FastAPI dependency."""
