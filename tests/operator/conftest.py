"""Test fixtures for Kubernetes operators.

These are kept separate from the general test fixtures so that they can use
generic names that would only make sense in the Kubernetes context, without
risking confusion in other contexts.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
from kubernetes_asyncio.client import ApiClient
from safir.kubernetes import initialize_kubernetes

from ..support.kubernetes import install_crds, temporary_namespace

__all__ = [
    "api_client",
    "kubernetes_setup",
    "namespace",
]


@pytest_asyncio.fixture(loop_scope="session", scope="session", autouse=True)
async def kubernetes_setup() -> None:
    """Initialize the Kubernetes client and install the testing CRDs.

    Notes
    -----
    This needs to be done as a session fixture, since deleting CRDs between
    tests doesn't really work. Even if one waits for the CRD to be deleted,
    Kubernetes still won't allow it to be reinstalled, failing with a 409
    Conflict error. Presumably it lives on for longer than we want to wait.
    """
    await initialize_kubernetes()
    async with ApiClient() as api_client:
        await install_crds(api_client)


@pytest_asyncio.fixture
async def api_client() -> AsyncIterator[ApiClient]:
    """Set up a Kubernetes environment and clean up after a test."""
    async with ApiClient() as client:
        yield client


@pytest_asyncio.fixture
async def namespace(api_client: ApiClient) -> AsyncIterator[str]:
    """Set up a randomly-named namespace, and clean it up afterwards."""
    async with temporary_namespace(api_client) as namespace:
        yield namespace
