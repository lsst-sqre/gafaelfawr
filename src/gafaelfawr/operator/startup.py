"""Kubernetes operator startup and shutdown."""

from __future__ import annotations

from typing import Any

import kopf
from kubernetes_asyncio.client import ApiClient
from safir.database import create_database_engine
from safir.kubernetes import initialize_kubernetes

from ..dependencies.config import config_dependency
from ..factory import Factory

__all__ = ["startup", "shutdown"]


@kopf.on.startup()
async def startup(memo: kopf.Memo, **_: Any) -> None:
    """Initialize global data for Kubernetes operators.

    Anything stored in the provided ``memo`` argument will be made available,
    via shallow copy, in the ``memo`` argument to any other handler.  Use this
    to initialize the database and Redis pools, create service objects, and so
    forth.
    """
    config = await config_dependency()
    memo.engine = create_database_engine(
        config.database_url, config.database_password
    )
    memo.factory = await Factory.create(config, memo.engine, check_db=True)
    await initialize_kubernetes()
    memo.api_client = ApiClient()
    service = memo.factory.create_kubernetes_token_service(memo.api_client)
    memo.token_service = service


@kopf.on.cleanup()
async def shutdown(memo: kopf.Memo, **_: Any) -> None:
    """Shut down a running Kubernetes operator."""
    await memo.api_client.close()
    await memo.factory.aclose()
    await memo.engine.dispose()
