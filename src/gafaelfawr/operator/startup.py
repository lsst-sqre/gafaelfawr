"""Kubernetes operator startup and shutdown."""

from __future__ import annotations

from typing import Any

import kopf
from kubernetes_asyncio.client import ApiClient
from safir.database import create_database_engine
from safir.kubernetes import initialize_kubernetes

from ..constants import KUBERNETES_WATCH_TIMEOUT
from ..dependencies.config import config_dependency
from ..factory import Factory

__all__ = ["startup", "shutdown"]


@kopf.on.startup()
async def startup(
    memo: kopf.Memo, settings: kopf.OperatorSettings, **_: Any
) -> None:
    """Initialize global data for Kubernetes operators.

    Anything stored in the provided ``memo`` argument will be made available,
    via shallow copy, in the ``memo`` argument to any other handler. Use this
    to initialize the database and Redis pools, create service objects, and so
    forth. Also add some configuration settings to Kopf.

    Parameters
    ----------
    memo
        Holds global state, used to store the service objects and the various
        infrastructure used to create them, and which needs to be freed
        cleanly during shutdown.
    settings
        Holds the Kopf settings.
    """
    settings.watching.server_timeout = KUBERNETES_WATCH_TIMEOUT
    settings.watching.client_timeout = KUBERNETES_WATCH_TIMEOUT + 60

    config = await config_dependency()
    await initialize_kubernetes()

    engine = create_database_engine(
        config.database_url, config.database_password
    )
    factory = await Factory.create(config, engine, check_db=True)
    api_client = ApiClient()
    ingress_service = factory.create_kubernetes_ingress_service(api_client)
    token_service = factory.create_kubernetes_token_service(api_client)

    memo.engine = engine
    memo.factory = factory
    memo.api_client = api_client
    memo.ingress_service = ingress_service
    memo.token_service = token_service


@kopf.on.cleanup()
async def shutdown(memo: kopf.Memo, **_: Any) -> None:
    """Shut down a running Kubernetes operator.

    Parameters
    ----------
    memo
        Holds global state, used to store the factory, Kubernetes client, and
        other state that needs to be freed cleanly during shutdown.
    """
    await memo.api_client.close()
    await memo.factory.aclose()
    await memo.engine.dispose()
