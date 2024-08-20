"""Kubernetes operator startup and shutdown."""

from __future__ import annotations

from typing import Any

import kopf
import structlog
from kubernetes_asyncio.client import ApiClient
from safir.database import create_database_engine
from safir.kubernetes import initialize_kubernetes

from ..constants import KUBERNETES_WATCH_TIMEOUT
from ..database import is_database_current
from ..dependencies.config import config_dependency
from ..exceptions import DatabaseSchemaError
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

    Raises
    ------
    DatabaseSchemaError
        Raised if the database schema is not current.
    """
    settings.watching.server_timeout = KUBERNETES_WATCH_TIMEOUT
    settings.watching.client_timeout = KUBERNETES_WATCH_TIMEOUT + 60

    # Only run at most five workers at a time. Nothing the Gafaelfawr operator
    # does will be that urgent and we don't want to overwhelm the API server.
    settings.batching.worker_limit = 5

    config = await config_dependency()
    await initialize_kubernetes()

    engine = create_database_engine(
        config.database_url, config.database_password
    )
    logger = structlog.get_logger("gafaelfawr")
    if not await is_database_current(config, logger, engine):
        raise DatabaseSchemaError("Database schema is not current")
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
