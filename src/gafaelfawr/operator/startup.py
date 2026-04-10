"""Kubernetes operator startup and shutdown."""

from typing import Any

import kopf
import structlog
from kubernetes_asyncio.client import ApiClient
from safir.database import create_database_engine, is_database_current
from safir.kubernetes import initialize_kubernetes

from ..constants import KUBERNETES_WATCH_TIMEOUT
from ..dependencies.config import config_dependency
from ..exceptions import DatabaseSchemaError
from ..factory import ProcessContext

__all__ = ["shutdown", "startup"]


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
    settings.queueing.worker_limit = 5

    config = await config_dependency()
    await initialize_kubernetes()
    context = await ProcessContext.from_config(config)

    engine = create_database_engine(
        config.database_url, config.database_password
    )
    logger = structlog.get_logger("gafaelfawr")
    if not await is_database_current(engine, logger):
        raise DatabaseSchemaError("Database schema is not current")
    api_client = ApiClient()

    memo.api_client = api_client
    memo.config = config
    memo.context = context
    memo.engine = engine
    memo.logger = logger


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
    await memo.context.aclose()
    await memo.engine.dispose()
