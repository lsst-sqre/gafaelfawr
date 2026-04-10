"""Kubernetes operator health checks."""

from contextlib import aclosing
from typing import Any

import kopf
from sqlalchemy.ext.asyncio import AsyncEngine

from ..config import Config
from ..factory import Factory, ProcessContext
from ..models.health import HealthCheck, HealthStatus

__all__ = ["get_health"]


@kopf.on.probe(id="health")
async def get_health(memo: kopf.Memo, **_: Any) -> dict[str, Any]:
    """Health check for Gafaelfawr data stores.

    Check the health of the Gafaelfawr database, Redis, and (if configured)
    LDAP connections and raise an exception if any of them do not work.

    Parameters
    ----------
    memo
        Holds global state.
    """
    config: Config = memo.config
    context: ProcessContext = memo.context
    engine: AsyncEngine = memo.engine

    factory = await Factory.create(config, context, engine)
    async with aclosing(factory):
        health_check_service = factory.create_health_check_service()
        await health_check_service.check(check_user_info=False)
    return HealthCheck(status=HealthStatus.HEALTHY).model_dump(mode="json")
