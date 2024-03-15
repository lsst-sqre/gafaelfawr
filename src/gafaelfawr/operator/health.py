"""Kubernetes operator health checks."""

from __future__ import annotations

from typing import Any

import kopf

from ..factory import Factory
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
    factory: Factory = memo.factory

    health_check_service = factory.create_health_check_service()
    await health_check_service.check()
    return HealthCheck(status=HealthStatus.HEALTHY).model_dump()
