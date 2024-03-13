"""Kubernetes operator health checks."""

from __future__ import annotations

from typing import Any

import kopf


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
    health_check_service = memo.factory.create_health_check_service()
    return await health_check_service.health().model_dump()
