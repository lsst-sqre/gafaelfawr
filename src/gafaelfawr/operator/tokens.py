"""Kubernetes operator handlers for GafaelfawrServiceTokens."""

from __future__ import annotations

import logging
from typing import Any

import kopf
from pydantic import ValidationError

from ..constants import KUBERNETES_TIMER_DELAY, KUBERNETES_TOKEN_INTERVAL
from ..exceptions import KubernetesObjectError
from ..models.kubernetes import GafaelfawrServiceToken
from ..services.kubernetes import KubernetesTokenService

__all__ = [
    "create",
    "periodic",
]


async def _update_token(
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    memo: kopf.Memo,
) -> dict[str, int | str] | None:
    """Do the work of updating the token, shared by `create` and `periodic`."""
    token_service: KubernetesTokenService = memo.token_service

    # These cases are probably not possible given how the handlers are
    # invoked, but unconfuse mypy.
    if not name or not namespace:
        return None

    # Parse the GafaelafwrServiceToken resource.
    try:
        service_token = GafaelfawrServiceToken.parse_obj(body)
    except ValidationError as e:
        raise KubernetesObjectError(
            "GafaelfawrServiceToken", name, namespace, e
        ) from e

    # Update the corresponding Secret and return the new status information.
    status = await token_service.update(name, namespace, service_token)
    return status.to_dict() if status else None


@kopf.on.create("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens")
@kopf.on.update("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens")
async def create(
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> dict[str, int | str] | None:
    """Handle creation or modification of a GafaelfawrServiceToken object.

    Parameters
    ----------
    name
        Name of the object.
    namespace
        Namespace of the object.
    body
        Body of the object in dictionary form.
    memo
        Holds global state, used to store the
        `~gafaelfawr.services.kubernetes.KubernetesTokenService` object.

    Returns
    -------
    dict or None
        Status information to record in the object, or `None` if no changes
        were made.
    """
    return await _update_token(name, namespace, body, memo)


@kopf.timer(
    "gafaelfawr.lsst.io",
    "v1alpha1",
    "gafaelfawrservicetokens",
    idle=KUBERNETES_TIMER_DELAY,
    interval=KUBERNETES_TOKEN_INTERVAL,
    initial_delay=KUBERNETES_TIMER_DELAY,
)
async def periodic(
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> dict[str, int | str] | None:
    """Periodically re-check all GafaelfawrServiceToken objects.

    Parameters
    ----------
    name
        Name of the object.
    namespace
        Namespace of the object.
    body
        Body of the object in dictionary form.
    memo
        Holds global state, used to store the
        `~gafaelfawr.services.kubernetes.KubernetesTokenService` object.

    Returns
    -------
    dict or None
        Status information to record in the object, or `None` if no changes
        were made.

    Notes
    -----
    The callbacks for timers have different signatures than the callbacks for
    event handlers, so this unfortunately has to be a separate function and
    thus will record separate status information than the `create` function.
    Kopf determines the key into which to store status information from the
    name of the handler function and there is apparently no way to override
    this.

    This uses idle and initial_delay settings to try to avoid conflicting with
    the create and update handlers on startup if changes had happened while
    the operator was down, without interfering too much with the test suite.
    """
    try:
        return await _update_token(name, namespace, body, memo)
    except Exception:
        # We don't want to retry failures for the token updates.  Just ignore
        # them and we'll try again in the normal interval.
        logging.exception(f"Processing of {namespace}/{name} failed")
        return None
