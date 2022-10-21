"""Kubernetes operator handlers for GafaelfawrServiceTokens."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Union

import kopf

from ..constants import KUBERNETES_TIMER_DELAY, KUBERNETES_TOKEN_INTERVAL
from ..services.kubernetes import KubernetesTokenService

__all__ = [
    "create",
    "periodic",
]


async def _update_token(
    name: Optional[str],
    namespace: Optional[str],
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> Optional[Dict[str, Union[int, str]]]:
    """Do the work of updating the token, shared by `create` and `periodic`."""
    token_service: KubernetesTokenService = memo.token_service
    if not name:
        return None
    if not namespace:
        return None
    status = await token_service.update(name, namespace, body)
    return status.to_dict() if status else None


@kopf.on.create("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens")
@kopf.on.update("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens")
async def create(
    name: Optional[str],
    namespace: Optional[str],
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> Optional[Dict[str, Union[int, str]]]:
    """Handle creation or modification of a GafaelfawrServiceToken object.

    Parameters
    ----------
    name : `str`
        Name of the object.
    namespace : `str`
        Namespace of the object.
    body : `kopf.Body`
        Body of the object in dictionary form.
    memo : `kopf.Memo`
        Holds global state, used to store the
        `~gafaelfawr.services.KubernetesService` object.

    Returns
    -------
    status : Dict[`str`, Union[`int`, `str`]] or `None`
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
    name: Optional[str],
    namespace: Optional[str],
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> Optional[Dict[str, Union[int, str]]]:
    """Periodically re-check all GafaelfawrServiceToken objects.

    Parameters
    ----------
    name : `str`
        Name of the object.
    namespace : `str`
        Namespace of the object.
    body : `kopf.Body`
        Body of the object in dictionary form.
    memo : `kopf.Memo`
        Holds global state, used to store the
        `~gafaelfawr.services.KubernetesService` object.

    Returns
    -------
    status : Dict[`str`, Union[`int`, `str`]] or `None`
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
