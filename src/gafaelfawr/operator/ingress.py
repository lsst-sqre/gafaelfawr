"""Kubernetes operator handlers for GafaelfawrIngress."""

from contextlib import aclosing
from typing import Any

import kopf
from kubernetes_asyncio.client import ApiClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncEngine

from ..config import Config
from ..exceptions import KubernetesObjectError
from ..factory import Factory, ProcessContext
from ..models.kubernetes import GafaelfawrIngress

__all__ = ["create"]


@kopf.on.create("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawringresses")
@kopf.on.resume("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawringresses")
@kopf.on.update("gafaelfawr.lsst.io", "v1alpha1", "gafaelfawringresses")
async def create(
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    memo: kopf.Memo,
    **_: Any,
) -> dict[str, int | str] | None:
    """Handle creation or modiication of a GafaelfawrIngress object.

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
        `~gafaelfawr.services.kubernetes.KubernetesIngressService` object.

    Returns
    -------
    dict or None
        Status information to record in the object, or `None` if no changes
        were made.
    """
    # These cases are probably not possible given how the handlers are
    # invoked, but unconfuse mypy.
    if not name or not namespace:
        return None

    api_client: ApiClient = memo.api_client
    config: Config = memo.config
    context: ProcessContext = memo.context
    engine: AsyncEngine = memo.engine

    factory = await Factory.create(config, context, engine)
    async with aclosing(factory):
        ingress_service = factory.create_kubernetes_ingress_service(api_client)

        # Parse the GafaelafwrIngress resource.
        try:
            ingress = GafaelfawrIngress.model_validate(body)
        except ValidationError as e:
            raise KubernetesObjectError(
                "GafaelfawrIngress", name, namespace, e
            ) from e

        # Update the corresponding Ingress and return the new status
        # information.
        status = await ingress_service.update(ingress)
        return status.to_dict() if status else None
