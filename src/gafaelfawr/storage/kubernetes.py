"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

from base64 import b64encode
from functools import wraps
from typing import Any, Awaitable, Callable, Optional, TypeVar, cast

from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)
from structlog.stdlib import BoundLogger

from ..exceptions import KubernetesError
from ..models.kubernetes import (
    GafaelfawrServiceToken,
    KubernetesResourceStatus,
    StatusReason,
)
from ..models.token import Token

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

__all__ = ["KubernetesTokenStorage"]


def _convert_exception(f: F) -> F:
    """Convert Kubernetes ApiException to KubernetesError."""

    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await f(*args, **kwargs)
        except ApiException as e:
            raise KubernetesError(f"Kubernetes API error: {str(e)}") from e

    return cast(F, wrapper)


class KubernetesTokenStorage:
    """Kubernetes storage layer for service token objects.

    This abstracts storage of Gafaelfawr service tokens in Kubernetes objects
    by wrapping the underlying Kubernetes Python client.

    Parameters
    ----------
    api_client
        Kubernetes async client to use.
    logger
        Logger to use.
    """

    def __init__(self, api_client: ApiClient, logger: BoundLogger) -> None:
        self._api_client = api_client
        self._api = client.CoreV1Api(api_client)
        self._custom_api = client.CustomObjectsApi(api_client)
        self._logger = logger

    @_convert_exception
    async def create_secret(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> KubernetesResourceStatus:
        """Create a Kubernetes secret from a ``GafaelfawrServiceToken``.

        The token will always be stored in the data field ``token``.

        Parameters
        ----------
        parent
            The parent object for the secret.
        token
            The token to store.

        Returns
        -------
        KubernetesResourceStatus
            Status information to store in the parent object.
        """
        secret = self._build_secret(parent, token)
        await self._api.create_namespaced_secret(parent.namespace, secret)
        return KubernetesResourceStatus(
            message="Secret was created",
            reason=StatusReason.Created,
            generation=parent.generation,
        )

    @_convert_exception
    async def get_secret(
        self, parent: GafaelfawrServiceToken
    ) -> Optional[V1Secret]:
        """Retrieve the secret corresponding to a ``GafaelfawrServiceToken``.

        Parameters
        ----------
        parent
            The parent object.

        Returns
        -------
        kubernetes_asyncio.client.V1Secret or None
            The Kubernetes secret, or `None` if that secret does not exist.
        """
        try:
            secret = await self._api.read_namespaced_secret(
                parent.name, parent.namespace
            )
        except ApiException as e:
            if e.status == 404:
                return None
            raise

        return secret

    @_convert_exception
    async def replace_secret(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> KubernetesResourceStatus:
        """Replace the token in a ``Secret``.

        Parameters
        ----------
        parent
            The parent object for the ``Secret``.
        token
            The token to store.

        Returns
        -------
        KubernetesResourceStatus
            Status information to store in the parent object.
        """
        secret = self._build_secret(parent, token)
        await self._api.replace_namespaced_secret(
            parent.name, parent.namespace, secret
        )
        return KubernetesResourceStatus(
            message="Secret was updated",
            reason=StatusReason.Updated,
            generation=parent.generation,
        )

    @_convert_exception
    async def update_secret_metadata(
        self, parent: GafaelfawrServiceToken
    ) -> None:
        """Update the metadata for a ``Secret``.

        Parameters
        ----------
        parent
            The parent object for the ``Secret``.
        """
        await self._api.patch_namespaced_secret(
            parent.name,
            parent.namespace,
            [
                {
                    "op": "replace",
                    "path": "/metadata/annotations",
                    "value": parent.annotations,
                },
                {
                    "op": "replace",
                    "path": "/metadata/labels",
                    "value": parent.labels,
                },
            ],
        )

    def _build_secret(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> V1Secret:
        """Construct a new ``Secret`` object.

        Parameters
        ----------
        parent
            The parent object.
        token
            The Gafaelfawr token to store in the secret.

        Returns
        -------
        kubernetes_asyncio.client.V1Secret
            Newly created secret.

        Notes
        -----
        Unfortunately, we cannot use `kopf.adopt` and have to manually
        implement the same logic, since Kopf doesn't support
        kubernetes_asyncio.
        """
        secret = V1Secret(
            api_version="v1",
            kind="Secret",
            data={"token": b64encode(str(token).encode()).decode()},
            metadata=V1ObjectMeta(
                name=parent.name,
                namespace=parent.namespace,
                annotations=parent.annotations,
                labels=parent.labels,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrServiceToken",
                        name=parent.name,
                        uid=parent.uid,
                    ),
                ],
            ),
            type="Opaque",
        )
        return secret
