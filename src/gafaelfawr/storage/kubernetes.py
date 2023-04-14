"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

from base64 import b64encode
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, TypeVar, cast

from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    ApiException,
    V1Ingress,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)
from structlog.stdlib import BoundLogger

from ..exceptions import KubernetesError
from ..models.kubernetes import (
    GafaelfawrIngress,
    GafaelfawrServiceToken,
    KubernetesResourceStatus,
    StatusReason,
)
from ..models.token import Token

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

__all__ = [
    "KubernetesIngressStorage",
    "KubernetesTokenStorage",
]


def _convert_exception(f: F) -> F:
    """Convert Kubernetes ApiException to KubernetesError."""

    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await f(*args, **kwargs)
        except ApiException as e:
            raise KubernetesError(f"Kubernetes API error: {str(e)}") from e

    return cast(F, wrapper)


class KubernetesIngressStorage:
    """Kubernetes storage layer for ingress objects.

    This abstracts creation of ``Ingress`` resources based on configuration
    and templates in ``GafaelfawrIngress`` resources by wrapping the
    underlying Kubernetes Python client.

    Parameters
    ----------
    api_client
        Kubernetes async client to use.
    logger
        Logger to use.

    Notes
    -----
    Unlike `KubernetesTokenStorage`, this storage layer is very lightweight,
    since the API is defined in terms of Kubernetes API objects (there was no
    compelling reason to create parallel models) and the service is
    responsible for assembling those objects based on the template in
    ``GafaelfawrIngress``.
    """

    def __init__(self, api_client: ApiClient, logger: BoundLogger) -> None:
        self._api = client.NetworkingV1Api(api_client)
        self._custom_api = client.CustomObjectsApi(api_client)
        self._logger = logger

    @_convert_exception
    async def create_ingress(
        self, ingress: V1Ingress, parent: GafaelfawrIngress
    ) -> KubernetesResourceStatus:
        """Create a Kubernetes ``Ingress`` resource.

        Parameters
        ----------
        ingress
            The ``Ingress`` object to create. This will be modified in place
            to add owner metadata.
        parent
            The parent object for the ingress

        Returns
        -------
        KubernetesResourceStatus
            Status information to store in the parent object.
        """
        self._add_owner(ingress, parent)
        namespace = ingress.metadata.namespace
        await self._api.create_namespaced_ingress(namespace, ingress)
        return KubernetesResourceStatus(
            message="Ingress was created",
            reason=StatusReason.Created,
            generation=parent.metadata.generation,
        )

    @_convert_exception
    async def get_ingress(self, name: str, namespace: str) -> V1Ingress | None:
        """Retrieve a Kubernetes ``Ingress`` resource.

        Parameters
        ----------
        name
            Name of the ingress
        namespace
            Namespace in which the ingress is located

        Returns
        -------
        kubernetes_asyncio.client.models.V1Ingress or None
            The Kubernetes ingress object, or `None` if it doesn't exist.
        """
        try:
            return await self._api.read_namespaced_ingress(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    @_convert_exception
    async def replace_ingress(
        self, ingress: V1Ingress, parent: GafaelfawrIngress
    ) -> KubernetesResourceStatus:
        """Replace a Kubernetes ``Ingress`` resource.

        Parameters
        ----------
        ingress
            The ``Ingress`` object to replace. This will be modified in place
            to add owner metadata.
        parent
            The parent object for the ingress

        Returns
        -------
        KubernetesResourceStatus
            Status information to store in the parent object.
        """
        self._add_owner(ingress, parent)
        name = ingress.metadata.name
        namespace = ingress.metadata.namespace
        await self._api.replace_namespaced_ingress(name, namespace, ingress)
        return KubernetesResourceStatus(
            message="Ingress was updated",
            reason=StatusReason.Updated,
            generation=parent.metadata.generation,
        )

    def _add_owner(
        self, ingress: V1Ingress, parent: GafaelfawrIngress
    ) -> V1Ingress:
        """Add ownership information to an ingress object.

        Parameters
        ----------
        ingress
             Object to which to add ownership. The object is modified in
             place.
        """
        ingress.metadata.owner_references = [
            V1OwnerReference(
                api_version="gafaelfawr.lsst.io/v1alpha1",
                block_owner_deletion=True,
                controller=True,
                kind="GafaelfawrIngress",
                name=parent.metadata.name,
                uid=parent.metadata.uid,
            )
        ]


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
        namespace = parent.metadata.namespace
        await self._api.create_namespaced_secret(namespace, secret)
        return KubernetesResourceStatus(
            message="Secret was created",
            reason=StatusReason.Created,
            generation=parent.metadata.generation,
        )

    @_convert_exception
    async def get_secret(
        self, parent: GafaelfawrServiceToken
    ) -> V1Secret | None:
        """Retrieve the secret corresponding to a ``GafaelfawrServiceToken``.

        Parameters
        ----------
        parent
            The parent object.

        Returns
        -------
        kubernetes_asyncio.client.models.V1Secret or None
            The Kubernetes secret, or `None` if that secret does not exist.
        """
        try:
            return await self._api.read_namespaced_secret(
                parent.metadata.name, parent.metadata.namespace
            )
        except ApiException as e:
            if e.status == 404:
                return None
            raise

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
            parent.metadata.name, parent.metadata.namespace, secret
        )
        return KubernetesResourceStatus(
            message="Secret was updated",
            reason=StatusReason.Updated,
            generation=parent.metadata.generation,
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
            parent.metadata.name,
            parent.metadata.namespace,
            [
                {
                    "op": "replace",
                    "path": "/metadata/annotations",
                    "value": parent.metadata.annotations,
                },
                {
                    "op": "replace",
                    "path": "/metadata/labels",
                    "value": parent.metadata.labels,
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
                name=parent.metadata.name,
                namespace=parent.metadata.namespace,
                annotations=parent.metadata.annotations,
                labels=parent.metadata.labels,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrServiceToken",
                        name=parent.metadata.name,
                        uid=parent.metadata.uid,
                    ),
                ],
            ),
            type="Opaque",
        )
        return secret
