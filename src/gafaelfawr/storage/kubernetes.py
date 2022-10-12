"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    TypeVar,
    Union,
    cast,
)

from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)
from structlog.stdlib import BoundLogger

from ..exceptions import KubernetesError, KubernetesObjectError
from ..models.token import Token
from ..util import current_datetime

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

__all__ = [
    "GafaelfawrServiceToken",
    "GafaelfawrServiceTokenStatus",
    "KubernetesStorage",
    "StatusReason",
]


@dataclass
class GafaelfawrServiceToken:
    """The key data from a GafaelfawrServiceToken Kubernetes object."""

    name: str
    """The name of the GafaelfawrServiceToken object."""

    namespace: str
    """The namespace in which the GafaelfawrServiceToken object is located."""

    annotations: Dict[str, str]
    """The annotations of the GafaelfawrServiceToken object."""

    labels: Dict[str, str]
    """The labels of the GafaelfawrServiceToken object."""

    uid: str
    """The UID of the GafaelfawrServiceToken object."""

    generation: int
    """The generation of the GafaelfawrServiceToken object."""

    service: str
    """The username of the service token."""

    scopes: List[str]
    """The scopes to grant to the service token."""

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any]) -> GafaelfawrServiceToken:
        """Convert from the dict returned by Kubernetes.

        Parameters
        ----------
        obj : Dict[`str`, Any]
            The object as returned by the Kubernetes API.

        Raises
        ------
        KubernetesObjectError
            The dict could not be parsed.
        """
        name = None
        namespace = None
        try:
            name = obj["metadata"]["name"]
            namespace = obj["metadata"]["namespace"]
            annotations = {
                k: v
                for k, v in obj["metadata"].get("annotations", {}).items()
                if not k.startswith("kopf.zalando.org/")
            }
            return cls(
                name=name,
                namespace=namespace,
                annotations=annotations,
                labels=obj["metadata"].get("labels", {}),
                uid=obj["metadata"]["uid"],
                generation=obj["metadata"]["generation"],
                service=obj["spec"]["service"],
                scopes=obj["spec"]["scopes"],
            )
        except KeyError as e:
            if name and namespace:
                msg = (
                    f"GafaelfawrServiceToken {namespace}/{name} is"
                    f" malformed: {str(e)}"
                )
            else:
                msg = f"GafaelfawrServiceToken is malformed: {str(e)}"
            raise KubernetesObjectError(msg) from e

    @property
    def key(self) -> str:
        """Return a unique key for this custom object."""
        return f"{self.namespace}/{self.name}"


class StatusReason(Enum):
    """Reason for the status update of a GafaelfawrServiceToken."""

    Created = "Created"
    Updated = "Updated"
    Failed = "Failed"


@dataclass
class GafaelfawrServiceTokenStatus:
    """Represents the processing status of a GafaelfawrServiceToken.

    This is returned as the result of the Kopf_ operator handlers for changes
    to a GafaelfawrServiceToken.  Kopf will then put this information into the
    ``status`` field of the GafaelfawrServiceToken object.
    """

    message: str
    """Message associated with the transition."""

    generation: int
    """Generation of the GafaelfawrServiceToken that was processed."""

    reason: StatusReason
    """Reason for the status update."""

    timestamp: datetime = field(default_factory=current_datetime)
    """Time of the status event."""

    @classmethod
    def failure(
        cls, service_token: GafaelfawrServiceToken, message: str
    ) -> GafaelfawrServiceTokenStatus:
        """Create a status object for a failure.

        Parameters
        ----------
        service_token : `GafaelfawrServiceToken`
            The GafaelfawrServiceToken object being processed.
        message : `str`
            The error message for the failure.
        """
        return cls(
            message=message,
            generation=service_token.generation,
            reason=StatusReason.Failed,
        )

    def to_dict(self) -> Dict[str, Union[str, int]]:
        """Convert the status update to a dictionary for Kubernetes."""
        transition_time = self.timestamp.isoformat().split("+")[0] + "Z"
        status = "False" if self.reason == StatusReason.Failed else "True"
        return {
            "lastTransitionTime": transition_time,
            "message": self.message,
            "observedGeneration": self.generation,
            "reason": self.reason.value,
            "status": status,
            "type": "SecretCreated",
        }


def _convert_exception(f: F) -> F:
    """Convert Kubernetes ApiException to KubernetesError."""

    @wraps(f)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await f(*args, **kwargs)
        except ApiException as e:
            raise KubernetesError(f"Kubernetes API error: {str(e)}") from e

    return cast(F, wrapper)


class KubernetesStorage:
    """Kubernetes storage layer.

    This abstracts storage of Kubernetes objects by wrapping the underlying
    Kubernetes Python client.
    """

    def __init__(self, api_client: ApiClient, logger: BoundLogger) -> None:
        self._api_client = api_client
        self._api = client.CoreV1Api(api_client)
        self._custom_api = client.CustomObjectsApi(api_client)
        self._logger = logger

    @_convert_exception
    async def create_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> GafaelfawrServiceTokenStatus:
        """Create a Kubernetes secret from a token.

        The token will always be stored in the data field ``token``.  This
        must be called within a Kopf_ handler, since it relies on Kopf and the
        currently-processed resource to set metadata for the ``Secret``.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent `GafaelfawrServiceToken` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.

        Returns
        -------
        status : `GafaelfawrServiceTokenStatus`
            Status information to store in the parent object.
        """
        secret = self._build_secret_for_service_token(parent, token)
        await self._api.create_namespaced_secret(parent.namespace, secret)
        return GafaelfawrServiceTokenStatus(
            message="Secret was created",
            reason=StatusReason.Created,
            generation=parent.generation,
        )

    @_convert_exception
    async def get_secret_for_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> Optional[V1Secret]:
        """Retrieve the secret corresponding to a GafaelfawrServiceToken.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent GafaelfawrServiceToken object.

        Returns
        -------
        secret : ``kubernetes_asyncio.client.V1Secret`` or `None`
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
    async def replace_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> GafaelfawrServiceTokenStatus:
        """Replace the token in a Secret.

        This must be called within a Kopf_ handler, since it relies on Kopf
        and the currently-processed resource to set metadata for the
        ``Secret``.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the Secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.

        Returns
        -------
        status : `GafaelfawrServiceTokenStatus`
            Status information to store in the parent object.
        """
        secret = self._build_secret_for_service_token(parent, token)
        await self._api.replace_namespaced_secret(
            parent.name, parent.namespace, secret
        )
        return GafaelfawrServiceTokenStatus(
            message="Secret was updated",
            reason=StatusReason.Updated,
            generation=parent.generation,
        )

    @_convert_exception
    async def update_secret_metadata_for_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> None:
        """Update the metadata for a Secret.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the Secret.
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

    def _build_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> V1Secret:
        """Construct a new Secret object.

        Parameters
        ----------
        parent : `GafaelfawrServiceSecret`
            The parent GafaelfawrServiceSecret object.
        token : `gafaelfawr.models.token.Token`
            The Gafaelfawr token to store in the secret.

        Returns
        -------
        secret : ``kubernetes_asyncio.client.V1Secret``
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
