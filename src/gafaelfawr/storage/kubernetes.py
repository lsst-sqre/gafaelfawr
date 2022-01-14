"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

import asyncio
from asyncio import Queue
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    TypeVar,
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
from kubernetes_asyncio.watch import Watch
from structlog.stdlib import BoundLogger

from ..exceptions import KubernetesError, KubernetesObjectError
from ..models.token import Token

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

__all__ = [
    "GafaelfawrServiceToken",
    "KubernetesStorage",
    "KubernetesWatcher",
    "StatusReason",
    "WatchEvent",
    "WatchEventType",
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
    def from_dict(cls, obj: Dict[str, Any]) -> GafaelfawrServiceToken:
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
            return cls(
                name=name,
                namespace=namespace,
                annotations=obj["metadata"].get("annotations", {}),
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
            raise KubernetesObjectError(msg)

    @property
    def key(self) -> str:
        """Return a unique key for this custom object."""
        return f"{self.namespace}/{self.name}"


class WatchEventType(Enum):
    """The types of events that can be returned from the watch API."""

    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"


@dataclass
class WatchEvent:
    """A custom resource event returned from a watcher."""

    event_type: WatchEventType
    """The type of event."""

    name: str
    """Name of the custom object."""

    namespace: str
    """Namespace of the custom object."""

    generation: int
    """Generation of the custom object."""

    @property
    def key(self) -> str:
        """Return a unique key for this custom object."""
        return f"{self.namespace}/{self.name}"

    def __str__(self) -> str:
        return (
            f"{self.event_type.value} for {self.key}"
            f" (generation {self.generation})"
        )


class StatusReason(Enum):
    """Reason for the status update of a GafaelfawrServiceToken."""

    Created = "Created"
    Updated = "Updated"
    Failed = "Failed"


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
    ) -> None:
        """Create a Kubernetes secret from a token.

        The token will always be stored in the data field ``token``.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent `GafaelfawrServiceToken` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        await self._api.create_namespaced_secret(parent.namespace, secret)
        await self.update_service_token_status(
            parent,
            reason=StatusReason.Created,
            message="Secret was created",
            success=True,
        )

    async def create_service_token_watcher(self) -> Queue[WatchEvent]:
        """Create a Kubernetes watcher for a custom object.

        The watcher will run forever in a background thread.

        Returns
        -------
        queue : `asyncio.Queue`
            The queue into which the custom object events will be put.
        """
        queue: Queue[WatchEvent] = Queue(50)
        watcher = KubernetesWatcher(
            "gafaelfawrservicetokens", self._api_client, queue, self._logger
        )
        asyncio.create_task(watcher.run())
        return queue

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
    async def get_service_token(
        self, name: str, namespace: str
    ) -> Optional[GafaelfawrServiceToken]:
        """Retrieve a specific GafaelfawrServiceToken by name.

        Parameters
        ----------
        name : `str`
            The name of the object.
        namespace : `str`
            The namespace of the object.

        Returns
        -------
        token : `GafaelfawrServiceToken` or `None`
            The token, or `None` if it does not exist.
        """
        try:
            obj = await self._custom_api.get_namespaced_custom_object(
                "gafaelfawr.lsst.io",
                "v1alpha1",
                namespace,
                "gafaelfawrservicetokens",
                name,
            )
            return GafaelfawrServiceToken.from_dict(obj)
        except ApiException as e:
            if e.status == 404:
                return None
            raise
        except KubernetesObjectError as e:
            self._logger.warning(
                "Ignoring malformed GafaelfawrServiceToken", error=str(e)
            )
            return None

    @_convert_exception
    async def list_service_tokens(self) -> List[GafaelfawrServiceToken]:
        """Return a list of all GafaelfawrServiceToken objects in the cluster.

        Returns
        -------
        objects : List[`GafaelfawrServiceToken`]
            List of all GafaelfawrServiceToken objects in the cluster.
        """
        obj_list = await self._custom_api.list_cluster_custom_object(
            "gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens"
        )

        # Convert to GafaelfawrServiceToken objects.
        tokens = []
        for obj in obj_list["items"]:
            try:
                token = GafaelfawrServiceToken.from_dict(obj)
                tokens.append(token)
            except KubernetesObjectError as e:
                self._logger.warning(
                    "Ignoring malformed GafaelfawrServiceToken", error=str(e)
                )

        return tokens

    @_convert_exception
    async def replace_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> None:
        """Replace the token in a Secret.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the Secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        await self._api.replace_namespaced_secret(
            parent.name, parent.namespace, secret
        )
        await self.update_service_token_status(
            parent,
            reason=StatusReason.Updated,
            message="Secret was updated",
            success=True,
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

    @_convert_exception
    async def update_service_token_status(
        self,
        service_token: GafaelfawrServiceToken,
        *,
        reason: StatusReason,
        message: str,
        success: bool,
    ) -> None:
        """Update the status field of the parent GafaelfawrServiceToken.

        Parameters
        ----------
        service_token : `GafaelfawrServiceToken`
            The service token to update.
        reason : `StatusReason`
            The reason for the current condition.
        message : `str`
            Human-readable message describing the current condition.
        success : `bool`
            Whether the GafaelfawrServiceToken was successfully processed.
        """
        isodate = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

        # Remove the time zone from the date.
        now = isodate.split("+")[0] + "Z"

        patch = [
            {
                "op": "replace",
                "path": "/status",
                "value": {
                    "conditions": [
                        {
                            "lastTransitionTime": now,
                            "message": message,
                            "observedGeneration": service_token.generation,
                            "reason": reason.value,
                            "status": "True" if success else "False",
                            "type": "SecretCreated",
                        },
                    ],
                },
            },
        ]
        await self._custom_api.patch_namespaced_custom_object_status(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            service_token.namespace,
            "gafaelfawrservicetokens",
            service_token.name,
            patch,
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
        """
        return V1Secret(
            api_version="v1",
            kind="Secret",
            data={"token": self._encode_token(token)},
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

    @staticmethod
    def _encode_token(token: Token) -> str:
        """Encode a token in base64."""
        return b64encode(str(token).encode()).decode()


class KubernetesWatcher:
    """Watch for cluster-wide changes to a custom resource.

    Parameters
    ----------
    plural : `str`
        The plural for the custom resource for which to watch.
    api_client : ``kubernetes_asyncio.client.ApiClient``
        The Kubernetes client.
    queue : `asyncio.Queue`
        The queue into which to put the events.
    logger : ``structlog.stdlib.BoundLogger``
        Logger to use for messages.
    """

    def __init__(
        self,
        plural: str,
        api_client: ApiClient,
        queue: Queue[WatchEvent],
        logger: BoundLogger,
    ) -> None:
        self._plural = plural
        self._queue = queue
        self._logger = logger
        self._api = client.CustomObjectsApi(api_client)

    async def run(self) -> None:
        """Watch for changes to the configured custom object.

        This method is intended to be run as a background async task.  It will
        run forever, adding any custom object changes to the associated queue.
        """
        self._logger.debug("Starting Kubernetes watcher")
        consecutive_failures = 0
        watch_call = (
            self._api.list_cluster_custom_object,
            "gafaelfawr.lsst.io",
            "v1alpha1",
            self._plural,
        )
        while True:
            try:
                async with Watch().stream(*watch_call) as stream:
                    async for raw_event in stream:
                        event = self._parse_raw_event(raw_event)
                        if event:
                            await self._queue.put(event)
                        consecutive_failures = 0
            except ApiException as e:
                msg = "ApiException from watch"
                consecutive_failures += 1
                if consecutive_failures > 10:
                    raise
                else:
                    self._logger.exception(msg, error=str(e))
                    msg = "Pausing 10s before attempting to continue"
                    self._logger.info()
                    await asyncio.sleep(10)

    def _parse_raw_event(
        self, raw_event: Dict[str, Any]
    ) -> Optional[WatchEvent]:
        """Parse a raw event from the watch API.

        Returns
        -------
        event : `WatchEvent` or `None`
            A `WatchEvent` object if the event could be parsed, otherwise
           `None`.
        """
        try:
            return WatchEvent(
                event_type=WatchEventType(raw_event["type"]),
                name=raw_event["object"]["metadata"]["name"],
                namespace=raw_event["object"]["metadata"]["namespace"],
                generation=raw_event["object"]["metadata"]["generation"],
            )
        except KeyError:
            return None
