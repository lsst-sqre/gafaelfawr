"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

import os
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, TypeVar, cast

import kubernetes
from kubernetes.client import (
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)

from gafaelfawr.exceptions import KubernetesError
from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from queue import Queue
    from typing import Dict, List, Optional

    from structlog.stdlib import BoundLogger

F = TypeVar("F", bound=Callable[..., Any])

__all__ = ["KubernetesStorage"]


class KubernetesObjectError(Exception):
    """A Kubernetes object could not be parsed."""


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


class StatusReason(Enum):
    """Reason for the status update of a GafaelfawrServiceToken."""

    Created = "Created"
    Updated = "Updated"
    Failed = "Failed"


def _convert_exception(f: F) -> F:
    """Convert Kubernetes ApiException to KubernetesError."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except ApiException as e:
            raise KubernetesError(f"Kubernetes API error: {str(e)}") from e

    return cast(F, wrapper)


class KubernetesStorage:
    """Kubernetes storage layer.

    This abstracts storage of Kubernetes objects by wrapping the underlying
    Kubernetes Python client.

    Parameters
    ----------
    logger : `structlog.stdlib.BoundLogger`
        Logger to use for messages.
    """

    def __init__(
        self,
        logger: BoundLogger,
    ) -> None:
        if "KUBERNETES_PORT" in os.environ:
            kubernetes.config.load_incluster_config()
        else:
            kubernetes.config.load_kube_config()
        self._api = kubernetes.client.CoreV1Api()
        self._custom_api = kubernetes.client.CustomObjectsApi()
        self._logger = logger

    @_convert_exception
    def create_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> None:
        """Create a Kubernetes secret from a token.

        The token will always be stored in the data field ``token``.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        self._api.create_namespaced_secret(parent.namespace, secret)
        self.update_service_token_status(
            parent,
            reason=StatusReason.Created,
            message="Secret was created",
            success=True,
        )

    @_convert_exception
    def get_secret_for_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> Optional[V1Secret]:
        """Retrieve the secret corresponding to a GafaelfawrServiceToken.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent GafaelfawrServiceToken object.

        Returns
        -------
        secret : `kubernetes.client.V1Secret` or `None`
            The Kubernetes secret, or `None` if that secret does not exist.
        """
        try:
            secret = self._api.read_namespaced_secret(
                parent.name, parent.namespace
            )
        except ApiException as e:
            if e.status == 404:
                return None
            raise

        return secret

    @_convert_exception
    def get_service_token(
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
            obj = self._custom_api.get_namespaced_custom_object(
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
    def list_service_tokens(self) -> List[GafaelfawrServiceToken]:
        """Return a list of all GafaelfawrServiceToken objects in the cluster.

        Returns
        -------
        objects : List[Dict[`str`, Any]]
        """
        obj_list = self._custom_api.list_cluster_custom_object(
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
    def replace_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> None:
        """Replace the token in a secret.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        self._api.replace_namespaced_secret(parent.namespace, secret)
        self.update_service_token_status(
            parent,
            reason=StatusReason.Updated,
            message="Secret was updated",
            success=True,
        )

    @_convert_exception
    def update_service_token_status(
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

        patch = {
            "status": {
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
        }
        self._custom_api.patch_namespaced_custom_object_status(
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
    queue : `queue.Queue`
        The queue into which to put the events.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use for messages.
    """

    def __init__(
        self,
        plural: str,
        queue: Queue[WatchEvent],
        logger: BoundLogger,
    ) -> None:
        self._plural = plural
        self._queue = queue
        self._logger = logger
        self._api = kubernetes.client.CustomObjectsApi()

    def run(self) -> None:
        """Watch for changes to the configured custom object.

        This method is intended to be run in a separate thread.  It will run
        forever, adding any custom object changes to the associated queue.
        """
        while True:
            stream = kubernetes.watch.Watch().stream(
                self._api.list_cluster_custom_object,
                "gafaelfawr.lsst.io",
                "v1alpha1",
                self._plural,
            )
            for raw_event in stream:
                event = self._parse_raw_event(raw_event)
                if event:
                    self._queue.put(event)

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
            event_type = WatchEventType(raw_event["type"])
            name = raw_event["object"]["metadata"]["name"]
            namespace = raw_event["object"]["metadata"]["namespace"]
            return WatchEvent(
                event_type=event_type, name=name, namespace=namespace
            )
        except KeyError:
            return None
