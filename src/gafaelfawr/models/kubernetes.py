"""Models for Kubernetes operators."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Mapping, Union

from ..exceptions import KubernetesObjectError
from ..util import current_datetime

__all__ = [
    "GafaelfawrServiceToken",
    "KubernetesResource",
    "KubernetesResourceStatus",
    "StatusReason",
]


@dataclass
class KubernetesResource:
    """A Kubernetes resource being processed by an operator.

    Intended for use as a parent class for all operator resources.  This holds
    generic data that is used by parts of the Kubernetes plumbing.  It should
    be extended with resource-specific data.
    """

    name: str
    """The name of the object."""

    namespace: str
    """The namespace in which the object is located."""

    annotations: Dict[str, str]
    """The annotations of the object."""

    labels: Dict[str, str]
    """The labels of the object."""

    uid: str
    """The UID of the object."""

    generation: int
    """The generation of the object."""


@dataclass
class GafaelfawrServiceToken(KubernetesResource):
    """The key data from a GafaelfawrServiceToken Kubernetes object."""

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
class KubernetesResourceStatus:
    """Represents the processing status of a Kubernetes resource.

    This is returned as the result of the Kopf_ operator handlers for changes
    to a Kubernetes resource.  Kopf will then put this information into the
    ``status`` field of the GafaelfawrServiceToken object.
    """

    message: str
    """Message associated with the transition."""

    generation: int
    """Generation of the resource that was processed."""

    reason: StatusReason
    """Reason for the status update."""

    timestamp: datetime = field(default_factory=current_datetime)
    """Time of the status event."""

    @classmethod
    def failure(
        cls, resource: KubernetesResource, message: str
    ) -> KubernetesResourceStatus:
        """Create a status object for a failure.

        Parameters
        ----------
        service_token : `KubernetesResource`
            The object being processed.
        message : `str`
            The error message for the failure.
        """
        return cls(
            message=message,
            generation=resource.generation,
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
            "type": "ResourceCreated",
        }
