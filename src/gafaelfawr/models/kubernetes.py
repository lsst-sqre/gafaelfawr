"""Models for Kubernetes operators."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, validator

from ..util import current_datetime

__all__ = [
    "GafaelfawrServiceToken",
    "GafaelfawrServiceTokenSpec",
    "KubernetesMetadata",
    "KubernetesResource",
    "KubernetesResourceStatus",
    "StatusReason",
]


class KubernetesMetadata(BaseModel):
    """The metadata section of a Kubernetes resource."""

    name: str
    """The name of the object."""

    namespace: str
    """The namespace in which the object is located."""

    annotations: Optional[Dict[str, str]] = None
    """The annotations of the object."""

    labels: Optional[Dict[str, str]] = None
    """The labels of the object."""

    uid: str
    """The UID of the object."""

    generation: int
    """The generation of the object."""

    @validator("annotations")
    def _filter_kopf_annotations(
        cls, v: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        """Filter out the annotations added by Kopf."""
        if not v:
            return v
        return {
            key: value
            for key, value in v.items()
            if not key.startswith("kopf.zalando.org/")
        }


class KubernetesResource(BaseModel):
    """A Kubernetes resource being processed by an operator.

    Intended for use as a parent class for all operator resources.  This holds
    generic data that is used by parts of the Kubernetes plumbing.  It should
    be extended with resource-specific data.
    """

    metadata: KubernetesMetadata
    """Metadata section of the Kubernetes resource."""

    @property
    def key(self) -> str:
        """A unique key for this custom object."""
        return f"{self.metadata.namespace}/{self.metadata.name}"


class GafaelfawrServiceTokenSpec(BaseModel):
    """Holds the ``spec`` section of a ``GafaelfawrServiceToken`` resource."""

    service: str
    """The username of the service token."""

    scopes: List[str]
    """The scopes to grant to the service token."""


class GafaelfawrServiceToken(KubernetesResource):
    """Representation of a ``GafaelfawrServiceToken`` resource."""

    spec: GafaelfawrServiceTokenSpec
    """Specification for the ``Secret`` resource to create."""


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
        service_token
            The object being processed.
        message
            The error message for the failure.

        Returns
        -------
        KubernetesResourceStatus
            The corresponding status object.
        """
        return cls(
            message=message,
            generation=resource.metadata.generation,
            reason=StatusReason.Failed,
        )

    def to_dict(self) -> Dict[str, Union[str, int]]:
        """Convert the status update to a dictionary for Kubernetes.

        Returns
        -------
        dict
            Information to store in the ``status`` field of the Kubernetes
            resource.
        """
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
