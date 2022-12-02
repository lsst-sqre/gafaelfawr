"""Models for Kubernetes operators."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional, Union

from kubernetes_asyncio.client import (
    V1HTTPIngressPath,
    V1HTTPIngressRuleValue,
    V1IngressBackend,
    V1IngressRule,
    V1IngressServiceBackend,
    V1IngressTLS,
    V1ServiceBackendPort,
)
from pydantic import BaseModel, Extra, Field, validator

from ..util import (
    current_datetime,
    normalize_timedelta,
    to_camel_case,
    validate_exactly_one_of,
)
from .auth import AuthType, Satisfy

__all__ = [
    "GafaelfawrIngress",
    "GafaelfawrIngressConfig",
    "GafaelfawrIngressDelegate",
    "GafaelfawrIngressDelegateInternal",
    "GafaelfawrIngressDelegateNotebook",
    "GafaelfawrIngressMetadata",
    "GafaelfawrIngressPath",
    "GafaelfawrIngressPathBackend",
    "GafaelfawrIngressPathService",
    "GafaelfawrServicePortName",
    "GafaelfawrServicePortNumber",
    "GafaelfawrIngressRule",
    "GafaelfawrIngressRuleHTTP",
    "GafaelfawrIngressScopesAll",
    "GafaelfawrIngressScopesAny",
    "GafaelfawrIngressScopesBase",
    "GafaelfawrIngressSpec",
    "GafaelfawrIngressTLS",
    "GafaelfawrIngressTemplate",
    "GafaelfawrServiceToken",
    "GafaelfawrServiceTokenSpec",
    "KubernetesMetadata",
    "KubernetesResource",
    "KubernetesResourceStatus",
    "PathType",
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


class GafaelfawrIngressDelegateInternal(BaseModel):
    """Configuration for a delegated internal token."""

    service: str
    """The name of the service to which the token is being delegated."""

    scopes: list[str]
    """The requested scopes of the delegated token."""


class GafaelfawrIngressDelegateNotebook(BaseModel):
    """Configuration for a delegated notebook token.

    Notes
    -----
    This model is currently empty and represents an empty dict on the
    Kubernetes side, but it is still an object for parallelism with
    `GafaelfawrIngressDelegateInternal`. It may have parameters for notebook
    tokens in the future.
    """


class GafaelfawrIngressDelegate(BaseModel):
    """Configuration for delegated tokens requested for a service."""

    notebook: Optional[GafaelfawrIngressDelegateNotebook] = None
    """Whether the delegated token requested is a notebook token."""

    internal: Optional[GafaelfawrIngressDelegateInternal] = None
    """Configuration for a delegated internal token."""

    minimum_lifetime: Optional[timedelta] = None
    """The minimum lifetime of the delegated token."""

    _normalize_minimum_lifetime = validator(
        "minimum_lifetime", allow_reuse=True, pre=True
    )(normalize_timedelta)

    _validate_type = validator("internal", always=True, allow_reuse=True)(
        validate_exactly_one_of("notebook", "internal")
    )

    class Config:
        """Pydantic configuration."""

        alias_generator = to_camel_case


class GafaelfawrIngressScopesBase(BaseModel, metaclass=ABCMeta):
    """Base class for specifying the required scopes.

    Required scopes can be specified in one of two ways: a list of scopes that
    must all be present, or a list of scopes where any one of those scopes
    must be present.  This base class represents the common interface with the
    rest of Gafaelfawr.
    """

    @property
    @abstractmethod
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""

    @property
    @abstractmethod
    def scopes(self) -> list[str]:
        """List of scopes."""

    class Config:
        """Pydantic configuration."""

        extra = Extra.forbid


class GafaelfawrIngressScopesAll(GafaelfawrIngressScopesBase):
    """Represents scopes where all scopes are required."""

    all: list[str]
    """All of these scopes are required to allow access."""

    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ALL

    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return self.all


class GafaelfawrIngressScopesAny(GafaelfawrIngressScopesBase):
    """Represents scopes where any scope is sufficient."""

    any: list[str]
    """Any of these scopes is sufficient to allow access."""

    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ANY

    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return self.any


class GafaelfawrIngressConfig(BaseModel):
    """Configuration settings for an ingress using Gafaelfawr for auth."""

    base_url: str
    """The base URL for Gafaelfawr URLs in Ingress annotations."""

    scopes: GafaelfawrIngressScopesAll | GafaelfawrIngressScopesAny
    """The scopes to require for access."""

    auth_type: Optional[AuthType] = None
    """Auth type of challenge for 401 responses."""

    login_redirect: bool = False
    """Whether to redirect unauthenticated users to the login flow."""

    replace_403: bool = False
    """Whether to generate a custom error response for 403 errors."""

    delegate: Optional[GafaelfawrIngressDelegate] = None
    """Details of the requested delegated token, if any."""

    class Config:
        """Pydantic configuration."""

        alias_generator = to_camel_case


class GafaelfawrIngressMetadata(BaseModel):
    """Metadata used to create an ``Ingress`` object."""

    name: str
    """Name of the ingress."""

    annotations: Dict[str, str] = Field(default_factory=dict)
    """Annotations to add to the ingress."""

    labels: Optional[Dict[str, str]] = None
    """Labels to add to the ingress."""


class PathType(Enum):
    """Matching types for paths in ingress rules."""

    Exact = "Exact"
    """The path must match exactly."""

    ImplementationSpecific = "ImplementationSpecific"
    """Use this for regex matches with NGINX."""

    Prefix = "Prefix"
    """Use longest prefix matching to find the correct rule."""


class GafaelfawrServicePortName(BaseModel):
    """Port for a service."""

    name: str
    """Port name."""

    class Config:
        """Pydantic configuration."""

        extra = Extra.forbid

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(name=self.name)


class GafaelfawrServicePortNumber(BaseModel):
    """Port for a service."""

    number: int
    """Port number."""

    class Config:
        """Pydantic configuration."""

        extra = Extra.forbid

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(number=self.number)


class GafaelfawrIngressPathService(BaseModel):
    """Service that serves a given path."""

    name: str
    """Name of the service to which to route the request."""

    port: GafaelfawrServicePortName | GafaelfawrServicePortNumber
    """Port to which to route the request."""

    def to_kubernetes(self) -> V1IngressServiceBackend:
        """Convert to the Kubernetes API object."""
        return V1IngressServiceBackend(
            name=self.name, port=self.port.to_kubernetes()
        )


class GafaelfawrIngressPathBackend(BaseModel):
    """Backend that serves a given path."""

    service: GafaelfawrIngressPathService
    """The underlying service that serves this path."""

    def to_kubernetes(self) -> V1IngressBackend:
        """Convert to the Kubernetes API object."""
        return V1IngressBackend(service=self.service.to_kubernetes())


class GafaelfawrIngressPath(BaseModel):
    """A path routing rule for an ingress."""

    path: str
    """Path match, interpreted based on the ``path_type`` field."""

    path_type: PathType
    """How to match the specified path against the URL."""

    backend: GafaelfawrIngressPathBackend
    """Backend that serves this path."""

    class Config:
        """Pydantic configuration."""

        alias_generator = to_camel_case

    def to_kubernetes(self) -> V1HTTPIngressPath:
        """Convert to the Kubernetes API object."""
        return V1HTTPIngressPath(
            path=self.path,
            path_type=self.path_type.value,
            backend=self.backend.to_kubernetes(),
        )


class GafaelfawrIngressRuleHTTP(BaseModel):
    """Routing rules for HTTP access."""

    paths: list[GafaelfawrIngressPath]
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1HTTPIngressRuleValue:
        """Convert to the Kubernetes API object."""
        return V1HTTPIngressRuleValue(
            paths=[p.to_kubernetes() for p in self.paths]
        )


class GafaelfawrIngressRule(BaseModel):
    """A routing rule for an ingress."""

    host: str
    """Hostname to which to attach the rule."""

    http: GafaelfawrIngressRuleHTTP
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1IngressRule:
        """Convert to the Kubernetes API object."""
        return V1IngressRule(host=self.host, http=self.http.to_kubernetes())


class GafaelfawrIngressTLS(BaseModel):
    """A TLS certificate rule for an ingress."""

    hosts: list[str]
    """The hosts to which this certificate applies.

    These should match the host parameters to the path rules."""

    secret_name: str
    """The name of the secret containing the TLS certificate."""

    class Config:
        """Pydantic configuration."""

        alias_generator = to_camel_case

    def to_kubernetes(self) -> V1IngressTLS:
        """Convert to the Kubernetes API object."""
        return V1IngressTLS(hosts=self.hosts, secret_name=self.secret_name)


class GafaelfawrIngressSpec(BaseModel):
    """Template for ``spec`` portion of ``Ingress`` resource."""

    rules: list[GafaelfawrIngressRule]
    """The ingress routing rules."""

    tls: Optional[list[GafaelfawrIngressTLS]] = None
    """The TLS certificate rules."""


class GafaelfawrIngressTemplate(BaseModel):
    """Template for ``Ingress`` created from ``GafaelfawrIngress`` resource."""

    metadata: GafaelfawrIngressMetadata
    """Template for the metadata of the created ``Ingress``."""

    spec: GafaelfawrIngressSpec
    """Template for the ``spec`` of the created ``Ingress``."""


class GafaelfawrIngress(KubernetesResource):
    """Representation of a ``GafaelfawrIngress`` resource."""

    config: GafaelfawrIngressConfig
    """Configuration settings for Gafaelfawr for this ingress."""

    template: GafaelfawrIngressTemplate
    """Template for the ``Ingress`` resource to create."""


class GafaelfawrServiceTokenSpec(BaseModel):
    """Holds the ``spec`` section of a ``GafaelfawrServiceToken`` resource."""

    service: str
    """The username of the service token."""

    scopes: list[str]
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
