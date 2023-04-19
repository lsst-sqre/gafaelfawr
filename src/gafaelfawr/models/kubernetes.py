"""Models for Kubernetes operators."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Literal, Optional, Self

from kubernetes_asyncio.client import (
    V1HTTPIngressPath,
    V1HTTPIngressRuleValue,
    V1IngressBackend,
    V1IngressRule,
    V1IngressServiceBackend,
    V1IngressTLS,
    V1ServiceBackendPort,
)
from pydantic import Extra, Field, root_validator, validator
from safir.datetime import current_datetime
from safir.pydantic import (
    CamelCaseModel,
    to_camel_case,
    validate_exactly_one_of,
)

from ..util import normalize_timedelta
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
    "GafaelfawrIngressRule",
    "GafaelfawrIngressRuleHTTP",
    "GafaelfawrIngressScopesAll",
    "GafaelfawrIngressScopesAnonymous",
    "GafaelfawrIngressScopesAny",
    "GafaelfawrIngressScopesBase",
    "GafaelfawrIngressSpec",
    "GafaelfawrIngressTLS",
    "GafaelfawrIngressTemplate",
    "GafaelfawrServicePortName",
    "GafaelfawrServicePortNumber",
    "GafaelfawrServiceToken",
    "GafaelfawrServiceTokenSpec",
    "KubernetesMetadata",
    "KubernetesResource",
    "KubernetesResourceStatus",
    "PathType",
    "StatusReason",
]


class KubernetesMetadata(CamelCaseModel):
    """The metadata section of a Kubernetes resource."""

    name: str
    """The name of the object."""

    namespace: str
    """The namespace in which the object is located."""

    annotations: Optional[dict[str, str]] = None
    """The annotations of the object."""

    labels: Optional[dict[str, str]] = None
    """The labels of the object."""

    uid: str
    """The UID of the object."""

    generation: int
    """The generation of the object."""

    @validator("annotations")
    def _filter_kopf_annotations(
        cls, v: dict[str, str] | None
    ) -> dict[str, str] | None:
        """Filter out the annotations added by Kopf."""
        if not v:
            return v
        return {
            key: value
            for key, value in v.items()
            if not key.startswith("kopf.zalando.org/")
        }


class KubernetesResource(CamelCaseModel):
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


class GafaelfawrIngressDelegateInternal(CamelCaseModel):
    """Configuration for a delegated internal token."""

    service: str
    """The name of the service to which the token is being delegated."""

    scopes: list[str]
    """The requested scopes of the delegated token."""


class GafaelfawrIngressDelegateNotebook(CamelCaseModel):
    """Configuration for a delegated notebook token.

    Notes
    -----
    This model is currently empty and represents an empty dict on the
    Kubernetes side, but it is still an object for parallelism with
    `GafaelfawrIngressDelegateInternal`. It may have parameters for notebook
    tokens in the future.
    """


class GafaelfawrIngressDelegate(CamelCaseModel):
    """Configuration for delegated tokens requested for a service."""

    notebook: Optional[GafaelfawrIngressDelegateNotebook] = None
    """Whether the delegated token requested is a notebook token."""

    internal: Optional[GafaelfawrIngressDelegateInternal] = None
    """Configuration for a delegated internal token."""

    minimum_lifetime: Optional[timedelta] = None
    """The minimum lifetime of the delegated token."""

    use_authorization: bool = False
    """Whether to put the delegated token in the ``Authorization`` header."""

    _normalize_minimum_lifetime = validator(
        "minimum_lifetime", allow_reuse=True, pre=True
    )(normalize_timedelta)

    _validate_type = root_validator(allow_reuse=True)(
        validate_exactly_one_of("notebook", "internal")
    )


class GafaelfawrIngressScopesBase(CamelCaseModel, metaclass=ABCMeta):
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

    @abstractmethod
    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""

    class Config:
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

    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return False


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

    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return False


class GafaelfawrIngressScopesAnonymous(GafaelfawrIngressScopesBase):
    """Represents anonymous access."""

    anonymous: Literal[True]
    """Mark this ingress as anonymous."""

    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ANY

    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return []

    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return True


class GafaelfawrIngressConfig(CamelCaseModel):
    """Configuration settings for an ingress using Gafaelfawr for auth."""

    base_url: str
    """The base URL for Gafaelfawr URLs in Ingress annotations."""

    auth_type: Optional[AuthType] = None
    """Auth type of challenge for 401 responses."""

    delegate: Optional[GafaelfawrIngressDelegate] = None
    """Details of the requested delegated token, if any."""

    login_redirect: bool = False
    """Whether to redirect unauthenticated users to the login flow."""

    replace_403: bool = False
    """Whether to generate a custom error response for 403 errors."""

    scopes: (
        GafaelfawrIngressScopesAll
        | GafaelfawrIngressScopesAny
        | GafaelfawrIngressScopesAnonymous
    )
    """The scopes to require for access."""

    @root_validator
    def _validate_conflicts(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Check for conflicts between settings.

        Notes
        -----
        Ideally, all of these checks would be represented in the Kubernetes
        schema to make them much less likely, but my JSON schema validation
        skill is not up to the task.
        """
        if values.get("auth_type") == AuthType.Basic:
            if values.get("login_redirect"):
                msg = "authType: basic has no effect when loginRedirect is set"
                raise ValueError(msg)

        scopes = values.get("scopes")
        if scopes and scopes.is_anonymous():
            fields = ("auth_type", "delegate", "login_redirect", "replace_403")
            for snake_name in fields:
                if values.get(snake_name):
                    camel_name = to_camel_case(snake_name)
                    msg = f"{camel_name} has no effect for anonymous ingresses"
                    raise ValueError(msg)

        return values


class GafaelfawrIngressMetadata(CamelCaseModel):
    """Metadata used to create an ``Ingress`` object."""

    name: str
    """Name of the ingress."""

    annotations: dict[str, str] = Field(default_factory=dict)
    """Annotations to add to the ingress."""

    labels: Optional[dict[str, str]] = None
    """Labels to add to the ingress."""


class PathType(Enum):
    """Matching types for paths in ingress rules."""

    Exact = "Exact"
    """The path must match exactly."""

    ImplementationSpecific = "ImplementationSpecific"
    """Use this for regex matches with NGINX."""

    Prefix = "Prefix"
    """Use longest prefix matching to find the correct rule."""


class GafaelfawrServicePortName(CamelCaseModel):
    """Port for a service."""

    name: str
    """Port name."""

    class Config:
        extra = Extra.forbid

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(name=self.name)


class GafaelfawrServicePortNumber(CamelCaseModel):
    """Port for a service."""

    number: int
    """Port number."""

    class Config:
        extra = Extra.forbid

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(number=self.number)


class GafaelfawrIngressPathService(CamelCaseModel):
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


class GafaelfawrIngressPathBackend(CamelCaseModel):
    """Backend that serves a given path."""

    service: GafaelfawrIngressPathService
    """The underlying service that serves this path."""

    def to_kubernetes(self) -> V1IngressBackend:
        """Convert to the Kubernetes API object."""
        return V1IngressBackend(service=self.service.to_kubernetes())


class GafaelfawrIngressPath(CamelCaseModel):
    """A path routing rule for an ingress."""

    path: str
    """Path match, interpreted based on the ``path_type`` field."""

    path_type: PathType
    """How to match the specified path against the URL."""

    backend: GafaelfawrIngressPathBackend
    """Backend that serves this path."""

    def to_kubernetes(self) -> V1HTTPIngressPath:
        """Convert to the Kubernetes API object."""
        return V1HTTPIngressPath(
            path=self.path,
            path_type=self.path_type.value,
            backend=self.backend.to_kubernetes(),
        )


class GafaelfawrIngressRuleHTTP(CamelCaseModel):
    """Routing rules for HTTP access."""

    paths: list[GafaelfawrIngressPath]
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1HTTPIngressRuleValue:
        """Convert to the Kubernetes API object."""
        return V1HTTPIngressRuleValue(
            paths=[p.to_kubernetes() for p in self.paths]
        )


class GafaelfawrIngressRule(CamelCaseModel):
    """A routing rule for an ingress."""

    host: str
    """Hostname to which to attach the rule."""

    http: GafaelfawrIngressRuleHTTP
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1IngressRule:
        """Convert to the Kubernetes API object."""
        return V1IngressRule(host=self.host, http=self.http.to_kubernetes())


class GafaelfawrIngressTLS(CamelCaseModel):
    """A TLS certificate rule for an ingress."""

    hosts: list[str]
    """The hosts to which this certificate applies.

    These should match the host parameters to the path rules."""

    secret_name: str
    """The name of the secret containing the TLS certificate."""

    def to_kubernetes(self) -> V1IngressTLS:
        """Convert to the Kubernetes API object."""
        return V1IngressTLS(hosts=self.hosts, secret_name=self.secret_name)


class GafaelfawrIngressSpec(CamelCaseModel):
    """Template for ``spec`` portion of ``Ingress`` resource."""

    rules: list[GafaelfawrIngressRule]
    """The ingress routing rules."""

    tls: Optional[list[GafaelfawrIngressTLS]] = None
    """The TLS certificate rules."""


class GafaelfawrIngressTemplate(CamelCaseModel):
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


class GafaelfawrServiceTokenSpec(CamelCaseModel):
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
    def failure(cls, resource: KubernetesResource, message: str) -> Self:
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

    def to_dict(self) -> dict[str, str | int]:
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
