"""Models for Kubernetes operators."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Self, override

from kubernetes_asyncio.client import (
    V1HTTPIngressPath,
    V1HTTPIngressRuleValue,
    V1IngressBackend,
    V1IngressRule,
    V1IngressServiceBackend,
    V1IngressTLS,
    V1ServiceBackendPort,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel
from safir.datetime import current_datetime
from safir.pydantic import (
    SecondsTimedelta,
    UtcDatetime,
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


class KubernetesMetadata(BaseModel):
    """The metadata section of a Kubernetes resource."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    """The name of the object."""

    namespace: str
    """The namespace in which the object is located."""

    annotations: dict[str, str] | None = None
    """The annotations of the object."""

    labels: dict[str, str] | None = None
    """The labels of the object."""

    uid: str
    """The UID of the object."""

    generation: int
    """The generation of the object."""

    @field_validator("annotations")
    @classmethod
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


class KubernetesResource(BaseModel):
    """A Kubernetes resource being processed by an operator.

    Intended for use as a parent class for all operator resources.  This holds
    generic data that is used by parts of the Kubernetes plumbing.  It should
    be extended with resource-specific data.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    metadata: KubernetesMetadata
    """Metadata section of the Kubernetes resource."""

    @property
    def key(self) -> str:
        """A unique key for this custom object."""
        return f"{self.metadata.namespace}/{self.metadata.name}"


class GafaelfawrIngressDelegateInternal(BaseModel):
    """Configuration for a delegated internal token."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class GafaelfawrIngressDelegate(BaseModel):
    """Configuration for delegated tokens requested for a service."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    notebook: GafaelfawrIngressDelegateNotebook | None = None
    """Whether the delegated token requested is a notebook token."""

    internal: GafaelfawrIngressDelegateInternal | None = None
    """Configuration for a delegated internal token."""

    minimum_lifetime: SecondsTimedelta | None = None
    """The minimum lifetime of the delegated token."""

    use_authorization: bool = False
    """Whether to put the delegated token in the ``Authorization`` header."""

    _validate_type = model_validator(mode="after")(
        validate_exactly_one_of("notebook", "internal")
    )

    def to_auth_query(self) -> list[tuple[str, str]]:
        """Generate the query parameters corresponding to this delegation.

        Returns
        -------
        list of tuple
            List of query parameters corresponding to this ingress delegation
            configuration to pass to the Gafaelfawr ``/ingress/auth`` route.
        """
        query = []
        if self.notebook:
            query.append(("notebook", "true"))
        elif self.internal:
            service = self.internal.service
            query.append(("delegate_to", service))
            scopes = self.internal.scopes
            query.extend(("delegate_scope", s) for s in scopes)
        if self.minimum_lifetime:
            minimum_lifetime = self.minimum_lifetime
            minimum_str = str(int(minimum_lifetime.total_seconds()))
            query.append(("minimum_lifetime", minimum_str))
        if self.use_authorization:
            query.append(("use_authorization", "true"))
        return query


class GafaelfawrIngressScopesBase(BaseModel, metaclass=ABCMeta):
    """Base class for specifying the required scopes.

    Required scopes can be specified in one of two ways: a list of scopes that
    must all be present, or a list of scopes where any one of those scopes
    must be present.  This base class represents the common interface with the
    rest of Gafaelfawr.
    """

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

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


class GafaelfawrIngressScopesAll(GafaelfawrIngressScopesBase):
    """Represents scopes where all scopes are required."""

    all: list[str]
    """All of these scopes are required to allow access."""

    @override
    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ALL

    @override
    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return self.all

    @override
    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return False


class GafaelfawrIngressScopesAny(GafaelfawrIngressScopesBase):
    """Represents scopes where any scope is sufficient."""

    any: list[str]
    """Any of these scopes is sufficient to allow access."""

    @override
    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ANY

    @override
    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return self.any

    @override
    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return False


class GafaelfawrIngressScopesAnonymous(GafaelfawrIngressScopesBase):
    """Represents anonymous access."""

    anonymous: Literal[True]
    """Mark this ingress as anonymous."""

    @override
    @property
    def satisfy(self) -> Satisfy:
        """The authorization satisfy strategy."""
        return Satisfy.ANY

    @override
    @property
    def scopes(self) -> list[str]:
        """List of scopes."""
        return []

    @override
    def is_anonymous(self) -> bool:
        """Whether this ingress is anonymous."""
        return True


class GafaelfawrIngressConfig(BaseModel):
    """Configuration settings for an ingress using Gafaelfawr for auth."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    allow_cookies: bool = True
    """Whether to allow cookie authentication to this ingress."""

    allow_options: bool = False
    """Whether to allow non-CORS preflight ``OPTIONS`` requests."""

    auth_cache_duration: str | None = None
    """How long NGINX should cache the Gafaelfawr authorization response."""

    auth_type: AuthType | None = None
    """Auth type of challenge for 401 responses."""

    base_url: str | None = None
    """Obsolete field, now ignored."""

    delegate: GafaelfawrIngressDelegate | None = None
    """Details of the requested delegated token, if any."""

    login_redirect: bool = False
    """Whether to redirect unauthenticated users to the login flow."""

    only_services: list[str] | None = None
    """If non-empty, restrict to tokens issued by one of the services."""

    replace_403: bool = False
    """Obsolete field, now ignored."""

    scopes: (
        GafaelfawrIngressScopesAll
        | GafaelfawrIngressScopesAny
        | GafaelfawrIngressScopesAnonymous
    )
    """The scopes to require for access."""

    service: str | None = None
    """Name of the service this ingress is for."""

    user_domain: bool = False
    """Restrict access to the user matching the last hostname component.

    Used for per-user hostnames, such as the per-user domain names for
    JupyterLab pods.
    """

    username: str | None = None
    """Restrict access to the given user."""

    @model_validator(mode="after")
    def _validate_conflicts(self) -> Self:
        """Check for conflicts between settings.

        Notes
        -----
        Ideally, all of these checks would be represented in the Kubernetes
        schema to make them much less likely, but my JSON schema validation
        skill is not up to the task.
        """
        if self.auth_type == AuthType.Basic and self.login_redirect:
            msg = "authType: basic has no effect when loginRedirect is set"
            raise ValueError(msg)

        if not self.allow_cookies and self.login_redirect:
            msg = "loginRedirect incompatible with allowCookies: false"
            raise ValueError(msg)

        if self.scopes and self.scopes.is_anonymous():
            fields = (
                "allow_options",
                "auth_cache_duration",
                "auth_type",
                "delegate",
                "login_redirect",
                "only_services",
                "replace_403",
                "user_domain",
                "username",
            )
            for snake_name in fields:
                if getattr(self, snake_name, None):
                    camel_name = to_camel_case(snake_name)
                    msg = f"{camel_name} has no effect for anonymous ingresses"
                    raise ValueError(msg)
            if not self.allow_cookies:
                msg = "allowCookies has no effect for anonymous ingresses"
                raise ValueError(msg)

        if self.service and self.delegate and self.delegate.internal:
            if self.service != self.delegate.internal.service:
                msg = "service must match delegate.internal.service"
                raise ValueError(msg)

        return self

    def to_auth_query(self) -> list[tuple[str, str]]:
        """Generate the query corresponding to this ingress configuration.

        Returns
        -------
        list of tuple
            List of query parameters corresponding to this ingress
            configuration to pass to the Gafaelfawr ``/ingress/auth`` route.
        """
        query = []
        if not self.allow_cookies:
            query.append(("allow_cookies", "false"))
        if self.allow_options:
            query.append(("allow_options", "true"))
        if self.auth_type:
            query.append(("auth_type", self.auth_type.value))
        if self.delegate:
            query.extend(self.delegate.to_auth_query())
        query.extend(("only_service", s) for s in self.only_services or [])
        query.extend(("scope", s) for s in self.scopes.scopes)
        if self.scopes.satisfy != Satisfy.ALL:
            query.append(("satisfy", self.scopes.satisfy.value))
        if self.service:
            query.append(("service", self.service))
        if self.user_domain:
            query.append(("user_domain", "true"))
        if self.username:
            query.append(("username", self.username))
        return query


class GafaelfawrIngressMetadata(BaseModel):
    """Metadata used to create an ``Ingress`` object."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    """Name of the ingress."""

    annotations: dict[str, str] = Field(default_factory=dict)
    """Annotations to add to the ingress."""

    labels: dict[str, str] | None = None
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

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    name: str
    """Port name."""

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(name=self.name)


class GafaelfawrServicePortNumber(BaseModel):
    """Port for a service."""

    model_config = ConfigDict(
        alias_generator=to_camel, extra="forbid", populate_by_name=True
    )

    number: int
    """Port number."""

    def to_kubernetes(self) -> V1ServiceBackendPort:
        """Convert to the Kubernetes API object."""
        return V1ServiceBackendPort(number=self.number)


class GafaelfawrIngressPathService(BaseModel):
    """Service that serves a given path."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    service: GafaelfawrIngressPathService
    """The underlying service that serves this path."""

    def to_kubernetes(self) -> V1IngressBackend:
        """Convert to the Kubernetes API object."""
        return V1IngressBackend(service=self.service.to_kubernetes())


class GafaelfawrIngressPath(BaseModel):
    """A path routing rule for an ingress."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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


class GafaelfawrIngressRuleHTTP(BaseModel):
    """Routing rules for HTTP access."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    paths: list[GafaelfawrIngressPath]
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1HTTPIngressRuleValue:
        """Convert to the Kubernetes API object."""
        return V1HTTPIngressRuleValue(
            paths=[p.to_kubernetes() for p in self.paths]
        )


class GafaelfawrIngressRule(BaseModel):
    """A routing rule for an ingress."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    host: str
    """Hostname to which to attach the rule."""

    http: GafaelfawrIngressRuleHTTP
    """Path routing rules for this host."""

    def to_kubernetes(self) -> V1IngressRule:
        """Convert to the Kubernetes API object."""
        return V1IngressRule(host=self.host, http=self.http.to_kubernetes())


class GafaelfawrIngressTLS(BaseModel):
    """A TLS certificate rule for an ingress."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    hosts: list[str]
    """The hosts to which this certificate applies.

    These should match the host parameters to the path rules."""

    secret_name: str
    """The name of the secret containing the TLS certificate."""

    def to_kubernetes(self) -> V1IngressTLS:
        """Convert to the Kubernetes API object."""
        return V1IngressTLS(hosts=self.hosts, secret_name=self.secret_name)


class GafaelfawrIngressSpec(BaseModel):
    """Template for ``spec`` portion of ``Ingress`` resource."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    rules: list[GafaelfawrIngressRule]
    """The ingress routing rules."""

    tls: list[GafaelfawrIngressTLS] | None = None
    """The TLS certificate rules."""


class GafaelfawrIngressTemplate(BaseModel):
    """Template for ``Ingress`` created from ``GafaelfawrIngress`` resource."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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
    to a Kubernetes resource. Kopf will then put this information into the
    ``status`` field of the GafaelfawrServiceToken object.
    """

    message: str
    """Message associated with the transition."""

    generation: int
    """Generation of the resource that was processed."""

    reason: StatusReason
    """Reason for the status update."""

    timestamp: UtcDatetime = field(default_factory=current_datetime)
    """Time of the status event."""

    @classmethod
    def failure(cls, resource: KubernetesResource, message: str) -> Self:
        """Create a status object for a failure.

        Parameters
        ----------
        service_token
            Object being processed.
        message
            Error message for the failure.

        Returns
        -------
        KubernetesResourceStatus
            Corresponding status object.
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
