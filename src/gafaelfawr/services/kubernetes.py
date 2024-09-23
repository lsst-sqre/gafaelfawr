"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from urllib.parse import urlencode

from kubernetes_asyncio.client import (
    V1Ingress,
    V1IngressSpec,
    V1ObjectMeta,
    V1Secret,
)
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..config import Config
from ..constants import NGINX_RESPONSE_HEADERS, NGINX_SNIPPET
from ..exceptions import (
    InputValidationError,
    InvalidScopesError,
    KubernetesError,
    PermissionDeniedError,
)
from ..models.kubernetes import (
    GafaelfawrIngress,
    GafaelfawrIngressScopesBase,
    GafaelfawrServiceToken,
    KubernetesResourceStatus,
)
from ..models.token import AdminTokenRequest, Token, TokenData, TokenType
from ..storage.kubernetes import (
    KubernetesIngressStorage,
    KubernetesTokenStorage,
)
from .token import TokenService

__all__ = ["KubernetesIngressService", "KubernetesTokenService"]


class KubernetesIngressService:
    """Manage ``Ingress`` resources with Gafaelfawr annotations.

    The ``GafaelfawrIngress`` custom resource defines a template for an
    ``Ingress`` resource that will be created by this service, with the
    special annotations and configuration for Gafaelfawr added.  It is
    intended to be driven by Kopf_ and a thin layer of Kopf event handlers.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    storage
        Storage layer for the Kubernetes cluster.
    logger
        Logger to report issues.
    """

    def __init__(
        self,
        config: Config,
        storage: KubernetesIngressStorage,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._storage = storage
        self._logger = logger

    async def update(
        self, parent: GafaelfawrIngress
    ) -> KubernetesResourceStatus | None:
        """Handle a change to a ``GafaelfawrIngress``.

        Parameters
        ----------
        parent
            Contents of the ``GafaelfawrIngress`` Kubernetes object.

        Returns
        -------
        KubernetesResourceStatus or None
            Information to put into the ``status`` portion of the object, or
            `None` if no status update is required.

        Raises
        ------
        KubernetesError
            Raised if some error occurred while trying to write to Kubernetes.
        """
        try:
            self._validate_scopes(parent.config.scopes)
        except InputValidationError as e:
            msg = f"Invalid GafaelfawrIngress {parent.key}"
            self._logger.exception(msg, error=str(e))
            return KubernetesResourceStatus.failure(parent, str(e))
        new_ingress = self._build_kubernetes_ingress(parent)
        name = new_ingress.metadata.name
        namespace = new_ingress.metadata.namespace
        try:
            old_ingress = await self._storage.get_ingress(name, namespace)
        except KubernetesError as e:
            msg = f"Cannot retrieve Ingress {namespace}/{name}"
            self._logger.exception(msg, error=str(e))
            raise
        return await self._update_ingress(old_ingress, new_ingress, parent)

    def _build_annotations(self, ingress: GafaelfawrIngress) -> dict[str, str]:
        """Build annotations for an ``Ingress``."""
        auth_url = (
            str(self._config.base_internal_url).rstrip("/")
            + "/ingress/auth?"
            + urlencode(ingress.config.to_auth_query())
        )
        base_url = ingress.config.base_url or str(self._config.base_url)
        snippet_key = "nginx.ingress.kubernetes.io/configuration-snippet"
        snippet = ingress.template.metadata.annotations.get(snippet_key, "")
        if snippet and not snippet.endswith("\n"):
            snippet += "\n"
        snippet += NGINX_SNIPPET
        headers = ",".join(NGINX_RESPONSE_HEADERS)
        annotations = {
            **ingress.template.metadata.annotations,
            "nginx.ingress.kubernetes.io/auth-method": "GET",
            "nginx.ingress.kubernetes.io/auth-response-headers": headers,
            "nginx.ingress.kubernetes.io/auth-url": auth_url,
            snippet_key: snippet,
        }
        if ingress.config.auth_cache_duration:
            annotations["nginx.ingress.kubernetes.io/auth-cache-key"] = (
                "$http_cookie$http_authorization"
            )
            annotations["nginx.ingress.kubernetes.io/auth-cache-duration"] = (
                f"200 202 401 {ingress.config.auth_cache_duration}"
            )
        if ingress.config.login_redirect:
            url = base_url.rstrip("/") + "/login"
            annotations["nginx.ingress.kubernetes.io/auth-signin"] = url

        return annotations

    def _build_anonymous_annotations(
        self, ingress: GafaelfawrIngress
    ) -> dict[str, str]:
        """Build annotations for an anonymous ``Ingress``."""
        base_url = str(self._config.base_internal_url).rstrip("/")
        auth_url = f"{base_url}/ingress/anonymous"
        headers = ",".join(NGINX_RESPONSE_HEADERS)
        return {
            **ingress.template.metadata.annotations,
            "nginx.ingress.kubernetes.io/auth-method": "GET",
            "nginx.ingress.kubernetes.io/auth-response-headers": headers,
            "nginx.ingress.kubernetes.io/auth-url": auth_url,
        }

    def _build_kubernetes_ingress(
        self, ingress: GafaelfawrIngress
    ) -> V1Ingress:
        """Construct a Kubernetes ``Ingress`` from a ``GafaelfawrIngress``."""
        if ingress.config.scopes.is_anonymous():
            annotations = self._build_anonymous_annotations(ingress)
        else:
            annotations = self._build_annotations(ingress)

        tls = None
        if ingress.template.spec.tls:
            tls = [t.to_kubernetes() for t in ingress.template.spec.tls]
        return V1Ingress(
            metadata=V1ObjectMeta(
                name=ingress.template.metadata.name,
                namespace=ingress.metadata.namespace,
                annotations=annotations,
                labels=ingress.template.metadata.labels,
            ),
            spec=V1IngressSpec(
                ingress_class_name="nginx",
                rules=[r.to_kubernetes() for r in ingress.template.spec.rules],
                tls=tls,
            ),
        )

    def _ingress_needs_update(self, old: V1Ingress, new: V1Ingress) -> bool:
        """Determine whether an existing ``Ingress`` needs an update.

        Compare an existing ``Ingress`` resource with one generated from a
        ``GafaelfawrIngress`` and see if it needs an update.
        """
        return (
            old.metadata.annotations != new.metadata.annotations
            or old.metadata.labels != new.metadata.labels
            or old.spec.rules != new.spec.rules
            or old.spec.tls != new.spec.tls
        )

    async def _update_ingress(
        self,
        old_ingress: V1Ingress | None,
        new_ingress: V1Ingress,
        parent: GafaelfawrIngress,
    ) -> KubernetesResourceStatus | None:
        """Update the ``Ingress`` object in Kubernetes if necessary.

        Parameters
        ----------
        old_ingress
            The current existing ingress, or `None` if it doesn't exist.
        new_ingress
            The new ingress generated from the ``GafaelfawrIngress`` object.
        parent
            The owning ``GafaelfawrIngress`` object.

        Returns
        -------
        KubernetesResourceStatus or None
            Information to put into the ``status`` portion of the object, or
            `None` if no status update is required.

        Raises
        ------
        KubernetesError
            Some error occurred while trying to write to Kubernetes.
        """
        if not old_ingress:
            status = await self._storage.create_ingress(new_ingress, parent)
        elif self._ingress_needs_update(old_ingress, new_ingress):
            status = await self._storage.replace_ingress(new_ingress, parent)
        else:
            return None

        # If we performed an update, log that fact and return the new status
        # for the GafaelfawrIngress.
        key = f"{new_ingress.metadata.namespace}/{new_ingress.metadata.name}"
        if old_ingress:
            msg = f"Updated {key} ingress from {parent.key} GafaelfawrIngress"
        else:
            msg = f"Created {key} ingress from {parent.key} GafaelfawrIngress"
        self._logger.info(msg)
        return status

    def _validate_scopes(self, scopes: GafaelfawrIngressScopesBase) -> None:
        """Check that the requested scopes are valid.

        Arguments
        ---------
        scopes
            Requested scopes.

        Raises
        ------
        InvalidScopesError
            Raised if any of the requested scopes are not valid scopes.
        """
        for scope in scopes.scopes:
            if scope not in self._config.known_scopes:
                raise InvalidScopesError(f"Unknown scope {scope}")


class KubernetesTokenService:
    """Manage Gafaelfawr service tokens stored in Kubernetes secrets.

    The ``GafaelfawrServiceToken`` custom resource defines a Gafaelfawr
    service token that should be created and managed as a Kubernetes secret.
    This class provides the core of the Kubernetes operator that does this.
    It is intended to be driven via Kopf_ and a thin layer of Kopf event
    handlers.

    Notes
    -----
    This service unfortunately has to be aware of the database session since
    it has to manage transactions around token issuance.  The token service is
    transaction-unaware because it otherwise runs in the context of a request
    handler, where we implement one transaction per request.

    Parameters
    ----------
    token_service
        Token management service.
    storage
        Storage layer for the Kubernetes cluster.
    session
        Database session, used for transaction management.
    logger
        Logger to report issues.
    """

    def __init__(
        self,
        *,
        token_service: TokenService,
        storage: KubernetesTokenStorage,
        session: async_scoped_session,
        logger: BoundLogger,
    ) -> None:
        self._token_service = token_service
        self._storage = storage
        self._session = session
        self._logger = logger

    async def update(
        self, name: str, namespace: str, service_token: GafaelfawrServiceToken
    ) -> KubernetesResourceStatus | None:
        """Handle a change to a ``GafaelfawrServiceToken``.

        Parameters
        ----------
        name
            Name of the ``GafaelfawrServiceToken`` Kubernetes object.
        namespace
            Namespace of the ``GafaelfawrServiceToken`` Kubernetes object.
        body
            Contents of the ``GafaelfawrServiceToken`` Kubernetes object.

        Returns
        -------
        KubernetesResourceStatus or None
            Information to put into the ``status`` portion of the object, or
            `None` if no status update is required.

        Raises
        ------
        KubernetesError
            Some error occurred while trying to write to Kubernetes.
        """
        try:
            secret = await self._storage.get_secret(service_token)
        except KubernetesError as e:
            msg = f"Cannot retrieve Secret {service_token.key}"
            self._logger.exception(msg, error=str(e))
            raise
        return await self._update_secret(service_token, secret)

    async def _create_token(self, parent: GafaelfawrServiceToken) -> Token:
        """Create a service token for a ``GafaelfawrServiceToken``."""
        request = AdminTokenRequest(
            username=parent.spec.service,
            token_type=TokenType.service,
            scopes=parent.spec.scopes,
        )
        async with self._session.begin():
            return await self._token_service.create_token_from_admin_request(
                request, TokenData.internal_token(), ip_address=None
            )

    async def _is_token_valid(
        self, token: Token, parent: GafaelfawrServiceToken
    ) -> bool:
        """Check whether a service token matches its configuration."""
        token_data = await self._token_service.get_data(token)
        if not token_data:
            return False
        if token_data.username != parent.spec.service:
            return False
        return sorted(token_data.scopes) == sorted(parent.spec.scopes)

    async def _secret_needs_update(
        self, parent: GafaelfawrServiceToken, secret: V1Secret | None
    ) -> bool:
        """Check if a secret needs to be updated."""
        if not secret:
            return True
        if not secret.data or "token" not in secret.data:
            return True
        try:
            token_str = b64decode(secret.data["token"]).decode()
            token = Token.from_str(token_str)
            return not await self._is_token_valid(token, parent)
        except Exception:
            return True

    def _secret_needs_metadata_update(
        self, parent: GafaelfawrServiceToken, secret: V1Secret
    ) -> bool:
        """Check if a secret needs its metadata updated."""
        return not (
            secret.metadata.annotations == parent.metadata.annotations
            and secret.metadata.labels == parent.metadata.labels
        )

    async def _update_secret(
        self, parent: GafaelfawrServiceToken, secret: V1Secret
    ) -> KubernetesResourceStatus | None:
        """Update a service token stored in Kubernetes if necessary.

        This checks that the service token stored in the ``Secret`` is still
        valid and the ``Secret`` metadata matches the
        ``GafaelfawrServiceToken``, and updates the ``Secret`` as needed.

        Returns
        -------
        KubernetesResourceStatus or None
            Information to put into the ``status`` field of the
            ``GafaelfawrServiceToken`` Kubernetes object, or `None` if no
            status update is required.
        """
        storage = self._storage
        if not await self._secret_needs_update(parent, secret):
            if self._secret_needs_metadata_update(parent, secret):
                try:
                    await storage.update_secret_metadata(parent)
                except KubernetesError as e:
                    msg = f"Updating Secret {parent.key} failed"
                    self._logger.exception(msg, error=str(e))
            return None

        # Something is either different or invalid.  Replace the secret.
        try:
            token = await self._create_token(parent)
            if secret:
                status = await storage.replace_secret(parent, token)
            else:
                status = await storage.create_secret(parent, token)
        except (
            KubernetesError,
            PermissionDeniedError,
            InputValidationError,
        ) as e:
            msg = f"Updating Secret {parent.key} failed"
            self._logger.exception(msg, error=str(e))
            return KubernetesResourceStatus.failure(parent, str(e))
        else:
            if secret:
                msg = f"Updated {parent.key} secret"
            else:
                msg = f"Created {parent.key} secret"
            self._logger.info(
                msg, service=parent.spec.service, scopes=parent.spec.scopes
            )
            return status
