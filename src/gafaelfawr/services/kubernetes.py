"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from typing import Optional

from kubernetes_asyncio.client import V1Secret
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..exceptions import (
    KubernetesError,
    PermissionDeniedError,
    ValidationError,
)
from ..models.kubernetes import (
    GafaelfawrServiceToken,
    KubernetesResourceStatus,
)
from ..models.token import AdminTokenRequest, Token, TokenData, TokenType
from ..storage.kubernetes import KubernetesTokenStorage
from .token import TokenService

__all__ = ["KubernetesTokenService"]


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
    ) -> Optional[KubernetesResourceStatus]:
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
            self._logger.error(msg, error=str(e))
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
        if sorted(token_data.scopes) != sorted(parent.spec.scopes):
            return False
        return True

    async def _secret_needs_update(
        self, parent: GafaelfawrServiceToken, secret: Optional[V1Secret]
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
    ) -> Optional[KubernetesResourceStatus]:
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
                    self._logger.error(msg, error=str(e))
            return None

        # Something is either different or invalid.  Replace the secret.
        try:
            token = await self._create_token(parent)
            if secret:
                status = await storage.replace_secret(parent, token)
            else:
                status = await storage.create_secret(parent, token)
        except (KubernetesError, PermissionDeniedError, ValidationError) as e:
            msg = f"Updating Secret {parent.key} failed"
            self._logger.error(msg, error=str(e))
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
