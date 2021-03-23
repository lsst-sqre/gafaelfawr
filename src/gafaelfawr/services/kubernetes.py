"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from typing import TYPE_CHECKING

from gafaelfawr.config import KubernetesConfig
from gafaelfawr.exceptions import KubernetesError
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.storage.kubernetes import SecretType

if TYPE_CHECKING:
    from structlog.stdlib import BoundLogger

    from gafaelfawr.config import ServiceSecret
    from gafaelfawr.services.token import TokenService
    from gafaelfawr.storage.kubernetes import KubernetesStorage

__all__ = ["KubernetesService"]


class KubernetesService:
    """Manage Gafaelfawr-related Kubernetes secrets.

    Gafaelfawr supports automatic creation and management of service tokens
    for other Kubernetes services running in the same cluster.  This service
    ensures that all the configured service tokens exist as secrets in the
    appropriate namespace, and that no other secrets exist that are
    labelled with gafaelfawr.lsst.io/token-type=service.
    """

    def __init__(
        self,
        config: KubernetesConfig,
        token_service: TokenService,
        storage: KubernetesStorage,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._token_service = token_service
        self._storage = storage
        self._logger = logger

    async def update_service_secrets(self) -> None:
        """Ensure all configured service secrets exist and are valid.

        Removes any secrets found in Kubernetes with the appropriate label
        that are not part of the configured set.

        Raises
        ------
        gafaelfawr.exceptions.KubernetesError
            On a fatal error that prevents all further processing.  Exceptions
            processing single secrets will be logged but this method will
            attempt to continue processing the remaining secrets.
        """
        wanted = {
            (s.secret_name, s.secret_namespace): s
            for s in self._config.service_secrets
        }
        try:
            secrets = self._storage.list_secrets(SecretType.service)
        except KubernetesError as e:
            # Report this error even though it's unrecoverable and we're
            # re-raising it, since our caller doesn't have the context that
            # the failure was due to listing service token secrets.
            msg = "Unable to list service token secrets"
            self._logger.error(msg, error=str(e))
            raise

        # Remove any secrets that shouldn't exist and update any secrets that
        # already exist.
        for secret in secrets:
            name = secret.metadata.name
            namespace = secret.metadata.namespace
            if (name, namespace) not in wanted:
                self._delete_service_secret(name, namespace)
            else:
                await self._update_service_secret(wanted[(name, namespace)])
                del wanted[(name, namespace)]

        # Create any secrets that we're missing.
        for missing_secret in wanted.values():
            await self._create_service_secret(missing_secret)

    async def _check_service_token(
        self, token: Token, service_secret: ServiceSecret
    ) -> bool:
        """Check whether a service token matches its configuration."""
        token_data = await self._token_service.get_data(token)
        if not token_data:
            return False
        if token_data.username != service_secret.service:
            return False
        if sorted(token_data.scopes) != sorted(service_secret.scopes):
            return False
        return True

    async def _create_service_secret(
        self, service_secret: ServiceSecret
    ) -> None:
        """Create a Kubernetes service secret."""
        token = await self._create_service_token(service_secret)
        name = service_secret.secret_name
        namespace = service_secret.secret_namespace
        try:
            self._storage.create_secret(
                name, namespace, SecretType.service, token
            )
        except KubernetesError as e:
            msg = f"Creating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
        else:
            self._logger.info(
                f"Created {namespace}/{name} secret",
                service=service_secret.service,
                scopes=service_secret.scopes,
            )

    async def _create_service_token(
        self, service_secret: ServiceSecret
    ) -> Token:
        request = AdminTokenRequest(
            username=service_secret.service,
            token_type=TokenType.service,
            scopes=service_secret.scopes,
        )
        return await self._token_service.create_token_from_admin_request(
            request, TokenData.internal_token(), ip_address=None
        )

    def _delete_service_secret(self, name: str, namespace: str) -> None:
        """Delete a Kubernetes service secret."""
        try:
            self._storage.delete_secret(name, namespace, SecretType.service)
        except KubernetesError as e:
            msg = f"Deleting {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
        else:
            self._logger.info(f"Deleted {namespace}/{name} secret")

    async def _update_service_secret(
        self, service_secret: ServiceSecret
    ) -> None:
        """Verify that a service secret is still correct.

        This checks that the service token is still valid and replaces it with
        a new one if not.
        """
        name = service_secret.secret_name
        namespace = service_secret.secret_namespace
        try:
            secret = self._storage.get_secret(
                name, namespace, SecretType.service
            )
        except KubernetesError as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
            return
        if not secret:
            self._logger.error(
                f"Updating {namespace}/{name} failed",
                error=f"Secret {namespace}/{name} not found while updating",
            )
            return

        valid = False
        if "token" in secret.data:
            try:
                token_str = b64decode(secret.data["token"]).decode()
                token = Token.from_str(token_str)
                valid = await self._check_service_token(token, service_secret)
            except Exception:
                valid = False
        if valid:
            return

        # The token is not valid.  Replace the secret.
        token = await self._create_service_token(service_secret)
        try:
            self._storage.patch_secret(name, namespace, token)
        except KubernetesError as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
        else:
            self._logger.info(
                f"Updated {namespace}/{name} secret",
                service=service_secret.service,
                scopes=service_secret.scopes,
            )
