"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from typing import TYPE_CHECKING

from gafaelfawr.exceptions import (
    KubernetesError,
    PermissionDeniedError,
    ValidationError,
)
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.storage.kubernetes import StatusReason, WatchEventType

if TYPE_CHECKING:
    from asyncio import Queue
    from typing import Dict, Optional

    from kubernetes_asyncio.client import V1Secret
    from sqlalchemy.ext.asyncio import AsyncSession
    from structlog.stdlib import BoundLogger

    from gafaelfawr.services.token import TokenService
    from gafaelfawr.storage.kubernetes import (
        GafaelfawrServiceToken,
        KubernetesStorage,
        WatchEvent,
    )

__all__ = ["KubernetesService"]


class KubernetesService:
    """Manage Gafaelfawr-related Kubernetes secrets.

    The GafaelfawrServiceToken custom resource defines a Gafaelfawr service
    token that should be created and managed as a Kubernetes secret.  This
    object provides two mechanisms to update those Secrets from the custom
    objects: a full pass that ensures all Secrets are in sync with their
    parent GafaelfawrServiceToken objects, and a watcher and queue processor
    that watches for changes and updates Secrets as those changes come in.

    Notes
    -----
    Because the GafaelfawrServiceToken is updated with the status of the
    attempt to create its child Secret, processing a GafaelfawrServiceToken
    event will trigger another MODIFIED event of the same object.  If the
    update was successful, this is generally harmless (if a waste of
    resources), since Gafaelfawr will discover that the secret is already
    correct.  But if the creation failed, this could produce an infinite loop
    of updates to the status.

    Work around this by using the generation of the GafaelfawrServiceToken
    custom object.  The generation metadata is incremented by Kubernetes when
    the object changes, but not when the object's status changes.  Only
    attempt to update the token in the Secret if the generation has changed.

    One problem with this approach is that the generation is also not
    incremented if the metadata changes, but we want to copy labels and
    annotations from the parent GafaelfawrServiceToken to the Secret.
    Therefore, even if the generation hasn't changed, retrieve the Secret,
    check if the annotations and labels do not match, and if they do not,
    update them.

    To optimize startup, where we will do one pass through all custom objects
    and then start a watcher, record the current generation of all objects
    found during that initial pass whose secrets are correctly up to date.  We
    will then skip the corresponding events when we receive them when starting
    up the watcher, although will redo the metadata checks.

    This service unfortunately has to be aware of the database session since
    it has to manage transactions around token issuance.  The token service is
    transaction-unaware because it normally runs in the context of a request
    handler, where we implement one transaction per request.

    Parameters
    ----------
    token_service : `gafaelfawr.services.token.TokenService`
        Token management service.
    storage : `gafaelfawr.storage.kubernetes.KubernetesStorage`
        Storage layer for the Kubernetes cluster.
    session : `sqlalchemy.ext.asyncio.AsyncSession`
        Database session, used for transaction management.
    logger : `structlog.stdlib.BoundLogger`
        Logger to report issues.
    """

    def __init__(
        self,
        *,
        token_service: TokenService,
        storage: KubernetesStorage,
        session: AsyncSession,
        logger: BoundLogger,
    ) -> None:
        self._token_service = token_service
        self._storage = storage
        self._session = session
        self._logger = logger
        self._last_generation: Dict[str, int] = {}

    async def update_service_tokens(self) -> None:
        """Ensure all GafaelfawrServiceToken secrets exist and are valid.

        Raises
        ------
        gafaelfawr.exceptions.KubernetesError
            On a fatal error that prevents all further processing.  Exceptions
            processing single secrets will be logged but this method will
            attempt to continue processing the remaining secrets.
        """
        try:
            service_tokens = await self._storage.list_service_tokens()
        except KubernetesError as e:
            # Report this error even though it's unrecoverable and we're
            # re-raising it, since our caller doesn't have the context that
            # the failure was due to listing GafaelfawrServiceToken objects.
            msg = "Unable to list GafaelfawrServiceToken objects"
            self._logger.error(msg, error=str(e))
            raise

        # Process each GafaelfawrServiceToken and create or update its
        # corresponding secret if needed.
        for service_token in service_tokens:
            try:
                secret = await self._storage.get_secret_for_service_token(
                    service_token
                )
            except KubernetesError as e:
                msg = f"Cannot retrieve Secret {service_token.key}"
                self._logger.error(msg, error=str(e))
                return
            await self._update_secret_for_service_token(service_token, secret)

    async def start_watcher(self) -> Queue[WatchEvent]:
        """Start a watcher to process GafaelfawrServiceToken changes.

        The watcher will be started as a background daemon task.

        Returns
        -------
        queue : `asyncio.Queue`
            Queue returning `gafaelfawr.storage.kubernetes.WatchEvent`
            events.

        Notes
        -----
        This is separate from `update_service_tokens_from_queue` for ease of
        testing.
        """
        return await self._storage.create_service_token_watcher()

    async def update_service_tokens_from_queue(
        self, queue: Queue[WatchEvent], exit_on_empty: bool = False
    ) -> None:
        """Process GafaelfawrServiceToken changes from a queue.

        Normally this method runs forever.  Set ``exit_on_empty`` to `False`
        to stop when the queue is empty.

        Parameters
        ----------
        queue : `asyncio.Queue`
            Queue of changes to GafaelfawrServiceToken objects to process.
        exit_on_empty : `bool`, optional
            If set to `True` (the default is `False`), exit when the queue
            is empty.
        """
        storage = self._storage
        while not (exit_on_empty and queue.empty()):
            event = await queue.get()
            if event.event_type == WatchEventType.DELETED:
                if event.key in self._last_generation:
                    del self._last_generation[event.key]
                queue.task_done()
                continue
            service_token = await storage.get_service_token(
                event.name, event.namespace
            )
            if not service_token:
                queue.task_done()
                continue

            # Retrieve the corresponding secret.
            secret = await storage.get_secret_for_service_token(service_token)

            # If the generation matches, we won't try to update the token, but
            # we still need to check the metadata.
            last_generation = self._last_generation.get(event.key)
            if secret and last_generation == event.generation:
                if self._secret_needs_metadata_update(service_token, secret):
                    await storage.update_secret_metadata_for_service_token(
                        service_token
                    )
                    self._logger.info(f"Updated metadata for {event.key}")
                else:
                    self._logger.info(
                        f"Ignoring {str(event)}, generation unchanged"
                    )
                queue.task_done()
                continue

            # Update the last generation even if updating the service
            # token fails so that we don't get into an infinite loop
            # updating the failure status.
            self._last_generation[event.key] = event.generation
            self._logger.info(f"Saw {str(event)}")
            await self._update_secret_for_service_token(service_token, secret)
            queue.task_done()

    async def _create_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> Token:
        request = AdminTokenRequest(
            username=parent.service,
            token_type=TokenType.service,
            scopes=parent.scopes,
        )
        async with self._session.begin():
            return await self._token_service.create_token_from_admin_request(
                request, TokenData.internal_token(), ip_address=None
            )

    async def _secret_needs_update(
        self, parent: GafaelfawrServiceToken, secret: Optional[V1Secret]
    ) -> bool:
        """Check if a secret needs to be updated."""
        if not secret:
            return True
        if "token" not in secret.data:
            return True
        try:
            token_str = b64decode(secret.data["token"]).decode()
            token = Token.from_str(token_str)
            return not await self._service_token_valid(token, parent)
        except Exception:
            return True

    def _secret_needs_metadata_update(
        self, parent: GafaelfawrServiceToken, secret: V1Secret
    ) -> bool:
        """Check if a secret needs its metadata updated."""
        return not (
            secret.metadata.annotations == parent.annotations
            and secret.metadata.labels == parent.labels
        )

    async def _service_token_valid(
        self, token: Token, parent: GafaelfawrServiceToken
    ) -> bool:
        """Check whether a service token matches its configuration."""
        token_data = await self._token_service.get_data(token)
        if not token_data:
            return False
        if token_data.username != parent.service:
            return False
        if sorted(token_data.scopes) != sorted(parent.scopes):
            return False
        return True

    async def _update_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, secret: V1Secret
    ) -> None:
        """Verify that a service secret is still correct.

        This checks that the contained service token is still valid and the
        secret metadata matches the GafaelfawrServiceToken metadata and
        replaces it with a new one if not.
        """
        storage = self._storage
        if not await self._secret_needs_update(parent, secret):
            self._last_generation[parent.key] = parent.generation
            if self._secret_needs_metadata_update(parent, secret):
                try:
                    await storage.update_secret_metadata_for_service_token(
                        parent
                    )
                except KubernetesError as e:
                    msg = f"Updating Secret {parent.key} failed"
                    self._logger.error(msg, error=str(e))
            return

        # Something is either different or invalid.  Replace the secret.
        try:
            token = await self._create_service_token(parent)
            if secret:
                await storage.replace_secret_for_service_token(parent, token)
            else:
                await storage.create_secret_for_service_token(parent, token)
            self._last_generation[parent.key] = parent.generation
        except (KubernetesError, PermissionDeniedError, ValidationError) as e:
            msg = f"Updating Secret {parent.key} failed"
            self._logger.error(msg, error=str(e))
            try:
                await storage.update_service_token_status(
                    parent,
                    reason=StatusReason.Failed,
                    message=str(e),
                    success=False,
                )
            except KubernetesError as e:
                msg = f"Updating status of {parent.key} failed"
                self._logger.error(msg, error=str(e))
        else:
            if secret:
                msg = f"Updated {parent.key} secret"
            else:
                msg = f"Created {parent.key} secret"
            self._logger.info(
                msg, service=parent.service, scopes=parent.scopes
            )
