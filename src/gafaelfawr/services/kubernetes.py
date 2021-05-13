"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from queue import Queue
from threading import Thread
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
from gafaelfawr.storage.kubernetes import (
    KubernetesWatcher,
    StatusReason,
    WatchEventType,
)

if TYPE_CHECKING:
    from typing import Optional

    from kubernetes.client import V1Secret
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

    Gafaelfawr supports automatic creation and management of service tokens
    for other Kubernetes services running in the same cluster.  This service
    ensures that all the configured service tokens exist as secrets in the
    appropriate namespace, and that no other secrets exist that are
    labelled with gafaelfawr.lsst.io/token-type=service.
    """

    def __init__(
        self,
        token_service: TokenService,
        storage: KubernetesStorage,
        logger: BoundLogger,
    ) -> None:
        self._token_service = token_service
        self._storage = storage
        self._logger = logger

    def create_service_token_watcher(self) -> Queue[WatchEvent]:
        """Create a Kubernetes watcher for a custom object.

        The watcher will run forever in a background thread.

        Returns
        -------
        queue : `queue.Queue`
            The queue into which the custom object events will be put.
        """
        queue: Queue[WatchEvent] = Queue(50)
        watcher = KubernetesWatcher(
            "gafaelfawrservicetokens", queue, self._logger
        )
        Thread(target=watcher.run, daemon=True).start()
        return queue

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
            service_tokens = self._storage.list_service_tokens()
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
            await self._update_secret_for_service_token(service_token)

    async def update_service_tokens_from_queue(
        self, queue: Queue[WatchEvent], exit_on_empty: bool = False
    ) -> None:
        """Process GafaelfawrServiceToken changes from a queue.

        Normally this method runs forever.  Set ``exit_on_empty`` to `False`
        to stop when the queue is empty.

        Parameters
        ----------
        queue : `queue.Queue`
            Queue of changes to GafaelfawrServiceToken objects to process.
        exit_on_empty : `bool`, optional
            If set to `True` (the default is `False`), exit when the queue
            is empty.
        """
        while not (queue.empty() and exit_on_empty):
            event = queue.get()
            if event.event_type == WatchEventType.DELETED:
                continue
            service_token = self._storage.get_service_token(
                event.name, event.namespace
            )
            if service_token:
                await self._update_secret_for_service_token(service_token)
            queue.task_done()

    async def _create_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> Token:
        request = AdminTokenRequest(
            username=parent.service,
            token_type=TokenType.service,
            scopes=parent.scopes,
        )
        return await self._token_service.create_token_from_admin_request(
            request, TokenData.internal_token(), ip_address=None
        )

    async def _secret_needs_update(
        self, parent: GafaelfawrServiceToken, secret: Optional[V1Secret]
    ) -> bool:
        """Check if a secret needs to be updated."""
        if not secret:
            return True
        okay = (
            secret.metadata.annotations == parent.annotations
            and secret.metadata.labels == parent.labels
            and "token" in secret.data
        )
        if not okay:
            return True

        # Check the token contained in the secret.
        try:
            token_str = b64decode(secret.data["token"]).decode()
            token = Token.from_str(token_str)
            okay = await self._service_token_valid(token, parent)
        except Exception:
            okay = False

        return not okay

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
        self, parent: GafaelfawrServiceToken
    ) -> None:
        """Verify that a service secret is still correct.

        This checks that the contained service token is still valid and the
        secret metadata matches the GafaelfawrServiceToken metadata and
        replaces it with a new one if not.
        """
        name = parent.name
        namespace = parent.namespace
        try:
            secret = self._storage.get_secret_for_service_token(parent)
        except KubernetesError as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
            return
        if not await self._secret_needs_update(parent, secret):
            return

        # Something is either different or invalid.  Replace the secret.
        try:
            token = await self._create_service_token(parent)
            if secret:
                self._storage.replace_secret_for_service_token(parent, token)
            else:
                self._storage.create_secret_for_service_token(parent, token)
        except (KubernetesError, PermissionDeniedError, ValidationError) as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
            try:
                self._storage.update_service_token_status(
                    parent,
                    reason=StatusReason.Failed,
                    message=str(e),
                    success=False,
                )
            except KubernetesError as e:
                msg = f"Updating status of {namespace}/{name} failed"
                self._logger.error(msg, error=str(e))
        else:
            if secret:
                msg = f"Updated {namespace}/{name} secret"
            else:
                msg = f"Created {namespace}/{name} secret"
            self._logger.info(
                msg, service=parent.service, scopes=parent.scopes
            )
