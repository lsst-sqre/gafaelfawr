"""Firestore storage layer for Gafaelfawr."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from functools import wraps

import sentry_sdk
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import firestore
from structlog.stdlib import BoundLogger

from ..constants import (
    GID_MAX,
    GID_MIN,
    UID_BOT_MAX,
    UID_BOT_MIN,
    UID_USER_MIN,
)
from ..exceptions import (
    FirestoreAPIError,
    FirestoreNotInitializedError,
    NoAvailableGidError,
    NoAvailableUidError,
)

_INITIAL_COUNTERS = {
    "uid": UID_USER_MIN,
    "bot-uid": UID_BOT_MIN,
    "gid": GID_MIN,
}
"""Initial values for Firestore ID allocation counters."""

__all__ = ["FirestoreStorage"]


def _convert_exception[**P, T](
    f: Callable[P, Coroutine[None, None, T]],
) -> Callable[P, Coroutine[None, None, T]]:
    """Convert Firestore API exceptions to `FirestoreAPIError`."""

    @wraps(f)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await f(*args, **kwargs)
        except GoogleAPICallError as e:
            raise FirestoreAPIError.from_exception(e) from e

    return wrapper


class FirestoreStorage:
    """Google Firestore storage layer.

    Gafaelfawr supports assigning UIDs and GIDs from Google Firestore rather
    than getting them from LDAP or upstream authentication tokens. This module
    provides the read/write layer and transaction management for that
    storage. It's used from inside a per-process cache.

    This class authenticates to Google on creation, so it should not be
    created fresh for every request.

    Parameters
    ----------
    client
        Firestore client to use.
    logger
        Logger for debug messages and errors.
    """

    def __init__(
        self, client: firestore.AsyncClient, logger: BoundLogger
    ) -> None:
        self._client = client
        self._logger = logger

    @sentry_sdk.trace
    @_convert_exception
    async def get_gid(self, group: str) -> int:
        """Get the GID for a group.

        Retrieve the assigned GID for a group, or assign a new GID to that
        group if the group hasn't been seen before.

        Parameters
        ----------
        group
            Name of the group.

        Returns
        -------
        int
            GID of the group.

        Raises
        ------
        FirestoreNotInitializedError
            Raised if Firestore has not been initialized.
        NoAvailableGidError
            Raised if no more GIDs are available in that range.
        """
        transaction = self._client.transaction()
        group_ref = self._client.collection("groups").document(group)
        counter_ref = self._client.collection("counters").document("gid")
        return await _get_or_assign_gid(
            transaction,
            group_name=group,
            group_ref=group_ref,
            counter_ref=counter_ref,
            logger=self._logger,
        )

    @sentry_sdk.trace
    @_convert_exception
    async def get_uid(self, username: str, *, bot: bool = False) -> int:
        """Get the UID for a user.

        Retrieve the assigned UID for a user, or assign a new UID to that user
        if the user hasn't been seen before.

        Parameters
        ----------
        username
            Name of the user.
        bot
            If set to true, this is a bot user and should use the bot user
            range instead of the regular user range if a UID hasn't already
            been assigned.

        Returns
        -------
        int
            UID of the user.

        Raises
        ------
        FirestoreError
            Raised if some error occurs talking to Firestore.
        FirestoreNotInitializedError
            Raised if Firestore has not been initialized.
        NoAvailableUidError
            Raised if no more UIDs are available in that range.
        """
        transaction = self._client.transaction()
        user_ref = self._client.collection("users").document(username)
        counter = "bot-uid" if bot else "uid"
        counter_ref = self._client.collection("counters").document(counter)
        return await _get_or_assign_uid(
            transaction,
            username=username,
            user_ref=user_ref,
            counter_ref=counter_ref,
            bot=bot,
            logger=self._logger,
        )

    @_convert_exception
    async def initialize(self) -> None:
        """Initialize a Firestore document store for UID/GID assignment.

        This is safe to call on an already-initialized document store and will
        silently do nothing.

        Raises
        ------
        FirestoreError
            Raised if some error occurs talking to Firestore.
        """
        counter_refs = {
            n: self._client.collection("counters").document(n)
            for n in _INITIAL_COUNTERS
        }
        transaction = self._client.transaction()
        await _initialize_in_transaction(
            transaction, counter_refs, self._logger
        )


# firestore.async_transactional cannot annotate class methods because it
# forces the first argument to be the transaction, so these have to be
# stand-alone functions that take all the required parameters as arguments.


@firestore.async_transactional
async def _get_or_assign_gid(
    transaction: firestore.AsyncTransaction,
    *,
    group_name: str,
    group_ref: firestore.AsyncDocumentReference,
    counter_ref: firestore.AsyncDocumentReference,
    logger: BoundLogger,
) -> int:
    """Get or assign a GID for a group within a transaction.

    Parameters
    ----------
    transaction
        The open transaction.
    group_name
        Name of the group, for logging.
    group_ref
        Reference to the group's (possibly nonexistent) GID document.
    counter_ref
        Reference to the document holding the GID counter.
    logger
        Logger for messages.

    Returns
    -------
    int
        GID of the group.

    Raises
    ------
    FirestoreNotInitializedError
        Raised if Firestore has not been initialized.
    NoAvailableGidError
        Raised if no more UIDs are available in that range.
    """
    group = await group_ref.get(transaction=transaction)
    if group.exists:
        return group.get("gid")
    counter = await counter_ref.get(transaction=transaction)
    if not counter.exists:
        msg = "Firestore GID counter not found"
        logger.error(msg)
        raise FirestoreNotInitializedError(msg)
    next_gid = counter.get("next")
    if next_gid >= GID_MAX:
        msg = f"Next GID {next_gid} out of range (>= {GID_MAX})"
        logger.error(msg, group=group_name)
        raise NoAvailableGidError(msg)
    transaction.create(group_ref, {"gid": next_gid})
    transaction.update(counter_ref, {"next": next_gid + 1})
    logger.info("Assigned new GID", group=group_name, gid=next_gid)
    return next_gid


@firestore.async_transactional
async def _get_or_assign_uid(
    transaction: firestore.Transaction,
    *,
    username: str,
    user_ref: firestore.AsyncDocumentReference,
    counter_ref: firestore.AsyncDocumentReference,
    bot: bool,
    logger: BoundLogger,
) -> int:
    """Get or assign a UID for a user within a transaction.

    Parameters
    ----------
    transaction
        The open transaction.
    username
        Username of user, for logging.
    user_ref
        Reference to the user's (possibly nonexistent) UID document.
    counter_ref
        Reference to the document holding the UID counter.
    bot
        If set to true, this is a bot user and should use the bot user
        range instead of the regular user range if a UID hasn't already
        been assigned.
    logger
        Logger for messages.

    Returns
    -------
    int
        UID of the user.

    Raises
    ------
    FirestoreNotInitializedError
        Raised if Firestore has not been initialized.
    NoAvailableUidError
        Raised if no more UIDs are available in that range.
    """
    user = await user_ref.get(transaction=transaction)
    if user.exists:
        return user.get("uid")
    counter = await counter_ref.get(transaction=transaction)
    if not counter.exists:
        msg = "Firestore UID counter not found"
        logger.error(msg)
        raise FirestoreNotInitializedError(msg, username)
    next_uid = counter.get("next")
    if bot and next_uid >= UID_BOT_MAX:
        msg = f"Next bot UID {next_uid} out of range (>= {UID_BOT_MAX})"
        logger.error(msg, user=username)
        raise NoAvailableUidError(msg, username)
    transaction.create(user_ref, {"uid": next_uid})
    transaction.update(counter_ref, {"next": next_uid + 1})
    logger.info("Assigned new UID", user=username, uid=next_uid)
    return next_uid


@firestore.async_transactional
async def _initialize_in_transaction(
    transaction: firestore.Transaction,
    counter_refs: dict[str, firestore.AsyncDocumentReference],
    logger: BoundLogger,
) -> None:
    """Initialize Firestore for UID/GID assignment.

    This sets up the counters documents that track the next-available UID,
    bot UID, and GID.  If they already exist, they're left unchanged.

    Parameters
    ----------
    transaction
        The open transaction.
    counter_refs
        References to the documents holding the counters.
    logger
        Logger for messages.
    """
    # We have to do this in two passes since the Firestore transaction
    # model requires all reads happen before any writes.
    to_create: list[tuple[str, firestore.AsyncDocumentReference]] = []
    for name in _INITIAL_COUNTERS:
        counter_ref = counter_refs[name]
        counter = await counter_ref.get(transaction=transaction)
        if not counter.exists:
            to_create.append((name, counter_ref))
    for name, counter_ref in to_create:
        transaction.create(counter_ref, {"next": _INITIAL_COUNTERS[name]})
        logger.info(f"Initialized Firestore counter for {name}")
