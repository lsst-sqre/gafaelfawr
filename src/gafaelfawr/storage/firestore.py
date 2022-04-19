"""Firestore storage layer for Gafaelfawr."""

from __future__ import annotations

from typing import Dict, List, Tuple

from google.cloud import firestore
from structlog.stdlib import BoundLogger

from ..config import FirestoreConfig
from ..constants import (
    GID_MAX,
    GID_MIN,
    UID_BOT_MAX,
    UID_BOT_MIN,
    UID_USER_MIN,
)
from ..exceptions import (
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


class FirestoreStorage:
    """Google Firestore storage layer.

    Gafaelfawr supports assigning UIDs and GIDs from Google Firestore rather
    than getting them from LDAP or upstream authentication tokens.  This
    module provides the read/write layer and transaction management for that
    storage.  It's used from inside a per-process cache.

    Parameters
    ----------
    config : `gafaelfawr.config.FirestoreConfig`
        Configuration for Google Firestore.
    logger : `structlog.stdlib.BoundLogger`
        Logger for debug messages and errors.
    """

    def __init__(self, config: FirestoreConfig, logger: BoundLogger) -> None:
        self._config = config
        self._logger = logger
        self._db = firestore.AsyncClient(project=config.project)

    async def get_gid(self, group: str) -> int:
        """Get the GID for a group.

        Retrieve the assigned GID for a group, or assign a new GID to that
        group if the group hasn't been seen before.

        Parameters
        ----------
        group : `str`
            Name of the group.

        Returns
        -------
        gid : `int`
            GID of the group.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreNotInitializedError
            Firestore has not been initialized.
        gafaelfawr.exceptions.NoAvailableGidError
            No more GIDs are available in that range.
        """
        transaction = self._db.transaction()
        group_ref = self._db.collection("groups").document(group)
        counter_ref = self._db.collection("counters").document("gid")
        return await _get_or_assign_gid(transaction, group_ref, counter_ref)

    async def get_uid(self, username: str, bot: bool = False) -> int:
        """Get the UID for a user.

        Retrieve the assigned UID for a user, or assign a new UID to that user
        if the user hasn't been seen before.

        Parameters
        ----------
        username : `str`
            Name of the user.
        bot : `bool`, optional
            If set to true, this is a bot user and should use the bot user
            range instead of the regular user range if a UID hasn't already
            been assigned.

        Returns
        -------
        uid : `int`
            UID of the user.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreNotInitializedError
            Firestore has not been initialized.
        gafaelfawr.exceptions.NoAvailableUidError
            No more UIDs are available in that range.
        """
        transaction = self._db.transaction()
        user_ref = self._db.collection("users").document(username)
        counter_name = "bot-uid" if bot else "uid"
        counter_ref = self._db.collection("counters").document(counter_name)
        return await _get_or_assign_uid(
            transaction, user_ref, counter_ref, bot
        )

    async def initialize(self) -> None:
        """Initialize a Firestore document store for UID/GID assignment.

        This is safe to call on an already-initialized document store and will
        silently do nothing.
        """
        counter_refs = {
            n: self._db.collection("counters").document(n)
            for n in _INITIAL_COUNTERS
        }
        transaction = self._db.transaction()
        await _initialize_in_transaction(transaction, counter_refs)


# firestore.async_transactional cannot annotate class methods because it
# forces the first argument to be the transaction, so these have to be
# stand-alone functions that take all the required parameters as arguments.


@firestore.async_transactional
async def _get_or_assign_gid(
    transaction: firestore.AsyncTransaction,
    group_ref: firestore.AsyncDocumentReference,
    counter_ref: firestore.AsyncDocumentReference,
) -> int:
    """Get or assign a GID for a group within a transaction.

    Parameters
    ----------
    transaction : `google.cloud.firestore.Transaction`
        The open transaction.
    user_ref : `google.cloud.firestore.AsyncDocumentReference`
        Reference to the group's (possibly nonexistent) GID document.
    counter_ref : `google.cloud.firestore.AsyncDocumentReference`
        Reference to the document holding the GID counter.

    Returns
    -------
    gid : `int`
        GID of the group.

    Raises
    ------
    gafaelfawr.exceptions.FirestoreNotInitializedError
        Firestore has not been initialized.
    gafaelfawr.exceptions.NoAvailableGidError
        No more UIDs are available in that range.
    """
    group = await group_ref.get(transaction=transaction)
    if group.exists:
        return group["gid"]
    counter = await counter_ref.get(transaction=transaction)
    if not counter.exists:
        raise FirestoreNotInitializedError("Firestore GID counter not found")
    next_gid = counter["next"]
    if next_gid >= GID_MAX:
        msg = f"Next GID {next_gid} out of range (>= {GID_MAX}"
        raise NoAvailableGidError(msg)
    transaction.create(group_ref, {"gid": next_gid})
    transaction.update(counter_ref, {"next": next_gid + 1})
    return next_gid


@firestore.async_transactional
async def _get_or_assign_uid(
    transaction: firestore.Transaction,
    user_ref: firestore.AsyncDocumentReference,
    counter_ref: firestore.AsyncDocumentReference,
    bot: bool = False,
) -> int:
    """Get or assign a UID for a user within a transaction.

    Parameters
    ----------
    transaction : `google.cloud.firestore.Transaction`
        The open transaction.
    user_ref : `google.cloud.firestore.AsyncDocumentReference`
        Reference to the user's (possibly nonexistent) UID document.
    counter_ref : `google.cloud.firestore.AsyncDocumentReference`
        Reference to the document holding the UID counter.
    bot : `bool`, optional
        If set to true, this is a bot user and should use the bot user
        range instead of the regular user range if a UID hasn't already
        been assigned.

    Returns
    -------
    uid : `int`
        UID of the user.

    Raises
    ------
    gafaelfawr.exceptions.FirestoreNotInitializedError
        Firestore has not been initialized.
    gafaelfawr.exceptions.NoAvailableUidError
        No more UIDs are available in that range.
    """
    user = await user_ref.get(transaction=transaction)
    if user.exists:
        return user["uid"]
    counter = await counter_ref.get(transaction=transaction)
    if not counter.exists:
        raise FirestoreNotInitializedError("Firestore UID counter not found")
    next_uid = counter["next"]
    if bot and next_uid >= UID_BOT_MAX:
        msg = f"Next bot UID {next_uid} out of range (>= {UID_BOT_MAX}"
        raise NoAvailableUidError(msg)
    transaction.create(user_ref, {"uid": next_uid})
    transaction.update(counter_ref, {"next": next_uid + 1})
    return next_uid


@firestore.async_transactional
async def _initialize_in_transaction(
    transaction: firestore.Transaction,
    counter_refs: Dict[str, firestore.AsyncDocumentReference],
) -> None:
    """Initialize Firestore for UID/GID assignment.

    This sets up the counters documents that track the next-available UID,
    bot UID, and GID.  If they already exist, they're left unchanged.

    Parameters
    ----------
    transaction : `google.cloud.firestore.Transaction`
        The open transaction.
    counter_refs : Dict[str, `google.cloud.firestore.AsyncDocumentReference`]
        References to the documents holding the counters.
    """
    # We have to do this in two passes since the Firestore transaction
    # model requires all reads happen before any writes.
    to_create: List[Tuple[str, firestore.AsyncDocumentReference]] = []
    for name in _INITIAL_COUNTERS:
        counter_ref = counter_refs[name]
        counter = await counter_ref.get(transaction=transaction)
        if not counter.exists:
            to_create.append((name, counter_ref))
    for name, counter_ref in to_create:
        transaction.create(counter_ref, {"next": _INITIAL_COUNTERS[name]})
