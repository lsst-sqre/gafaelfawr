"""UID/GID assignment using Firestore."""

from __future__ import annotations

import re

from structlog.stdlib import BoundLogger

from ..cache import IdCache
from ..constants import BOT_USERNAME_REGEX
from ..storage.firestore import FirestoreStorage

__all__ = ["FirestoreService"]


class FirestoreService:
    """Manage UID and GID assignments using Firestore.

    This is a thin layer over `~gafaelfawr.storage.firestore.FirestoreStorage`
    and the UID/GID cache that integrates cache management with the underlying
    storage.  It is primarily intended to be used by the user information
    service rather than called directly.

    Parameters
    ----------
    uid_cache : `gafaelfawr.cache.IdCache`
        The underlying UID and GID cache and locks.
    gid_cache : `gafaelfawr.cache.IdCache`
        The underlying UID and GID cache and locks.
    storage : `gafaelfawr.storage.firestore.FirestoreStorage`, optional
        The underlying Firestore storage for UID and GID assignment, if
        Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        uid_cache: IdCache,
        gid_cache: IdCache,
        storage: FirestoreStorage,
        logger: BoundLogger,
    ) -> None:
        self._uid_cache = uid_cache
        self._gid_cache = gid_cache
        self._storage = storage
        self._logger = logger

    async def get_gid(self, group: str) -> int:
        """Get the GID for a given user from Firestore.

        Parameters
        ----------
        group : `str`
            Group of the user.

        Returns
        -------
        gid : `int`
            GID of the user.

        Raises
        ------
        gafaelfawr.exceptions.NoAvailableGidError
            No more GIDs are available in that range.
        """
        gid = self._gid_cache.get(group)
        if gid:
            return gid
        async with self._gid_cache.lock():
            gid = self._gid_cache.get(group)
            if gid:
                return gid
            gid = await self._storage.get_gid(group)
            self._gid_cache.store(group, gid)
            return gid

    async def get_uid(self, username: str) -> int:
        """Get the UID for a given user.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        uid : `int`
            UID of the user.

        Raises
        ------
        gafaelfawr.exceptions.NoAvailableUidError
            No more UIDs are available in that range.
        """
        uid = self._uid_cache.get(username)
        if uid:
            return uid
        async with self._uid_cache.lock():
            uid = self._uid_cache.get(username)
            if uid:
                return uid
            bot = re.search(BOT_USERNAME_REGEX, username) is not None
            uid = await self._storage.get_uid(username, bot=bot)
            self._uid_cache.store(username, uid)
            return uid
