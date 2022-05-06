"""UID/GID assignment using Firestore."""

from __future__ import annotations

import re

from structlog.stdlib import BoundLogger

from ..constants import BOT_USERNAME_REGEX
from ..dependencies.cache import IdCache
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
    cache : `gafaelfawr.dependencies.cache.IdCache`
        The underlying UID and GID cache and locks.
    firestore : `gafaelfawr.storage.firestore.FirestoreStorage`, optional
        The underlying Firestore storage for UID and GID assignment, if
        Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self, cache: IdCache, firestore: FirestoreStorage, logger: BoundLogger
    ) -> None:
        self._cache = cache
        self._firestore = firestore
        self._logger = logger

    async def clear_cache(self) -> None:
        """Invalidate the UID/GID cache.

        Used primarily for testing.
        """
        await self._cache.clear()

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
        gid = self._cache.get_gid(group)
        if gid:
            return gid
        async with self._cache.gid_lock:
            gid = self._cache.get_gid(group)
            if gid:
                return gid
            gid = await self._firestore.get_gid(group)
            self._cache.store_gid(group, gid)
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
        uid = self._cache.get_uid(username)
        if uid:
            return uid
        async with self._cache.uid_lock:
            uid = self._cache.get_uid(username)
            if uid:
                return uid
            bot = re.search(BOT_USERNAME_REGEX, username) is not None
            uid = await self._firestore.get_uid(username, bot=bot)
            self._cache.store_uid(username, uid)
            return uid
