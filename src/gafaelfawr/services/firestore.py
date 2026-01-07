"""UID/GID assignment using Firestore."""

import sentry_sdk
from structlog.stdlib import BoundLogger

from ..cache import IdCache
from ..storage.firestore import FirestoreStorage
from ..util import is_bot_user

__all__ = ["FirestoreService"]


class FirestoreService:
    """Manage UID and GID assignments using Firestore.

    This is a thin layer over `~gafaelfawr.storage.firestore.FirestoreStorage`
    and the UID/GID cache that integrates cache management with the underlying
    storage.  It is primarily intended to be used by the user information
    service rather than called directly.

    Parameters
    ----------
    uid_cache
        The underlying UID and GID cache and locks.
    gid_cache
        The underlying UID and GID cache and locks.
    storage
        The underlying Firestore storage for UID and GID assignment, if
        Firestore was configured.
    logger
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

    @sentry_sdk.trace
    async def get_gid(self, group: str, *, uncached: bool = False) -> int:
        """Get the GID for a given group from Firestore.

        Parameters
        ----------
        group
            Group of the user.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        int
            GID of the user.

        Raises
        ------
        NoAvailableGidError
            No more GIDs are available in that range.
        """
        if uncached:
            return await self._storage.get_gid(group)
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

    @sentry_sdk.trace
    async def get_uid(self, username: str, *, uncached: bool = False) -> int:
        """Get the UID for a given user.

        Parameters
        ----------
        username
            Username of the user.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        int
            UID of the user.

        Raises
        ------
        NoAvailableUidError
            No more UIDs are available in that range.
        """
        bot = is_bot_user(username)
        if uncached:
            return await self._storage.get_uid(username, bot=bot)
        uid = self._uid_cache.get(username)
        if uid:
            return uid
        async with self._uid_cache.lock():
            uid = self._uid_cache.get(username)
            if uid:
                return uid
            bot = is_bot_user(username)
            uid = await self._storage.get_uid(username, bot=bot)
            self._uid_cache.store(username, uid)
            return uid
