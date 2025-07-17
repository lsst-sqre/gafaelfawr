"""LDAP lookups for user information."""

from __future__ import annotations

import sentry_sdk
from structlog.stdlib import BoundLogger

from ..cache import LDAPCache
from ..models.ldap import LDAPUserData
from ..models.userinfo import Group
from ..storage.ldap import LDAPStorage

__all__ = ["LDAPService"]


class LDAPService:
    """Perform LDAP lookups for user information.

    This collects all of the LDAP search logic.  It is primarily intended to
    be used by the user information service rather than called directly.

    Parameters
    ----------
    ldap
        The underlying LDAP query layer.
    group_cache
        Cache of user group information (including GIDs).
    group_name_cache
        Cache of group names.
    user_cache
        Cache of user information from LDAP.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        ldap: LDAPStorage,
        group_cache: LDAPCache[list[Group]],
        group_name_cache: LDAPCache[list[str]],
        user_cache: LDAPCache[LDAPUserData],
        logger: BoundLogger,
    ) -> None:
        self._ldap = ldap
        self._group_cache = group_cache
        self._group_name_cache = group_name_cache
        self._user_cache = user_cache
        self._logger = logger

    @sentry_sdk.trace
    async def get_group_names(
        self, username: str, gid: int | None, *, uncached: bool = False
    ) -> list[str]:
        """Get the names of user groups from LDAP.

        Parameters
        ----------
        username
            Username of the user.
        gid
            Primary GID if set.  If not `None`, search for the group with this
            GID and add it to the user's group memberships.  This handles LDAP
            configurations where the user's primary group is represented only
            by their GID and not their group memberships.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        list of str
            The names of the user's groups according to LDAP.
        """
        if uncached:
            return await self._ldap.get_group_names(username, gid)
        groups = self._group_name_cache.get(username)
        if groups is not None:
            return groups
        async with await self._group_name_cache.lock(username):
            groups = self._group_name_cache.get(username)
            if groups is not None:
                return groups
            groups = await self._ldap.get_group_names(username, gid)
            self._group_name_cache.store(username, groups)
            return groups

    @sentry_sdk.trace
    async def get_groups(
        self, username: str, gid: int | None, *, uncached: bool = False
    ) -> list[Group]:
        """Get user group membership and GIDs from LDAP.

        Parameters
        ----------
        username
            Username for which to get information.
        gid
            Primary GID if set.  If not `None`, the user's groups will be
            checked for this GID.  If it's not found, search for the group
            with this GID and add it to the user's group memberships.  This
            handles LDAP configurations where the user's primary group is
            represented only by their GID and not their group memberships.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        list of Group
            Groups of the user.

        Raises
        ------
        LDAPError
            An error occurred when retrieving user information from LDAP.
        """
        if uncached:
            return await self._ldap.get_groups(username, gid)
        groups = self._group_cache.get(username)
        if groups is not None:
            return groups
        async with await self._group_cache.lock(username):
            groups = self._group_cache.get(username)
            if groups is not None:
                return groups
            groups = await self._ldap.get_groups(username, gid)
            self._group_cache.store(username, groups)
            return groups

    @sentry_sdk.trace
    async def get_data(
        self,
        username: str,
        *,
        uncached: bool = False,
    ) -> LDAPUserData:
        """Get configured data from LDAP.

        Returns all data configured to be retrieved from LDAP.

        Parameters
        ----------
        username
            Username of the user.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        LDAPUserData
            The retrieved data.
        """
        if uncached:
            return await self._ldap.get_data(username)
        data = self._user_cache.get(username)
        if data:
            return data
        async with await self._user_cache.lock(username):
            data = self._user_cache.get(username)
            if data:
                return data
            data = await self._ldap.get_data(username)
            self._user_cache.store(username, data)
            return data

    async def invalidate_cache(self, username: str) -> None:
        """Invalidate the cache for a given user.

        Parameters
        ----------
        username
            Username of the user.
        """
        if self._group_name_cache.get(username) is not None:
            async with await self._group_name_cache.lock(username):
                self._group_name_cache.invalidate(username)
        if self._group_cache.get(username) is not None:
            async with await self._group_cache.lock(username):
                self._group_cache.invalidate(username)
        if self._user_cache.get(username) is not None:
            async with await self._user_cache.lock(username):
                self._user_cache.invalidate(username)
