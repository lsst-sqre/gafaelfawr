"""LDAP lookups for user information."""

from __future__ import annotations

from typing import List, Optional

from structlog.stdlib import BoundLogger

from ..cache import LDAPCache
from ..models.ldap import LDAPUserData
from ..models.token import TokenGroup
from ..storage.ldap import LDAPStorage

__all__ = ["LDAPService"]


class LDAPService:
    """Perform LDAP lookups for user information.

    This collects all of the LDAP search logic.  It is primarily intended to
    be used by the user information service rather than called directly.

    Parameters
    ----------
    ldap : `gafaelfawr.storage.ldap.LDAPStorage`
        The underlying LDAP query layer.
    group_cache : `gafaelfawr.cache.LDAPCache`
        Cache of user group information (including GIDs).
    group_name_cache : `gafaelfawr.cache.LDAPCache`
        Cache of group names.
    user_cache : `gafaelfawr.cache.LDAPCache`
        Cache of user information from LDAP.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        ldap: LDAPStorage,
        group_cache: LDAPCache[List[TokenGroup]],
        group_name_cache: LDAPCache[List[str]],
        user_cache: LDAPCache[LDAPUserData],
        logger: BoundLogger,
    ) -> None:
        self._ldap = ldap
        self._group_cache = group_cache
        self._group_name_cache = group_name_cache
        self._user_cache = user_cache
        self._logger = logger

    async def get_group_names(self, username: str) -> List[str]:
        """Get the names of user groups from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        groups : List[`str`]
            The names of the user's groups according to LDAP.
        """
        groups = self._group_name_cache.get(username)
        if groups:
            return groups
        async with await self._group_name_cache.lock(username):
            groups = self._group_name_cache.get(username)
            if groups:
                return groups
            groups = await self._ldap.get_group_names(username)
            self._group_name_cache.store(username, groups)
            return groups

    async def get_groups(self, username: str) -> List[TokenGroup]:
        """Get user group membership and GIDs from LDAP.

        Parameters
        ----------
        username : `str`
            Username for which to get information.

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            Groups of the user.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            An error occurred when retrieving user information from LDAP.
        """
        groups = self._group_cache.get(username)
        if groups:
            return groups
        async with await self._group_cache.lock(username):
            groups = self._group_cache.get(username)
            if groups:
                return groups
            groups = await self._ldap.get_groups(username)
            self._group_cache.store(username, groups)
            return groups

    async def get_data(self, username: str) -> LDAPUserData:
        """Get configured data from LDAP.

        Returns all data configured to be retrieved from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        data : `gafaelfawr.models.ldap.LDAPUserData`
            The retrieved data.
        """
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

    async def get_username(self, sub: str) -> Optional[str]:
        """Determine a user's username from LDAP.

        Parameters
        ----------
        sub : `str`
            ``sub`` claim from the OpenID Connect ID token.

        Returns
        -------
        username : `str` or `None`
            Corresponding username from LDAP, or `None` if LDAP was not
            configured to get usernames.
        """
        return await self._ldap.get_username(sub)
