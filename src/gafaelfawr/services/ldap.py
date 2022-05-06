"""LDAP lookups for user information."""

from __future__ import annotations

from typing import List, Optional

from structlog.stdlib import BoundLogger

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
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(self, ldap: LDAPStorage, logger: BoundLogger) -> None:
        self._ldap = ldap
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
        async with self._ldap.connect() as conn:
            return await conn.get_group_names(username)

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
        async with self._ldap.connect() as conn:
            return await conn.get_groups(username)

    async def get_uid(self, username: str) -> Optional[int]:
        """Determine a user's numeric UID from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        username : `str` or `None`
            Corresponding numeric UID from LDAP, or `None` if LDAP was not
            configured to get UIDs.
        """
        async with self._ldap.connect() as conn:
            return await conn.get_uid(username)

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
        async with self._ldap.connect() as conn:
            return await conn.get_username(sub)
