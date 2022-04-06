"""LDAP storage layer for Gafaelfawr."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, List, Optional

import bonsai
from bonsai.utils import escape_filter_exp
from structlog.stdlib import BoundLogger

from ..config import LDAPConfig
from ..exceptions import LDAPException
from ..models.token import TokenGroup

__all__ = ["LDAPStorage", "LDAPStorageConnection"]


class LDAPStorage:
    """LDAP storage layer.

    Parameters
    ----------
    config : `gafaelfawr.config.LDAPConfig`
        Configuration for LDAP searches.
    logger : `structlog.stdlib.BoundLogger`
        Logger for debug messages and errors.
    """

    def __init__(self, config: LDAPConfig, logger: BoundLogger) -> None:
        self._config = config
        self._client = bonsai.LDAPClient(config.url)
        if self._config.user_dn and self._config.password:
            self._client.set_credentials(
                "SIMPLE",
                user=self._config.user_dn,
                password=self._config.password,
            )
        self._logger = logger.bind(
            ldap_url=self._config.url,
            ldap_base=self._config.uid_base_dn,
        )

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[LDAPStorageConnection]:
        """Open a connection to the LDAP server.

        Call this in an ``async with`` block to open a connection to the LDAP
        server and perform some searches via methods on the resulting
        `LDAPStorageConnection` class.
        """
        async with self._client.connect(is_async=True) as conn:
            yield LDAPStorageConnection(conn, self._config, self._logger)


class LDAPStorageConnection:
    """Wrapper around a single LDAP connection.

    This is returned by the `gafaelfawr.storage.ldap.LDAPStorage.connect`
    method and provides functions to do the LDAP lookups Gafaelfawr needs.
    Clients should never instantiate this class directly.

    Examples
    --------
    Use this in an ``async with`` block such as:

    .. code-block:: python

       async with ldap_storage.connect() as conn:
           uid = await conn.get_uid(username)
           groups = await conn.get_groups(username)
    """

    def __init__(
        self,
        conn: bonsai.LDAPConnection,
        config: LDAPConfig,
        logger: BoundLogger,
    ) -> None:
        self._conn = conn
        self._config = config
        self._logger = logger

    async def get_username(self, sub: str) -> Optional[str]:
        """Get the username of a user.

        Parameters
        ----------
        sub : `str`
            The ``sub`` claim from a JWT.

        Returns
        -------
        username : `str` or `None`
            The corresponding username from LDAP, or `None` if Gafaelfawr was
            not configured to get the username from LDAP (in which case the
            caller should fall back to other sources of the username).

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            The lookup by ``username_search_attr`` in the LDAP server was not
            valid (connection to the LDAP server failed, attribute not found
            in LDAP, result value not an integer).
        """
        if not self._config.username_base_dn:
            return None

        sub_escaped = escape_filter_exp(sub)
        search = f"(&({self._config.username_search_attr}={sub_escaped}))"
        self._logger.debug(
            "Querying LDAP for username", ldap_search=search, sub=sub
        )

        try:
            results = await self._conn.search(
                self._config.username_base_dn,
                bonsai.LDAPSearchScope.ONE,
                search,
                attrlist=["uid"],
            )
        except bonsai.LDAPError as e:
            self._logger.error(
                "Cannot query LDAP for username",
                error=str(e),
                ldap_search=search,
                sub=sub,
            )
            raise LDAPException("Error querying LDAP for username")

        for result in results:
            try:
                return result["uid"][0]
            except Exception as e:
                self._logger.error(
                    "LDAP username is invalid",
                    error=str(e),
                    ldap_search=search,
                    sub=sub,
                )
                raise LDAPException("Username in LDAP is invalid")

        # Fell through without finding a UID.
        self._logger.error(
            "No username found in LDAP", ldap_search=search, sub=sub
        )
        raise LDAPException("No username found in LDAP")

    async def get_uid(self, username: str) -> Optional[int]:
        """Get the numeric UID of a user.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        uid : `int` or `None`
            The numeric UID of the user from LDAP, or `None` if Gafaelfawr was
            not configured to get the UID from LDAP (in which case the caller
            should fall back to other sources of the UID).

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            The lookup of ``uid_attr`` in the LDAP server was not valid
            (connection to the LDAP server failed, attribute not found in
            LDAP, result value not an integer).
        """
        if not self._config.uid_base_dn:
            return None

        search = f"(&(uid={username}))"
        self._logger.debug(
            "Querying LDAP for UID number", ldap_search=search, user=username
        )

        try:
            results = await self._conn.search(
                self._config.uid_base_dn,
                bonsai.LDAPSearchScope.ONE,
                search,
                attrlist=[self._config.uid_attr],
            )
        except bonsai.LDAPError as e:
            self._logger.error(
                "Cannot query LDAP for UID number",
                error=str(e),
                ldap_search=search,
                user=username,
            )
            raise LDAPException("Error querying LDAP for UID number")

        for result in results:
            try:
                return int(result[self._config.uid_attr][0])
            except Exception as e:
                self._logger.error(
                    "LDAP UID number is invalid",
                    error=str(e),
                    ldap_search=search,
                    user=username,
                )
                raise LDAPException("UID number in LDAP is invalid")

        # Fell through without finding a UID.
        self._logger.error(
            "No UID found in LDAP", ldap_search=search, user=username
        )
        raise LDAPException("No UID found in LDAP")

    async def get_groups(self, username: str) -> List[TokenGroup]:
        """Get groups for a user from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            User's groups from LDAP.

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            One of the groups for the user in LDAP was not valid (missing
            ``cn`` or ``gidNumber`` attributes, or ``gidNumber`` is not an
            integer)
        """
        group_class = self._config.group_object_class
        member_attr = self._config.group_member_attr
        search = f"(&(objectClass={group_class})({member_attr}={username}))"
        self._logger.debug(
            "Querying LDAP for groups", ldap_search=search, user=username
        )

        try:
            results = await self._conn.search(
                self._config.base_dn,
                bonsai.LDAPSearchScope.SUB,
                search,
                attrlist=["cn", "gidNumber"],
            )
        except bonsai.LDAPError as e:
            self._logger.error(
                "Cannot query LDAP for groups",
                error=str(e),
                ldap_search=search,
                user=username,
            )
            raise LDAPException("Error querying LDAP for groups")

        # Parse the results into the group list.
        groups = []
        for result in results:
            try:
                name = None
                self._logger.debug(
                    "LDAP group found", result=result, user=username
                )
                name = result["cn"][0]
                gid = int(result["gidNumber"][0])
                groups.append(TokenGroup(name=name, id=gid))
            except Exception as e:
                self._logger.warning(
                    f"LDAP group {name} invalid, ignoring",
                    error=str(e),
                    ldap_search=search,
                    user=username,
                )
        return groups
