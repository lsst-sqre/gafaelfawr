"""LDAP storage layer for Gafaelfawr."""

from __future__ import annotations

from typing import List, Optional

import bonsai
from structlog.stdlib import BoundLogger

from ..config import LDAPConfig
from ..exceptions import LDAPException
from ..models.token import TokenGroup

__all__ = ["LDAPStorage"]


class LDAPStorage:
    """LDAP storage layer.

    This abstracts retrieving authorization information and user metadata from
    LDAP.

    Parameters
    ----------
    config : `gafaelfawr.config.LDAPConfig`
        Configuration for LDAP searches.
    logger : `structlog.stdlib.BoundLogger`
        Logger for debug messages and errors.

    Notes
    -----
    Currently, a new LDAP connection is opened for each LDAP search.  This is
    not ideal; ideally, LDAP searches should use a managed connection pool or
    otherwise maintain open connections.  However, it's unclear how bonsai
    handles open connections that are closed by the LDAP server due to an idle
    timeout, and thus whether doing that would cause stability issues if the
    LDAP search volume is low.  This will require future exploration.
    """

    def __init__(self, config: LDAPConfig, logger: BoundLogger) -> None:
        self._config = config
        self._client = bonsai.LDAPClient(config.url)
        self._logger = logger.bind(
            ldap_url=self._config.url,
            ldap_base=self._config.uid_base_dn,
        )

    async def get_uid(self, username: str) -> Optional[int]:
        """Get the numeric UID of a user.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        uid_number : `int` or `None`
            The numeric UID of the user from LDAP, or `None` if Gafaelfawr was
            not configured to get the UID from LDAP (in which case the caller
            should fall back to other sources of the UID).

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            The lookup of ``uid_number_attr`` in the LDAP server was not valid
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
            async with self._client.connect(is_async=True) as conn:
                results = await conn.search(
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
            async with self._client.connect(is_async=True) as conn:
                results = await conn.search(
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
