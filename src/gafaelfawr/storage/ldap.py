"""LDAP storage layer for Gafaelfawr."""

from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional

import bonsai
from bonsai import LDAPSearchScope
from bonsai.asyncio import AIOConnectionPool
from bonsai.asyncio.aiopool import AIOPoolContextManager
from structlog.stdlib import BoundLogger

from ..config import LDAPConfig
from ..constants import GROUPNAME_REGEX, LDAP_TIMEOUT
from ..exceptions import LDAPError
from ..models.ldap import LDAPUserData
from ..models.token import TokenGroup

__all__ = ["LDAPStorage"]


class LDAPStorage:
    """LDAP storage layer.

    Parameters
    ----------
    config : `gafaelfawr.config.LDAPConfig`
        Configuration for LDAP searches.
    pool : `bonsai.asyncio.AIOConnectionPool`
        Connection pool for LDAP searches.
    logger : `structlog.stdlib.BoundLogger`
        Logger for debug messages and errors.
    """

    def __init__(
        self, config: LDAPConfig, pool: AIOConnectionPool, logger: BoundLogger
    ) -> None:
        self._config = config
        self._pool = pool
        self._logger = logger.bind(ldap_url=self._config.url)

    async def get_group_names(
        self, username: str, primary_gid: Optional[int]
    ) -> List[str]:
        """Get names of groups for a user from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.
        primary_gid : `int` or `None`
            Primary GID if set.  If not `None`, search for the group with this
            GID and add it to the user's group memberships.  This handles LDAP
            configurations where the user's primary group is represented only
            by their GID and not their group memberships.

        Returns
        -------
        groups : List[`str`]
            User's group names from LDAP.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            Some error occurred while doing the LDAP search.
        """
        group_class = self._config.group_object_class
        member_attr = self._config.group_member_attr
        search = f"(&(objectClass={group_class})({member_attr}={username}))"
        logger = self._logger.bind(ldap_search=search, user=username)
        results = await self._query(
            self._config.group_base_dn,
            bonsai.LDAPSearchScope.SUB,
            search,
            ["cn"],
        )
        logger.debug("LDAP groups found", ldap_results=results)

        # Parse the results into the group list.
        groups = []
        valid_group_regex = re.compile(GROUPNAME_REGEX)
        for result in results:
            try:
                name = result["cn"][0]
            except Exception as e:
                logger.warning(
                    "Invalid LDAP group result, ignoring",
                    error=str(e),
                    ldap_result=result,
                )
            if valid_group_regex.match(name):
                groups.append(name)
            else:
                logger.warning(f"LDAP group {name} invalid, ignoring")

        # Check that the primary group is included, and if not, try to add it.
        if primary_gid:
            search = f"(&(objectClass={group_class})(gidNumber={primary_gid}))"
            logger = self._logger.bind(ldap_search=search)
            results = await self._query(
                self._config.group_base_dn,
                bonsai.LDAPSearchScope.SUB,
                search,
                ["cn"],
            )
            logger.debug(
                "Results for primary group",
                gid=primary_gid,
                ldap_results=results,
            )
            for result in results:
                if "cn" not in result or not result["cn"]:
                    continue
                name = result["cn"][0]
                if name in groups:
                    break
                if valid_group_regex.match(name):
                    groups.append(name)
                    break
                else:
                    logger.warning(f"LDAP group {name} invalid, ignoring")

        return groups

    async def get_groups(
        self, username: str, primary_gid: Optional[int]
    ) -> List[TokenGroup]:
        """Get groups for a user from LDAP.

        Parameters
        ----------
        username : `str`
            Username of the user.
        primary_gid : `int` or `None`
            Primary GID if set.  If not `None`, the user's groups will be
            checked for this GID.  If it's not found, search for the group
            with this GID and add it to the user's group memberships.  This
            handles LDAP configurations where the user's primary group is
            represented only by their GID and not their group memberships.

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            User's groups from LDAP.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            Some error occurred when searching LDAP.
        """
        group_class = self._config.group_object_class
        member_attr = self._config.group_member_attr
        search = f"(&(objectClass={group_class})({member_attr}={username}))"
        logger = self._logger.bind(ldap_search=search, user=username)
        results = await self._query(
            self._config.group_base_dn,
            bonsai.LDAPSearchScope.SUB,
            search,
            ["cn", "gidNumber"],
        )
        logger.debug("LDAP groups found", ldap_results=results)

        # Parse the results into the group list.
        groups = []
        for result in results:
            name = None
            try:
                name = result["cn"][0]
                gid = int(result["gidNumber"][0])
                groups.append(TokenGroup(name=name, id=gid))
            except Exception as e:
                logger.warning(
                    f"LDAP group {name} invalid, ignoring", error=str(e)
                )

        # Check that the primary group is included, and if not, try to add it.
        if primary_gid and not any(g.id == primary_gid for g in groups):
            search = f"(&(objectClass={group_class})(gidNumber={primary_gid}))"
            logger = self._logger.bind(ldap_search=search)
            results = await self._query(
                self._config.group_base_dn,
                bonsai.LDAPSearchScope.SUB,
                search,
                ["cn"],
            )
            logger.debug(
                "Results for primary group",
                gid=primary_gid,
                ldap_results=results,
            )
            for result in results:
                if "cn" not in result or not result["cn"]:
                    continue
                name = result["cn"][0]
                try:
                    groups.append(TokenGroup(name=name, id=primary_gid))
                    break
                except Exception as e:
                    msg = f"LDAP group {name} invalid, ignoring"
                    logger.warning(msg, error=str(e))

        return groups

    async def get_data(self, username: str) -> LDAPUserData:
        """Get the data for an LDAP user.

        Parameters
        ----------
        username : `str`
            Username of the user.

        Returns
        -------
        data : `gafaelfawr.models.ldap.LDAPUserData`
            The data for an LDAP user.  Which fields are filled in will be
            determined by the configuration.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            The lookup of ``user_search_attr`` at ``user_base_dn`` in the LDAP
            server was not valid (connection to the LDAP server failed,
            attribute not found in LDAP, UID result value not an integer).
        """
        if not self._config.user_base_dn:
            return LDAPUserData(name=None, email=None, uid=None, gid=None)

        search = f"({self._config.user_search_attr}={username})"
        logger = self._logger.bind(ldap_search=search, user=username)
        attrs = []
        if self._config.name_attr:
            attrs.append(self._config.name_attr)
        if self._config.email_attr:
            attrs.append(self._config.email_attr)
        if self._config.uid_attr:
            attrs.append(self._config.uid_attr)
        if self._config.gid_attr:
            attrs.append(self._config.gid_attr)
        results = await self._query(
            self._config.user_base_dn,
            bonsai.LDAPSearchScope.ONE,
            search,
            attrs,
        )
        logger.debug("LDAP entries for user data", ldap_results=results)

        # If results are empty, return no data.
        if not results:
            return LDAPUserData(name=None, email=None, uid=None, gid=None)
        result = results[0]

        # Extract data from the result.
        try:
            name = None
            email = None
            uid = None
            gid = None
            if self._config.name_attr and self._config.name_attr in result:
                name = result[self._config.name_attr][0]
            if self._config.email_attr and self._config.email_attr in result:
                email = result[self._config.email_attr][0]
            if self._config.uid_attr and self._config.uid_attr in result:
                uid = int(result[self._config.uid_attr][0])
            if self._config.gid_attr and self._config.gid_attr in result:
                gid = int(result[self._config.gid_attr][0])
            return LDAPUserData(name=name, email=email, uid=uid, gid=gid)
        except Exception as e:
            logger.error("LDAP user entry invalid", error=str(e))
            raise LDAPError("LDAP user entry invalid") from e

    async def _query(
        self,
        base: str,
        scope: LDAPSearchScope,
        filter_exp: str,
        attrlist: List[str],
    ) -> List[Dict[str, List[str]]]:
        """Perform an LDAP query using the connection pool.

        Notes
        -----
        The current bonsai connection pool does not keep track of failed
        connections and will keep returning the same connection even if the
        LDAP server has stopped responding (due to a firewall timeout, for
        example).  Working around this requires setting a timeout, catching
        the timeout exception, and explicitly closing and reopening the
        connection.  A search is attempted at most twice.

        As of bonsai 1.4.0, be aware that bonsai appears to go into an
        infinite CPU loop when waiting for results when run in an asyncio loop
        without other active coroutines.  It's not clear whether that's true
        if there are other active coroutines.

        Parameters
        ----------
        base : `str`
            Base DN of the search.
        scope : `bonsai.LDAPSearchScope`
            Scope of the search.
        filter_exp : `str`
            Search filter.
        attrlist : List[`str`]
            List of attributes to retrieve.

        Returns
        -------
        results : List[Dict[`str`, List[`str`]]]
            List of result entries, each of which is a dictionary of the
            requested attributes (plus possibly other attributes) to a list
            of their values.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            Failed to run the search.
        """
        logger = self._logger.bind(
            ldap_attrs=attrlist, ldap_base=base, ldap_search=filter_exp
        )

        try:
            for _ in range(2):
                async with AIOPoolContextManager(self._pool) as conn:
                    try:
                        logger.debug("Querying LDAP")
                        return await conn.search(
                            base=base,
                            scope=scope,
                            filter_exp=filter_exp,
                            attrlist=attrlist,
                            timeout=LDAP_TIMEOUT,
                        )
                    except (bonsai.ConnectionError, asyncio.TimeoutError):
                        logger.debug("Reopening LDAP connection after timeout")
                        conn.close()
                        await conn.open(timeout=LDAP_TIMEOUT)
                    except bonsai.ConnectionClosed:
                        # If we timed out and then the open failed, a closed
                        # connection is left in the pool and returned later,
                        # at which point it fails with this exception.
                        # Attempt to reopen it.
                        logger.debug("Attempting to reopen closed connection")
                        await conn.open(timeout=LDAP_TIMEOUT)
        except bonsai.LDAPError as e:
            logger.error("Cannot query LDAP", error=str(e))
            raise LDAPError("Error querying LDAP") from e

        # Failed due to timeout or closed connection twice.
        msg = f"LDAP query timed out after {LDAP_TIMEOUT}s"
        logger.error("Cannot query LDAP", error=msg)
        raise LDAPError(msg)
