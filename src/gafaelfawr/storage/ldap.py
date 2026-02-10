"""LDAP storage layer for Gafaelfawr."""

import re
from collections.abc import AsyncIterator

import bonsai
import sentry_sdk
from bonsai import LDAPSearchScope
from bonsai.asyncio import AIOConnectionPool
from structlog.stdlib import BoundLogger

from ..config import LDAPConfig
from ..constants import GROUPNAME_REGEX, LDAP_TIMEOUT
from ..exceptions import LDAPError
from ..models.ldap import LDAPUserData
from ..models.userinfo import Group

__all__ = ["LDAPStorage"]


class LDAPStorage:
    """LDAP storage layer.

    Parameters
    ----------
    config
        Configuration for LDAP searches.
    pool
        Connection pool for LDAP searches.
    logger
        Logger for debug messages and errors.
    """

    def __init__(
        self, config: LDAPConfig, pool: AIOConnectionPool, logger: BoundLogger
    ) -> None:
        self._config = config
        self._pool = pool
        self._logger = logger.bind(ldap_url=str(self._config.url))

    @sentry_sdk.trace
    async def get_group_names(
        self, username: str, primary_gid: int | None
    ) -> list[str]:
        """Get names of groups for a user from LDAP.

        Parameters
        ----------
        username
            Username of the user.
        primary_gid
            Primary GID if set. If not `None`, search for the group with this
            GID and add it to the user's group memberships. This handles LDAP
            configurations where the user's primary group is represented only
            by their GID and not their group memberships.

        Returns
        -------
        list of str
            User's group names from LDAP.

        Raises
        ------
        LDAPError
            Raised if some error occurred while doing the LDAP search.
        """
        groups = [
            r["cn"][0] async for r in self._find_groups(username, ["cn"])
        ]
        if primary_gid:
            group = await self._find_group_for_gid(primary_gid, username)
            if group:
                groups.append(group.name)
        return groups

    @sentry_sdk.trace
    async def get_groups(
        self, username: str, primary_gid: int | None
    ) -> list[Group]:
        """Get groups for a user from LDAP.

        Parameters
        ----------
        username
            Username of the user.
        primary_gid
            Primary GID if set. If not `None`, the user's groups will be
            checked for this GID. If it's not found, search for the group with
            this GID and add it to the user's group memberships.  This handles
            LDAP configurations where the user's primary group is represented
            only by their GID and not their group memberships.

        Returns
        -------
        list of Group
            User's groups from LDAP.

        Raises
        ------
        LDAPError
            Raised if some error occurred when searching LDAP.
        """
        groups = []
        async for result in self._find_groups(username, ["cn", "gidNumber"]):
            name = None
            try:
                name = result["cn"][0]
                gid = int(result["gidNumber"][0])
                groups.append(Group(name=name, id=gid))
            except Exception as e:
                msg = f"LDAP group {name} has invalid gidNumber, ignoring"
                self._logger.warning(
                    msg, error=str(e), username=username, ldap_result=result
                )

        # Check that the primary group is included, and if not, try to add it.
        if primary_gid and not any(g.id == primary_gid for g in groups):
            group = await self._find_group_for_gid(primary_gid, username)
            if group:
                groups.append(group)

        return groups

    @sentry_sdk.trace
    async def get_data(self, username: str) -> LDAPUserData:
        """Get the data for an LDAP user.

        Parameters
        ----------
        username
            Username of the user.

        Returns
        -------
        LDAPUserData
            The data for an LDAP user.  Which fields are filled in will be
            determined by the configuration.

        Raises
        ------
        LDAPError
            Raised if the lookup of ``user_search_attr`` at ``user_base_dn``
            in the LDAP server was not valid (connection to the LDAP server
            failed, attribute not found in LDAP, UID result value not an
            integer).
        """
        if not self._config.user_base_dn:
            return LDAPUserData(name=None, email=None, uid=None, gid=None)

        search = f"({self._config.user_search_attr}={username})"
        logger = self._logger.bind(ldap_search=search, user=username)
        results = await self._query(
            self._config.user_base_dn,
            bonsai.LDAPSearchScope.ONE,
            search,
            self._build_user_search_attrs(),
            username,
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
            msg = "LDAP user entry invalid"
            logger.exception(msg, error=str(e))
            raise LDAPError(msg, username) from e

    def _build_group_member_search(self, username: str) -> str:
        """Build the LDAP search to find group memberships for a user.

        Parameters
        ----------
        username
            Username of the user.

        Returns
        -------
        str
            LDAP search to find their group memberships.
        """
        group_class = self._config.group_object_class
        member_attr = self._config.group_member_attr
        if self._config.group_search_by_dn:
            base_dn = self._config.user_base_dn
            attr = self._config.user_search_attr
            target = f"{attr}={username},{base_dn}"
        else:
            target = username
        return f"(&(objectClass={group_class})({member_attr}={target}))"

    def _build_user_search_attrs(self) -> list[str]:
        """Construct the list of user attributes to search for."""
        attrs = []
        if self._config.name_attr:
            attrs.append(self._config.name_attr)
        if self._config.email_attr:
            attrs.append(self._config.email_attr)
        if self._config.uid_attr:
            attrs.append(self._config.uid_attr)
        if self._config.gid_attr:
            attrs.append(self._config.gid_attr)
        return attrs

    async def _find_group_for_gid(
        self, gid: int, username: str
    ) -> Group | None:
        """Find the group for a GID.

        Used to add the group corresponding to a person's primary GID, if it
        was not already included in their group list.

        Parameters
        ----------
        gid
            GID to search for.
        username
            Username of user, for logging.

        Returns
        -------
        Group or None
            Group if found, or `None` if it was not.
        """
        group_class = self._config.group_object_class
        search = f"(&(objectClass={group_class})(gidNumber={gid}))"
        logger = self._logger.bind(ldap_search=search, user=username)
        results = await self._query(
            self._config.group_base_dn,
            bonsai.LDAPSearchScope.SUB,
            search,
            ["cn"],
            username,
        )
        logger.debug(
            "Results for primary group", gid=gid, ldap_results=results
        )
        for result in results:
            if "cn" not in result or not result["cn"]:
                continue
            name = result["cn"][0]
            try:
                # Rely on Pydantic to do the validation.
                return Group(name=name, id=gid)
            except Exception as e:
                msg = f"LDAP group {name} invalid, ignoring"
                logger.warning(msg, error=str(e), ldap_result=result)
        return None

    async def _find_groups(
        self, username: str, attrs: list[str]
    ) -> AsyncIterator[dict[str, list[str]]]:
        """Search for group memberships.

        Assumes that the group name is in ``cn`` and discards invalid group
        names without yielding those results.

        Parameters
        ----------
        username
            Username of the user.
        attrs
            List of attributes to search for.

        Yields
        ------
        dict of list
            Each result, which will be a dictionary of attribute names to
            lists of values for that attribute.
        """
        search = self._build_group_member_search(username)
        logger = self._logger.bind(ldap_search=search, user=username)
        results = await self._query(
            self._config.group_base_dn,
            bonsai.LDAPSearchScope.SUB,
            search,
            attrs,
            username,
        )
        logger.debug("LDAP groups found", ldap_results=results)

        # Parse the results into the group list.
        valid_group_regex = re.compile(GROUPNAME_REGEX)
        for result in results:
            try:
                name = result["cn"][0]
            except Exception as e:
                msg = "Invalid LDAP group result, ignoring"
                logger.warning(msg, error=str(e), ldap_result=result)
            if valid_group_regex.match(name):
                yield result
            elif name.startswith("CO:"):
                # COmanage populates internal groups that start with CO:. We
                # always ignore these, so they don't warrant a warning.
                logger.debug(f"Ignoring COmanage group {name}")
            else:
                logger.warning(f"LDAP group {name} invalid, ignoring")

    async def _query(
        self,
        base: str,
        scope: LDAPSearchScope,
        filter_exp: str,
        attrlist: list[str],
        username: str,
    ) -> list[dict[str, list[str]]]:
        """Perform an LDAP query using the connection pool.

        Parameters
        ----------
        base
            Base DN of the search.
        scope
            Scope of the search.
        filter_exp
            Search filter.
        attrlist
            List of attributes to retrieve.
        username
            User for which the query is being performed, for error reporting.

        Returns
        -------
        list of dict
            List of result entries, each of which is a dictionary of the
            requested attributes (plus possibly other attributes) to a list
            of their values.

        Raises
        ------
        LDAPError
            Raised if failed to run the search.

        Notes
        -----
        The current bonsai connection pool does not keep track of failed
        connections and will keep returning the same connection even if the
        LDAP server has stopped responding (due to a firewall timeout, for
        example).  Working around this requires setting a timeout, catching
        the timeout exception, and explicitly closing the connection.  A
        search is attempted at most twice.

        Be aware that bonsai (seen in 1.4.0, not tested again in 1.5.0)
        appears to go into an infinite CPU loop when waiting for results when
        run in an asyncio loop without other active coroutines.  It's not
        clear whether that's true if there are other active coroutines.
        """
        logger = self._logger.bind(
            ldap_attrs=attrlist,
            ldap_base=base,
            ldap_search=filter_exp,
            user=username,
        )

        try:
            for _ in range(2):
                async with self._pool.spawn() as conn:
                    try:
                        logger.debug("Querying LDAP")
                        return await conn.search(
                            base=base,
                            scope=scope,
                            filter_exp=filter_exp,
                            attrlist=attrlist,
                            timeout=LDAP_TIMEOUT,
                        )
                    except TimeoutError, bonsai.ConnectionError:
                        logger.debug("Reopening LDAP connection after timeout")
                        conn.close()
        except bonsai.LDAPError as e:
            logger.exception("Cannot query LDAP", error=str(e))
            raise LDAPError("Error querying LDAP", username) from e

        # Failed due to timeout or closed connection twice.
        msg = f"LDAP query timed out after {LDAP_TIMEOUT}s"
        logger.error("Cannot query LDAP", error=msg)
        raise LDAPError(msg, username)
