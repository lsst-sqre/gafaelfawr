"""Service layer for user metadata."""

from __future__ import annotations

from structlog.stdlib import BoundLogger

from ..config import Config
from ..exceptions import FirestoreError
from ..models.ldap import LDAPUserData
from ..models.token import TokenData, TokenUserInfo
from ..models.userinfo import Group, UserInfo
from .firestore import FirestoreService
from .ldap import LDAPService

__all__ = ["UserInfoService"]


class UserInfoService:
    """Retrieve user metadata from external systems.

    In some cases, we take user metadata from external systems. Examples are:

    #. Resolve a unique identifier to a username via LDAP.
    #. Get user group membership from LDAP.
    #. Get UID or GID from LDAP.
    #. Assign and manage UIDs and GIDs via Google Firestore.

    This service manages those interactions. LDAP and Firestore data is
    cached via their service objects.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    ldap
        LDAP service for user metadata, if LDAP was configured.
    firestore
        Service for Firestore UID/GID lookups, if Firestore was configured.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        ldap: LDAPService | None,
        firestore: FirestoreService | None,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._ldap = ldap
        self._firestore = firestore
        self._logger = logger

    async def get_user_info_from_token(
        self, token_data: TokenData, *, uncached: bool = False
    ) -> UserInfo:
        """Get the user information from a token.

        Information stored with the token takes precedence over information
        from LDAP. If the token information is `None` and LDAP is configured,
        retrieve it dynamically from LDAP.

        Parameters
        ----------
        token_data
            Data from the authentication token.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        TokenUserInfo
            User information for the holder of that token.

        Raises
        ------
        FirestoreError
            UID/GID allocation using Firestore failed.
        LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        """
        username = token_data.username
        uid = token_data.uid
        gid = token_data.gid
        groups = token_data.groups or []

        # If the UID and primary GID aren't set in the token data, first try
        # to get them from Firestore.
        if uid is None and self._firestore:
            uid = await self._firestore.get_uid(username, uncached=uncached)
        if gid is None and self._firestore and self._config.add_user_group:
            gid = uid

        # Get data from LDAP if it is configured.
        if self._ldap:
            ldap_data = await self._ldap.get_data(username, uncached=uncached)
            if not groups:
                groups = await self._get_groups_from_ldap(
                    username,
                    uid or ldap_data.uid,
                    gid or ldap_data.gid,
                    uncached=uncached,
                )
        else:
            ldap_data = LDAPUserData()

        # If the primary GID isn't set and we're adding a user private group,
        # set the primary GID to the same as the UID.
        if not gid and not ldap_data.gid and self._config.add_user_group:
            gid = uid or ldap_data.uid

        # Calculate the quota.
        quota = None
        if self._config.quota:
            group_names = {g.name for g in groups}
            quota = self._config.quota.calculate_quota(group_names)

        # Return the results.
        return UserInfo(
            username=username,
            name=token_data.name or ldap_data.name,
            uid=uid or ldap_data.uid,
            gid=gid or ldap_data.gid,
            email=token_data.email or ldap_data.email,
            groups=sorted(groups, key=lambda g: g.name),
            quota=quota,
        )

    async def get_scopes(self, user_info: TokenUserInfo) -> set[str] | None:
        """Get scopes from user information.

        Used to determine the scope claim of a token issued based on an OpenID
        Connect authentication.

        Parameters
        ----------
        TokenUserInfo
            User information for a user.

        Returns
        -------
        set of str or None
            The scopes generated from the group membership based on the
            ``group_mapping`` configuration parameter, or `None` if the user
            was not a member of any known group.
        """
        if user_info.groups:
            groups = [g.name for g in user_info.groups]
        elif self._ldap:
            username = user_info.username
            gid = user_info.gid
            if not gid and self._config.ldap and self._config.ldap.gid_attr:
                ldap_data = await self._ldap.get_data(username)
                gid = ldap_data.gid
            groups = await self._ldap.get_group_names(username, gid)
        else:
            groups = []

        scopes: set[str] = set()
        for group in groups:
            scopes.update(self._config.get_scopes_for_group(group))

        return (scopes | {"user:token"}) if scopes else None

    async def invalidate_cache(self, username: str) -> None:
        """Invalidate any cached data for a given user.

        Used after failed login due to missing group memberships, so that if
        the user immediately fixes the problem, they don't have to wait for
        the LDAP cache to expire.

        Parameters
        ----------
        username
            User for which to invalidate cached data.

        Notes
        -----
        This should be sufficient for the most common cases of invalid group
        membership even if there are multiple instances of Gafaelfawr
        running.

        Retrieving LDAP information for a user only happens either (a) during
        the login process, or (b) when checking a user's token (via the /auth
        route, the API, etc.). For the typical case of a user who hasn't
        onboarded yet, (b) is impossible since they haven't previously
        authenticated and have no tokens. When they go through the login
        process, we will retrieve their LDAP information and cache it, but
        then we ask whether they're authorized. If not, we don't issue them a
        token and then invalidate the cache using this method. These both
        happen as part of processing the same request, so they can't be split
        across multiple instances.

        Therefore, in that normal case, this method will remove information
        that was cached as part of the same request, and no other instance of
        Gafaelfawr could have cached LDAP data because the user has not
        successfully authenticated.

        This cache invalidation could be insufficient if the user had
        previously authenticated and then their user information in LDAP
        changed such that they're no longer a member of an eligible group. In
        that case, a cache invalidation done by the login process may be
        undone by the user using an existing unexpired token to authenticate
        to something else, resulting in an LDAP query that will be cached.
        This could cause the confusing behavior that we were hoping to avoid:
        bad LDAP data cached until the cache timeout.

        That said, hopefully this case will be rare compared to the more
        typical case of some onboarding problem. In the case where a user is
        being invalidated entirely, we would normally delete all of their
        tokens as well, avoiding this conflict.
        """
        if self._ldap:
            await self._ldap.invalidate_cache(username)

    async def _get_groups_from_ldap(
        self,
        username: str,
        uid: int | None,
        primary_gid: int | None,
        *,
        uncached: bool = False,
    ) -> list[Group]:
        """Get user group information from LDAP.

        Add GIDs from Firestore if configured to do so.

        Parameters
        ----------
        username
            Username of the user.
        uid
            UID of user, if known. Used to add the user private group if
            configured to do so.
        primary_gid
            Primary GID if set. If not `None`, the user's groups will be
            checked for this GID. If it's not found, search for the group with
            this GID and add it to the user's group memberships. This handles
            LDAP configurations where the user's primary group is represented
            only by their GID and not their group memberships.
        uncached
            Bypass the cache, used for health checks.

        Returns
        -------
        list of Group
            User's groups from LDAP.

        Raises
        ------
        FirestoreError
            GID allocation using Firestore failed.
        LDAPError
            Raised if some error occurred when searching LDAP.
        """
        if not self._ldap:
            raise RuntimeError("LDAP not configured")
        if self._firestore:
            names = await self._ldap.get_group_names(
                username, primary_gid, uncached=uncached
            )
            groups = []
            for group_name in names:
                try:
                    group_gid = await self._firestore.get_gid(
                        group_name, uncached=uncached
                    )
                except FirestoreError as e:
                    e.user = username
                    raise
                groups.append(Group(name=group_name, id=group_gid))
        else:
            groups = await self._ldap.get_groups(
                username, primary_gid, uncached=uncached
            )

        # Add the user private group if configured to do so and it isn't
        # already in the list. When adding it, be careful not to change the
        # groups array, since it may be cached in the LDAP cache and modifying
        # it would modify the cache.
        if self._config.add_user_group and uid:
            if not any(g.name == username for g in groups):
                return [Group(name=username, id=uid), *groups]
        return groups
