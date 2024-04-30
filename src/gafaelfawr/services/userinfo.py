"""Service and caching layer for user metadata."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from ..config import Config
from ..exceptions import (
    ExternalUserInfoError,
    FirestoreError,
    InvalidTokenClaimsError,
    MissingGIDClaimError,
    MissingUIDClaimError,
    MissingUsernameClaimError,
    NotConfiguredError,
)
from ..models.ldap import LDAPUserData
from ..models.oidc import OIDCVerifiedToken
from ..models.token import (
    NotebookQuota,
    Quota,
    TokenData,
    TokenGroup,
    TokenUserInfo,
)
from .firestore import FirestoreService
from .ldap import LDAPService

__all__ = ["OIDCUserInfoService", "UserInfoService"]


class UserInfoService:
    """Retrieve user metadata from external systems.

    In some cases, we take user metadata from external systems.  Examples are:

    #. Resolve a unique identifier to a username via LDAP.
    #. Get user group membership from LDAP.
    #. Get UID or GID from LDAP.
    #. Assign and manage UIDs and GIDs via Google Firestore.

    This service manages those interactions.  UID/GID data from Firestore is
    cached.  LDAP data is not cached, since LDAP is supposed to be able to
    handle a very high query load.

    This is the parent class, which is further specialized by authentication
    provider to incorporate some provider-specific logic for extracting user
    information from the upstream authentication details.

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
    ) -> TokenUserInfo:
        """Get the user information from a token.

        Information stored with the token takes precedence over information
        from LDAP.  If the token information is `None` and LDAP is configured,
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
        if uid is None and self._firestore:
            uid = await self._firestore.get_uid(username, uncached=uncached)

        # If LDAP is not in use, whatever is stored with the token is all the
        # data that we have.
        if not self._ldap:
            return TokenUserInfo(
                username=token_data.username,
                name=token_data.name,
                uid=uid,
                gid=token_data.gid,
                email=token_data.email,
                groups=token_data.groups,
                quota=self._calculate_quota(token_data.groups),
            )

        # Otherwise, try retrieving data from LDAP if it's not already set in
        # the data stored with the token.
        gid = token_data.gid
        if not token_data.name or not token_data.email or not uid or not gid:
            ldap_data = await self._ldap.get_data(username, uncached=uncached)
            if not uid:
                uid = ldap_data.uid
            if not gid:
                gid = ldap_data.gid

        groups = token_data.groups
        if groups is None:
            groups = await self._get_groups_from_ldap(
                username, gid, uncached=uncached
            )

            # When adding the user private group, be careful not to change
            # the groups array, since it may be cached in the LDAP cache
            # and modifying it would modify the cache.
            if self._config.ldap and self._config.ldap.add_user_group and uid:
                groups = [*groups, TokenGroup(name=username, id=uid)]
                if not gid:
                    gid = uid

        return TokenUserInfo(
            username=username,
            name=token_data.name or ldap_data.name,
            uid=uid,
            gid=gid,
            email=token_data.email or ldap_data.email,
            groups=sorted(groups, key=lambda g: g.name),
            quota=self._calculate_quota(groups),
        )

    async def get_scopes(self, user_info: TokenUserInfo) -> list[str] | None:
        """Get scopes from user information.

        Used to determine the scope claim of a token issued based on an OpenID
        Connect authentication.

        Parameters
        ----------
        TokenUserInfo
            User information for a user.

        Returns
        -------
        list of str or None
            The scopes generated from the group membership based on the
            ``group_mapping`` configuration parameter, or `None` if the user
            was not a member of any known group.
        """
        if self._ldap:
            username = user_info.username
            gid = user_info.gid
            if not gid and self._config.ldap and self._config.ldap.gid_attr:
                ldap_data = await self._ldap.get_data(username)
                gid = ldap_data.gid
            groups = await self._ldap.get_group_names(username, gid)
        elif user_info.groups:
            groups = [g.name for g in user_info.groups]
        else:
            groups = []

        scopes = {"user:token"}
        found = False
        for group in groups:
            if group in self._config.group_mapping:
                found = True
                scopes.update(self._config.group_mapping[group])

        return sorted(scopes) if found else None

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

    def _calculate_quota(
        self, groups: list[TokenGroup] | None
    ) -> Quota | None:
        """Calculate the quota for a user.

        Parameters
        ----------
        groups
            The user's group membership.

        Returns
        -------
        gafaelfawr.models.token.Quota
            Quota information for that user.
        """
        if not self._config.quota:
            return None
        api = dict(self._config.quota.default.api)
        notebook = None
        if self._config.quota.default.notebook:
            notebook = NotebookQuota(
                cpu=self._config.quota.default.notebook.cpu,
                memory=self._config.quota.default.notebook.memory,
            )
        for group in groups or []:
            if group.name in self._config.quota.groups:
                extra = self._config.quota.groups[group.name]
                if extra.notebook:
                    if notebook:
                        notebook.cpu += extra.notebook.cpu
                        notebook.memory += extra.notebook.memory
                    else:
                        notebook = NotebookQuota(
                            cpu=extra.notebook.cpu,
                            memory=extra.notebook.memory,
                        )
                for service in extra.api:
                    if service in api:
                        api[service] += extra.api[service]
                    else:
                        api[service] = extra.api[service]
        return Quota(api=api, notebook=notebook)

    async def _get_groups_from_ldap(
        self, username: str, primary_gid: int | None, *, uncached: bool = False
    ) -> list[TokenGroup]:
        """Get user group information from LDAP.

        Add GIDs from Firestore if configured to do so.

        Parameters
        ----------
        username
            Username of the user.
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
        list of TokenGroup
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
                groups.append(TokenGroup(name=group_name, id=group_gid))
            return groups
        else:
            return await self._ldap.get_groups(
                username, primary_gid, uncached=uncached
            )


class OIDCUserInfoService(UserInfoService):
    """Retrieve user metadata from external systems for OIDC authentication.

    This is a specialization of `UserInfoService` when the upstream
    authentication provider is OpenID Connect.  It adds additional methods to
    extract user information from the OpenID Connect ID token.

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
        super().__init__(
            config=config,
            ldap=ldap,
            firestore=firestore,
            logger=logger,
        )
        if not config.oidc:
            raise NotConfiguredError("OpenID Connect not configured")
        self._oidc_config = config.oidc

    async def get_user_info_from_oidc_token(
        self, token: OIDCVerifiedToken
    ) -> TokenUserInfo:
        """Return the metadata for a given user.

        Determine the user's username, numeric UID, and groups.  These may
        come from LDAP, from Firestore, or some combination, depending on
        configuration.  This is the data that we'll store with the token data
        in Redis.  It therefore only includes that data if it comes statically
        from the OIDC tokens of the upstream authentication provider, not if
        they're read dynamically from LDAP or generated via Firestore.

        Parameters
        ----------
        token
            The verified ID token from the OpenID Connect provider.

        Returns
        -------
        TokenUserInfo
            User information derived from external data sources and the
            provided token.

        Raises
        ------
        LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        VerifyTokenError
            The token is missing required claims, or those claims are invalid.
        """
        username = self._get_username_from_oidc_token(token)
        groups = None
        uid = None
        gid = None
        ldap_data = LDAPUserData(name=None, email=None, uid=None, gid=None)
        if self._ldap:
            ldap_data = await self._ldap.get_data(username)
        else:
            groups = await self._get_groups_from_oidc_token(token, username)
        if not self._firestore and not ldap_data.uid:
            uid = self._get_uid_from_oidc_token(token, username)
        if not self._firestore and not ldap_data.gid:
            gid = self._get_gid_from_oidc_token(token, username)

        # If LDAP is configured and provides a name or email, set those to
        # None to ensure that LDAP will be used for that data going forward.
        return TokenUserInfo(
            username=username,
            name=None if ldap_data.name else token.claims.get("name"),
            email=None if ldap_data.email else token.claims.get("email"),
            uid=uid,
            gid=gid,
            groups=groups,
        )

    async def _get_groups_from_oidc_token(
        self,
        token: OIDCVerifiedToken,
        username: str,
    ) -> list[TokenGroup]:
        """Determine the user's groups from token claims.

        Invalid groups are logged and ignored.  The token claim containing the
        group membership can either be a list of dicts with ``name`` and
        optional ``id`` keys, or a simple list of names of groups.  In the
        latter case, the groups will have no GID data.

        Parameters
        ----------
        token
            The previously verified token.
        username
            Authenticated username (for error reporting).

        Returns
        -------
        list of TokenGroup
            List of groups derived from the token claim.

        Raises
        ------
        ExternalUserInfoError
            Raised if an error occurred getting a GID from an external source.
        InvalidTokenClaimsError
            The group claim has an invalid syntax.
        """
        claim = self._oidc_config.groups_claim
        groups = []
        invalid_groups = []
        try:
            for oidc_group in token.claims.get(claim, []):
                try:
                    group = await self._get_group_from_oidc_claim(oidc_group)
                except (TypeError, ValidationError):
                    invalid_groups.append(oidc_group)
                    continue
                if group:
                    groups.append(group)
        except ExternalUserInfoError as e:
            e.user = username
            raise
        except TypeError as e:
            msg = f"{claim} claim has invalid format: {e!s}"
            self._logger.exception(
                "Unable to get groups from token",
                error=msg,
                claim=token.claims.get(claim, []),
                user=username,
            )
            raise InvalidTokenClaimsError(msg, username) from e

        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups in OIDC token",
                error=f"{claim} claim value contained invalid groups",
                invalid_groups=invalid_groups,
                user=username,
            )

        return groups

    async def _get_group_from_oidc_claim(
        self, group: str | dict[str, Any]
    ) -> TokenGroup | None:
        """Translate one member of the OIDC group claim into a group.

        Parameters
        ----------
        group
            One member of the groups claim of the OpenID Connect token. This
            may be a simple group name or it may be a dict with group name and
            GID elements.

        Returns
        -------
        TokenGroup or None
            The equivalent group model, or `None` if this member of the claim
            could not be resolved into a group.

        Raises
        ------
        TypeError
            Raised if some part of the claim has an unexpected type.
        ValidationError
            Raised if the group is invalid (malformatted name, for instance).
        """
        # First, check if it's a simple group name. If so, treat that as the
        # group name. Otherwise, assume this is a dictionary and try to get
        # the group name and GID from name and id elements. One installation's
        # identity management system insisted on adding leading slashes.
        if isinstance(group, str):
            name = group.removeprefix("/")
        else:
            if "name" not in group:
                return None
            name = group["name"].removeprefix("/")

        # Now, try to resolve that group name to a GID. Try Firestore if
        # configured, and if not try to extract the GID from the OpenID
        # Connect claim. Failing all of those, create a group without a GID.
        gid = None
        if self._firestore:
            gid = await self._firestore.get_gid(name)
        elif isinstance(group, dict) and "id" in group:
            gid = int(group["id"])

        # Return the resulting group.
        return TokenGroup(name=name, id=gid)

    def _get_gid_from_oidc_token(
        self, token: OIDCVerifiedToken, username: str
    ) -> int | None:
        """Verify and return the primary GID from the token.

        Parameters
        ----------
        token
            The previously verified token.
        username
            Authenticated username (for error reporting).

        Returns
        -------
        int or None
            The primary GID of the user as obtained from the token, or `None`
            if not configured to get a primary GID from the claims.

        Raises
        ------
        MissingGIDClaimError
            The token is missing the required numeric GID claim.
        InvalidTokenClaimsError
            The GID claim contains something that is not a number.
        """
        if not self._oidc_config.gid_claim:
            return None
        if self._oidc_config.gid_claim not in token.claims:
            msg = f"No {self._oidc_config.gid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise MissingGIDClaimError(msg, username)
        try:
            gid = int(token.claims[self._oidc_config.gid_claim])
        except Exception as e:
            msg = f"Invalid {self._oidc_config.gid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise InvalidTokenClaimsError(msg, username) from e
        return gid

    def _get_uid_from_oidc_token(
        self, token: OIDCVerifiedToken, username: str
    ) -> int:
        """Verify and return the numeric UID from the token.

        Parameters
        ----------
        token
            The previously verified token.
        username
            Authenticated username (for error reporting).

        Returns
        -------
        int
            The numeric UID of the user as obtained from the token.

        Raises
        ------
        MissingUIDClaimError
            The token is missing the required numeric UID claim.
        InvalidTokenClaimsError
            The numeric UID claim contains something that is not a number.
        """
        if self._oidc_config.uid_claim not in token.claims:
            msg = f"No {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise MissingUIDClaimError(msg, username)
        try:
            uid = int(token.claims[self._oidc_config.uid_claim])
        except Exception as e:
            msg = f"Invalid {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise InvalidTokenClaimsError(msg, username) from e
        return uid

    def _get_username_from_oidc_token(self, token: OIDCVerifiedToken) -> str:
        """Verify and return the username from the token.

        Parameters
        ----------
        token
            The previously verified token.

        Returns
        -------
        str
            The username of the user as obtained from the token.

        Raises
        ------
        MissingUsernameClaimError
            The token is missing the required username claim.
        """
        if self._oidc_config.username_claim not in token.claims:
            msg = f"No {self._oidc_config.username_claim} claim in token"
            self._logger.warning(msg, claims=token.claims)
            raise MissingUsernameClaimError(msg)
        username = token.claims[self._oidc_config.username_claim]
        if not isinstance(username, str):
            msg = (
                f"Invalid {self._oidc_config.username_claim} claim in token:"
                f" {username}"
            )
            raise InvalidTokenClaimsError(msg)
        return username
