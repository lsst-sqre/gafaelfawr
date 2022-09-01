"""Service and caching layer for user metadata."""

from __future__ import annotations

from typing import List, Optional

from structlog.stdlib import BoundLogger

from ..config import Config
from ..exceptions import (
    InvalidTokenClaimsError,
    MissingGIDClaimError,
    MissingUIDClaimError,
    MissingUsernameClaimError,
    NotConfiguredError,
    ValidationError,
)
from ..models.ldap import LDAPUserData
from ..models.oidc import OIDCVerifiedToken
from ..models.token import TokenData, TokenGroup, TokenUserInfo
from ..services.firestore import FirestoreService
from ..services.ldap import LDAPService

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
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    ldap : `gafaelfawr.services.ldap.LDAPService`, optional
        LDAP service for user metadata, if LDAP was configured.
    firestore : `gafaelfawr.services.firestore.FirestoreService`, optional
        Service for Firestore UID/GID lookups, if Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        ldap: Optional[LDAPService],
        firestore: Optional[FirestoreService],
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._ldap = ldap
        self._firestore = firestore
        self._logger = logger

    async def get_user_info_from_token(
        self, token_data: TokenData
    ) -> TokenUserInfo:
        """Get the user information from a token.

        Information stored with the token takes precedence over information
        from LDAP.  If the token information is `None` and LDAP is configured,
        retrieve it dynamically from LDAP.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            Data from the authentication token.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information for the holder of that token.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreError
            UID/GID allocation using Firestore failed, probably because the UID
            or GID space has been exhausted.
        gafaelfawr.exceptions.LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        """
        username = token_data.username
        uid = token_data.uid
        if uid is None and self._firestore:
            uid = await self._firestore.get_uid(username)

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
            )

        # Otherwise, try retrieving data from LDAP if it's not already set in
        # the data stored with the token.
        gid = token_data.gid
        if not token_data.name or not token_data.email or not uid or not gid:
            ldap_data = await self._ldap.get_data(username)
            if not uid:
                uid = ldap_data.uid
            if not gid:
                gid = ldap_data.gid

        groups = token_data.groups
        if groups is None:
            if self._firestore:
                group_names = await self._ldap.get_group_names(username, gid)
                groups = []
                for group_name in group_names:
                    group_gid = await self._firestore.get_gid(group_name)
                    groups.append(TokenGroup(name=group_name, id=group_gid))
            else:
                groups = await self._ldap.get_groups(username, gid)

            # When adding the user private group, be careful not to change
            # the groups array, since it may be cached in the LDAP cache
            # and modifying it would modify the cache.
            if self._config.ldap and self._config.ldap.add_user_group and uid:
                groups = groups + [TokenGroup(name=username, id=uid)]
                if not gid:
                    gid = uid

        return TokenUserInfo(
            username=username,
            name=token_data.name or ldap_data.name,
            uid=uid,
            gid=gid,
            email=token_data.email or ldap_data.email,
            groups=sorted(groups, key=lambda g: g.name),
        )

    async def get_scopes(
        self, user_info: TokenUserInfo
    ) -> Optional[List[str]]:
        """Get scopes from user information.

        Used to determine the scope claim of a token issued based on an OpenID
        Connect authentication.

        Parameters
        ----------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information for a user.

        Returns
        -------
        scopes : List[`str`] or `None`
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

        scopes = set(["user:token"])
        found = False
        for group in groups:
            if group in self._config.group_mapping:
                found = True
                scopes.update(self._config.group_mapping[group])

        return sorted(scopes) if found else None


class OIDCUserInfoService(UserInfoService):
    """Retrieve user metadata from external systems for OIDC authentication.

    This is a specialization of `UserInfoService` when the upstream
    authentication provider is OpenID Connect.  It adds additional methods to
    extract user information from the OpenID Connect ID token.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    ldap : `gafaelfawr.services.ldap.LDAPService`, optional
        LDAP service for user metadata, if LDAP was configured.
    firestore : `gafaelfawr.services.firestore.FirestoreService`, optional
        Service for Firestore UID/GID lookups, if Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        ldap: Optional[LDAPService],
        firestore: Optional[FirestoreService],
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
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The verified ID token from the OpenID Connect provider.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information derived from external data sources and the
            provided token.

        Raises
        ------
        gafaelfawr.exceptions.LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        gafaelfawr.exceptions.VerifyTokenError
            The token is missing required claims.
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
    ) -> List[TokenGroup]:
        """Determine the user's groups from token claims.

        Invalid groups are logged and ignored.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.
        username : `str`
            Authenticated username (for error reporting).

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            List of groups derived from the ``isMemberOf`` token claim.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreError
            An error occured obtaining the GID from Firestore.
        gafaelfawr.exceptions.InvalidTokenClaimsError
            The ``isMemberOf`` claim has an invalid syntax.
        """
        groups = []
        invalid_groups = {}
        try:
            for oidc_group in token.claims.get("isMemberOf", []):
                if "name" not in oidc_group:
                    continue
                name = oidc_group["name"]
                try:
                    if self._firestore:
                        gid = await self._firestore.get_gid(name)
                    else:
                        if "id" not in oidc_group:
                            invalid_groups[name] = "missing id"
                            continue
                        gid = int(oidc_group["id"])
                    groups.append(TokenGroup(name=name, id=gid))
                except (TypeError, ValueError, ValidationError) as e:
                    invalid_groups[name] = str(e)
        except TypeError as e:
            msg = f"isMemberOf claim has invalid format: {str(e)}"
            self._logger.error(
                "Unable to get groups from token",
                error=msg,
                claim=token.claims.get("isMemberOf", []),
                user=username,
            )
            raise InvalidTokenClaimsError(msg) from e

        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups in OIDC token",
                error="isMemberOf claim value could not be parsed",
                invalid_groups=invalid_groups,
                user=username,
            )

        return groups

    def _get_gid_from_oidc_token(
        self, token: OIDCVerifiedToken, username: str
    ) -> Optional[int]:
        """Verify and return the primary GID from the token.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.
        username : `str`
            Authenticated username (for error reporting).

        Returns
        -------
        gid : `int` or `None`
            The primary GID of the user as obtained from the token, or `None`
            if not configured to get a primary GID from the claims.

        Raises
        ------
        gafaelfawr.exceptions.MissingGIDClaimError
            The token is missing the required numeric GID claim.
        gafaelfawr.exceptions.InvalidTokenClaimsError
            The GID claim contains something that is not a number.
        """
        if not self._oidc_config.gid_claim:
            return None
        if self._oidc_config.gid_claim not in token.claims:
            msg = f"No {self._oidc_config.gid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise MissingGIDClaimError(msg)
        try:
            gid = int(token.claims[self._oidc_config.gid_claim])
        except Exception as e:
            msg = f"Invalid {self._oidc_config.gid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise InvalidTokenClaimsError(msg) from e
        return gid

    def _get_uid_from_oidc_token(
        self, token: OIDCVerifiedToken, username: str
    ) -> int:
        """Verify and return the numeric UID from the token.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.
        username : `str`
            Authenticated username (for error reporting).

        Returns
        -------
        uid : `int`
            The numeric UID of the user as obtained from the token.

        Raises
        ------
        gafaelfawr.exceptions.MissingUIDClaimError
            The token is missing the required numeric UID claim.
        gafaelfawr.exceptions.InvalidTokenClaimsError
            The numeric UID claim contains something that is not a number.
        """
        if self._oidc_config.uid_claim not in token.claims:
            msg = f"No {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise MissingUIDClaimError(msg)
        try:
            uid = int(token.claims[self._oidc_config.uid_claim])
        except Exception as e:
            msg = f"Invalid {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise InvalidTokenClaimsError(msg) from e
        return uid

    def _get_username_from_oidc_token(self, token: OIDCVerifiedToken) -> str:
        """Verify and return the username from the token.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.

        Returns
        -------
        username : `str`
            The username of the user as obtained from the token.

        Raises
        ------
        gafaelfawr.exceptions.MissingUsernameClaimError
            The token is missing the required username claim.
        """
        if self._oidc_config.username_claim not in token.claims:
            msg = f"No {self._oidc_config.username_claim} claim in token"
            self._logger.warning(msg, claims=token.claims)
            raise MissingUsernameClaimError(msg)
        return token.claims[self._oidc_config.username_claim]
