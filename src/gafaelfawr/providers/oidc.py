"""OpenID Connect authentication provider."""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlencode

import bonsai
import jwt
from httpx import AsyncClient
from pydantic import ValidationError
from structlog.stdlib import BoundLogger

from ..config import LDAPConfig, OIDCConfig
from ..exceptions import LDAPException, OIDCException, VerifyTokenException
from ..models.oidc import OIDCToken
from ..models.state import State
from ..models.token import TokenGroup, TokenUserInfo
from ..verify import TokenVerifier
from .base import Provider

__all__ = ["OIDCProvider"]


class OIDCProvider(Provider):
    """Authenticate a user with GitHub.

    Parameters
    ----------
    config : `gafaelfawr.config.OIDCConfig`
        Configuration for the OpenID Connect authentication provider.
    verifier : `gafaelfawr.verify.TokenVerifier`
        Token verifier to use to verify the token returned by the provider.
    http_client : ``httpx.AsyncClient``
        Session to use to make HTTP requests.
    logger : ``structlog.stdlib.BoundLogger``
        Logger for any log messages.
    """

    def __init__(
        self,
        *,
        config: OIDCConfig,
        ldap_config: Optional[LDAPConfig],
        verifier: TokenVerifier,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._ldap_config = ldap_config
        self._verifier = verifier
        self._http_client = http_client
        self._logger = logger

    def get_redirect_url(self, state: str) -> str:
        """Get the login URL to which to redirect the user.

        Parameters
        ----------
        state : `str`
            A random string used for CSRF protection.

        Returns
        -------
        url : `str`
            The encoded URL to which to redirect the user.
        """
        scopes = ["openid"]
        scopes.extend(self._config.scopes)
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_url,
            "scope": " ".join(scopes),
            "state": state,
        }
        params.update(self._config.login_params)
        self._logger.info(
            "Redirecting user to %s for authentication", self._config.login_url
        )
        return f"{self._config.login_url}?{urlencode(params)}"

    async def create_user_info(
        self, code: str, state: str, session: State
    ) -> TokenUserInfo:
        """Given the code from a successful authentication, get a token.

        Parameters
        ----------
        code : `str`
            Code returned by a successful authentication.
        state : `str`
            The same random string used for the redirect URL, not used.
        session : `gafaelfawr.models.state.State`
            The session state, not used by this provider.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information corresponding to that authentication.

        Raises
        ------
        gafaelfawr.exceptions.OIDCException
            The OpenID Connect provider responded with an error to a request
            or the group membership in the resulting token was not valid.
        gafaelfawr.exceptions.LDAPException
            One of the groups for the user in LDAP was not valid (missing
            cn or gidNumber attributes, or gidNumber is not an integer).
        ``httpx.HTTPError``
            An HTTP client error occurred trying to talk to the authentication
            provider.
        jwt.exceptions.InvalidTokenError
            The token returned by the OpenID Connect provider was invalid.
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "redirect_uri": self._config.redirect_url,
        }
        self._logger.info(
            "Retrieving ID token from %s", self._config.token_url
        )
        r = await self._http_client.post(
            self._config.token_url,
            data=data,
            headers={"Accept": "application/json"},
        )

        # If the call failed, try to extract an error from the reply.  If that
        # fails, just raise an exception for the HTTP status.
        try:
            result = r.json()
        except Exception:
            if r.status_code != 200:
                r.raise_for_status()
            else:
                msg = "Response from {self._config.token_url} not valid JSON"
                raise OIDCException(msg)
        if r.status_code != 200 and "error" in result:
            msg = result["error"] + ": " + result["error_description"]
            raise OIDCException(msg)
        elif r.status_code != 200:
            r.raise_for_status()
        if "id_token" not in result:
            msg = f"No id_token in token reply from {self._config.token_url}"
            raise OIDCException(msg)

        # Extract and verify the token.
        unverified_token = OIDCToken(encoded=result["id_token"])

        # determine if we want to attempt to get uid from the token or 1ldap
        uidNumber = None
        # if self._ldap_config.uid_number_attr is None, then assume we want
        # the uid from the token
        uid_from_token = True
        if self._ldap_config and self._ldap_config.uid_number_attr:
            uid_from_token = False
        try:
            token = await self._verifier.verify_oidc_token(
                unverified_token, verify_uid=uid_from_token
            )
        except (jwt.InvalidTokenError, VerifyTokenException) as e:
            msg = f"OpenID Connect token verification failed: {str(e)}"
            raise OIDCException(msg)

        # If configured with LDAP support, get user group information from
        # LDAP.  Otherwise, extract it from the token.
        if self._ldap_config:
            # if configured, extract uidNumber from LDAP
            uidNumber = await self._get_ldap_uid_number(token.username)
            groups = await self._get_ldap_groups(token.username)
        else:
            uidNumber = token.uid
            groups = []
            invalid_groups = {}
            try:
                for oidc_group in token.claims.get("isMemberOf", []):
                    if "name" not in oidc_group:
                        continue
                    name = oidc_group["name"]
                    if "id" not in oidc_group:
                        invalid_groups[name] = "missing id"
                        continue
                    gid = int(oidc_group["id"])
                    try:
                        groups.append(TokenGroup(name=name, id=gid))
                    except ValidationError as e:
                        invalid_groups[name] = str(e)
            except Exception as e:
                msg = f"isMemberOf claim is invalid: {str(e)}"
                raise OIDCException(msg)
        return TokenUserInfo(
            username=token.username,
            name=token.claims.get("name"),
            email=token.claims.get("email"),
            uid=uidNumber,
            groups=groups,
        )

    async def logout(self, session: State) -> None:
        """User logout callback.

        Currently, this does nothing.

        Parameters
        ----------
        session : `gafaelfawr.models.state.State`
            The session state, which contains the GitHub access token.
        """
        pass

    async def _get_ldap_uid_number(self, uid: str) -> int:
        """Retrieve the uid number from ldap

        Parameters
        ----------
        uid : `str`
            Username of the user.

        Returns
        -------
        uidNumber : `int`
            The numeric id of the user from LDAP.

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            The lookup using uid_number_attr against the LDAP server was not
            valid (attribute not in LDAP or resultant value not an integer)
        """
        assert self._ldap_config
        attr = self._ldap_config.uid_number_attr
        search = f"(&(uid={uid}))"

        self._logger.debug(
            f"querying ldap {self._ldap_config.url} at "
            f"{self._ldap_config.base_dn} for uid number with {search}"
        )
        client = bonsai.LDAPClient(self._ldap_config.url)
        async with client.connect(is_async=True) as conn:
            results = await conn.search(
                self._ldap_config.base_dn,
                bonsai.LDAPSearchScope.ONE,
                search,
                attrlist=[attr],
            )
            # parse uidNumber
            uidNumber = None
            for result in results:
                try:
                    self._logger.debug(f"ldap result: {result}")
                    return int(result[attr][0])
                except Exception as e:
                    msg = (
                        f"LDAP uid number using {attr} "
                        f"for user {uid} invalid: {str(e)}"
                    )
                    raise LDAPException(msg)
            return uidNumber

    async def _get_ldap_groups(self, uid: str) -> List[TokenGroup]:
        """Get groups for a user from LDAP.

        Parameters
        ----------
        uid : `str`
            Username of the user.

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            User's groups from LDAP.

        Raises
        ------
        gafaelfawr.exceptions.LDAPException
            One of the groups for the user in LDAP was not valid (missing
            cn or gidNumber attributes, or gidNumber is not an integer)
        """
        assert self._ldap_config
        group_class = self._ldap_config.group_object_class
        member_attr = self._ldap_config.group_member
        ldap_query = f"(&(objectClass={group_class})({member_attr}={uid}))"

        self._logger.debug(
            f"querying ldap {self._ldap_config.url} at "
            f"{self._ldap_config.base_dn} for groups with {ldap_query}"
        )
        client = bonsai.LDAPClient(self._ldap_config.url)
        async with client.connect(is_async=True) as conn:
            results = await conn.search(
                self._ldap_config.base_dn,
                bonsai.LDAPSearchScope.SUB,
                ldap_query,
                attrlist=["cn", "gidNumber"],
            )

            # Parse the results into the group list.
            groups = []
            for result in results:
                name = None
                try:
                    self._logger.debug(f"ldap result: {result}")
                    name = result["cn"][0]
                    gid = int(result["gidNumber"][0])
                    groups.append(TokenGroup(name=name, id=gid))
                except Exception as e:
                    msg = f"LDAP group {name} for user {uid} invalid: {str(e)}"
                    raise LDAPException(msg)
            return groups
