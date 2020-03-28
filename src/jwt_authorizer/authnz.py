"""Authentication and authorization functions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import jwt
from flask import current_app, request
from jwt import InvalidIssuerError

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.tokens import get_key_as_pem

if TYPE_CHECKING:
    from typing import Any, Dict, List, Mapping, Set, Tuple

__all__ = [
    "authenticate",
    "authorize",
    "capabilities_from_groups",
    "group_membership_check_access",
    "verify_authorization_strategy",
]


logger = logging.getLogger(__name__)


def authenticate(encoded_token: str) -> Mapping[str, Any]:
    """Authenticate the token.

    Parameters
    ----------
    encoded_token : `str`
        The encoded token in string form.

    Returns
    -------
    verified_token : Mapping[`str`, Any]
        The contents of the verified token.

    Raises
    ------
    jwt.exceptions.DecodeError
        If there's an issue decoding the token.
    jwt.exceptions.InvalidIssuerError
        If the issuer of the token is not known and therefore the token cannot
        be verified.
    """
    unverified_token = jwt.decode(
        encoded_token, algorithms=ALGORITHM, verify=False
    )
    unverified_headers = jwt.get_unverified_header(encoded_token)
    jti = unverified_token.get("jti", "UNKNOWN")
    logger.debug(f"Authenticating token with jti: {jti}")
    if current_app.config["NO_VERIFY"] is True:
        logger.debug(f"Skipping Verification of the token with jti: {jti}")
        return unverified_token

    issuer_url = unverified_token["iss"]
    if issuer_url not in current_app.config["ISSUERS"]:
        raise InvalidIssuerError(f"Unauthorized Issuer: {issuer_url}")
    issuer = current_app.config["ISSUERS"][issuer_url]

    # This can throw an InvalidIssuerError as well,
    # though it may be a server-side issue
    key = get_key_as_pem(issuer_url, unverified_headers["kid"])
    return jwt.decode(
        encoded_token, key, algorithms=ALGORITHM, audience=issuer["audience"],
    )


def authorize(verified_token: Mapping[str, Any]) -> Tuple[bool, str]:
    """Authorize the request based on the token.

    From the set of capabilities declared via the request, this method will
    gather the capabilities that need to be satisfied and determine the
    criteria for satisfaction.  It will then, one by one, check authorization
    for each capability.

    Parameters
    ----------
    verified_token : Mapping[`str`, Any]
        The decoded token used for authorization.

    Returns
    -------
    success : `bool`
        Whether access is allowed.
    message : `str`
        Error message if access is not allowed.
    """
    jti = verified_token.get("jti", "UNKNOWN")
    logger.debug(f"Authorizing token with jti: {jti}")
    if current_app.config["NO_AUTHORIZE"] is True:
        logger.debug(f"Skipping authorizatino for token with jti: {jti}")
        return True, ""

    # Authorization Checks
    capabilities, satisfy = verify_authorization_strategy()
    successes = []
    messages = []
    for capability in capabilities:
        logger.debug(
            "Checking authorization for capability: '%s' for jti: %s",
            capability,
            jti,
        )
        (success, message) = group_membership_check_access(
            capability, verified_token
        )
        successes.append(success)
        if message:
            messages.append(message)
        if success and satisfy == "any":
            break

    if satisfy == "any":
        success = True in successes
    else:
        success = sum(successes) == len(capabilities)
    message = ", ".join(messages)
    return success, message


def group_membership_check_access(
    capability: str, token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Check access based on group membership.

    Check that a user has access with the following operation to this service
    based on some form of group membership or explicitly, by checking
    ``scope`` as in :py:func:`scope_check_access`.

    Parameters
    ----------
    capability : `str`
        The capability we are authorizing.
    verified_token : Mapping[`str`, Any]
        The verified token.

    Returns
    -------
    success : `bool`
        Whether access is allowed.
    message : `str`
        Error message if access is not allowed.
    """
    # Check `isMemberOf` first
    group_capabilities = capabilities_from_groups(token)
    scope_capabilites = set(token.get("scope", "").split(" "))
    capabilities = group_capabilities.union(scope_capabilites)
    if capability in capabilities:
        return True, "Success"

    msg = (
        "No Capability group found in user's `isMemberOf` or capability in "
        "`scope`"
    )
    return False, msg


def capabilities_from_groups(token: Mapping[str, Any]) -> Set[str]:
    """Map group membership to capabilities.

    Parameters
    ----------
    verified_token : Mapping[`str`, Any]
        The verified token.

    Returns
    -------
    group_derived_capabilities : Set[`str`]
        The capabilities (as from a ``scope`` attribute) corresponding to the
        group membership described in that token.
    """
    user_groups_list: List[Dict[str, str]] = token.get("isMemberOf", dict())
    user_groups_set = {group["name"] for group in user_groups_list}
    group_derived_capabilities = set()
    for capability, group_list in current_app.config["GROUP_MAPPING"].items():
        for group in set(group_list):
            if group in user_groups_set:
                group_derived_capabilities.add(capability)
    return group_derived_capabilities


def verify_authorization_strategy() -> Tuple[List[str], str]:
    """Build the authorization strategy for the request.

    Returns
    -------
    capabilities : List[`str`]
        A list of capabilities to check for.
    strategy : `str`
        The verification strategy, either ``any`` or ``all``, saying whether
        the possession of any of the list of capabilities is enough or if all
        must be present.
    """
    # Authorization Checks
    capabilities = request.args.getlist("capability")
    satisfy = request.args.get("satisfy") or "all"

    # If no capability have been explicitly delineated in the URI,
    # get them from the request method. These shouldn't happen for
    # properly configured applications
    assert satisfy in (
        "any",
        "all",
    ), "ERROR: Logic Error, Check nginx auth_request url (satisfy)"
    assert (
        capabilities
    ), "ERROR: Check nginx auth_request url (capability_names)"
    return capabilities, satisfy
