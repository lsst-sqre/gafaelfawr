import logging
from typing import Any, Dict, List, Mapping, Set, Tuple

import jwt
from flask import current_app, request
from jwt import InvalidIssuerError

from jwt_authorizer.config import AccessT
from jwt_authorizer.tokens import ALGORITHM, get_key_as_pem

logger = logging.getLogger(__name__)


def authenticate(encoded_token: str) -> Mapping[str, Any]:
    """
    Authenticate the token.
    Upon successful authentication, the decoded token is returned.
    Otherwise, an exception is thrown.
    :param encoded_token: The encoded token in string form
    :return: The verified token
    :raises PyJWTError: if there's an issue decoding the token
    :raises Exception: if there's some other issue
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
        encoded_token,
        key,
        algorithms=ALGORITHM,
        audience=issuer["audience"],
        options=current_app.config.get("JWT_VERIFICATION_OPTIONS"),
    )


def authorize(verified_token: Mapping[str, Any]) -> Tuple[bool, str]:
    """
    Authorize the request based on the token.
    From the set of capabilities declared via the request,
    This method will gather the capabilities that need to be satisfied
    and determine the criteria for satisfaction.
    It will then, one by one, check authorization for each capability.
    :param verified_token: The decoded token used for authorization
    :return: A (success, message) pair. Success is true
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
        (success, message) = check_authorization(capability, verified_token)
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


def check_authorization(
    capability: str, verified_token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """
    Check the authorization for a given capability.
    A given capability may be authorized by zero, one, or more criteria,
    modeled as callables. All callables MUST pass, returning True,
    for authorization on the given capability to succeed.
    :param capability: The capability we are authorizing
    :param verified_token: The verified token
    :rtype: Tuple[bool, str]
    :returns: (True, message) with successful as True if the
    all checks pass, otherwiss returns (False, message)
    """

    check_access_callables = get_check_access_functions()

    successes = []
    message = ""
    for check_access in check_access_callables:
        logger.debug(f"Checking access using {check_access.__name__}")
        (successful, message) = check_access(capability, verified_token)
        if not successful:
            break
        successes.append(successful)

    success = sum(successes) == len(check_access_callables)
    return success, message


def get_check_access_functions() -> List[AccessT]:
    """
    Return the check access callable for a resource.
    :return: A callable for check access
    """
    callables = []
    for checker_name in current_app.config["ACCESS_CHECKS"]:
        callables.append(current_app.ACCESS_CHECK_CALLABLES[checker_name])
    return callables


def scope_check_access(
    capability: str, token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this
    service based on the assumption the token has a "scope" claim.
    :param capability: The capability we are checking against
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
     scitoken allows for op and the user can read/write the file,
     otherwise return (False, message)
    """
    capabilites = set(token.get("scope", "").split(" "))
    if capability in capabilites:
        return True, "Success"
    return False, f"No capability found: {capability}"


def group_membership_check_access(
    capability: str, token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this
    service based on some form of group membership or explicitly, by
    checking ``scope`` as in :py:func:`scope_check_access`.
    :param capability: The capability we are checking against
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
     scitoken allows for op and the user can read/write the file,
     otherwise return (False, message)
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
    :return: A list of capabilities to check, and the strategy to check
    them by.
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
