# This file is part of jwt_authorizer.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import logging
from typing import Dict, Any, Tuple, List, Mapping, Callable

import jwt
from flask import current_app, request
from jwt import InvalidIssuerError

from .token import get_key_as_pem, ALGORITHM

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
    unverified_token = jwt.decode(encoded_token, verify=False)
    unverified_headers = jwt.get_unverified_header(encoded_token)
    if current_app.config["NO_VERIFY"] is True:
        logger.debug("Skipping Verification of the token")
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
        algorithm=ALGORITHM,
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
    if current_app.config["NO_AUTHORIZE"] is True:
        return True, ""

    # Authorization Checks
    capabilities = request.args.getlist("capability")
    satisfy = request.args.get("satisfy") or "all"

    # If no capability have been explicitly delineated in the URI,
    # get them from the request method. These shouldn't happen for properly
    # configured applications
    assert satisfy in ("any", "all"), "ERROR: Logic Error, Check nginx auth_request url (satisfy)"
    assert capabilities, "ERROR: Check nginx auth_request url (capability_names)"

    successes = []
    messages = []
    for capability in capabilities:
        logger.debug(f"Checking authorization for capability: {capability}")
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


def check_authorization(capability: str, verified_token: Mapping[str, Any]) -> Tuple[bool, str]:
    """
    Check the authorization for a given capability.
    A given capability may be authorized by zero, one, or more criteria,
    modeled as a callables. All callables MUST pass, returning True,
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


def get_check_access_functions() -> List[Callable]:
    """
    Return the check access callable for a resource.
    :return: A callable for check access
    """
    callables = []
    for checker_name in current_app.config["ACCESS_CHECKS"]:
        callables.append(current_app.ACCESS_CHECK_CALLABLES[checker_name])
    return callables


def scp_check_access(capability: str, token: Dict[str, Any]) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this
    service based on the assumption the token has a "scp" claim.
    :param capability: The capability we are checking against
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    capabilites = set(token.get("scp", list()))
    if capability in capabilites:
        return True, "Success"
    return False, f"No capability found: {capability}"


def group_membership_check_access(capability: str, token: Dict[str, Any]) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this
    service based on some form of group membership.
    Also checks `scp` as in :py:func:`scp_check_access`.
    :param capability: The capability we are checking against
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    # Check `isMemberOf` first
    user_groups_list: List[Dict[str, str]] = token.get("isMemberOf", dict())
    if user_groups_list is None:
        return False, "claim `isMemberOf` not found"
    user_groups_map = {group["name"]: group for group in user_groups_list}
    capability_group = _group_membership_get_group(capability)
    if capability_group in user_groups_map:
        return True, "Success"

    # Check `scp` next
    capabilites = set(token.get("scp", list()))
    if capability in capabilites:
        return True, "Success"

    return False, "No Capability group found in user's `isMemberOf` or capability in `scp`"


def _group_membership_get_group(capability: str) -> str:
    """
    Given a capability, find a group that represents this capability.
    :param capability: The capability in question
    :return: A string value of the group for this capability.
    """
    group = current_app.config["GROUP_MAPPING"].get(capability)
    assert capability is not None, "Error: Capability not found in group mapping"
    assert group is not None, "Error: No group mapping for capability"
    return group
