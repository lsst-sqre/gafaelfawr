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
from typing import Dict, Any, Tuple, List

from flask import current_app

logger = logging.getLogger(__name__)


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
