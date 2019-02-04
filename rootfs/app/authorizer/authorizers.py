# LSST Data Management System
# Copyright 2018 AURA/LSST.
#
# This product includes software developed by the
# LSST Project (http://www.lsst.org/).
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
# You should have received a copy of the LSST License Statement and
# the GNU General Public License along with this program.  If not,
# see <http://www.lsstcorp.org/LegalNotices/>.

import logging
from typing import Dict, Any, Tuple, List

from .config import Config

logger = logging.getLogger(__name__)


# noinspection PyUnusedLocal
def scp_check_access(capability: str, request_method: str, request_path: str,
                     token: Dict[str, Any]) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this
    service based on the assumption the token has a "scp" claim.
    :param capability: The capability we are checking against
    :param request_method: The operation requested for this service
    :param request_path: The uri that will be tested
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    capabilites = set(token.get("scp"))
    if capability in capabilites:
        return True, "Success"
    return False, f"No capability found: {capability}"


# noinspection PyUnusedLocal
def group_membership_check_access(capability: str, request_method: str, request_path: str,
                                  token: Dict[str, Any]) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this service
    based on some form of group membership.
    :param capability: The capability we are checking against
    :param request_method: The operation requested for this service
    :param request_path: The uri that will be tested
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    user_groups_list: List[Dict[str, str]] = token.get("isMemberOf")
    if user_groups_list is None:
        return False, "claim `isMemberOf` not found"
    user_groups_map = {group["name"]: group for group in user_groups_list}
    capability_group = _group_membership_get_group(capability)
    if capability_group in user_groups_map:
        return True, "Success"
    return False, "No Capability group found in user's `isMemberOf`"


def _group_membership_get_group(capability: str) -> str:
    """
    Given a capability, find a group that represents this capability.
    :param capability: The capability in question
    :return: A string value of the group for this capability.
    """
    group = Config.GROUP_MAPPING.get(capability)
    assert capability is not None, "Error: Capability not found in group mapping"
    assert group is not None, "Error: No group mapping for capability"
    return group
