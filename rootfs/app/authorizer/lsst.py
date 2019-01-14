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


from .config import Config
from typing import Dict, Tuple, Any

RESOURCE_TO_ABSTRACT_GROUP_PREFIX = {
    "image": "img",
    "image/metadata": "img_md",
    "tap": "tap",
    "tap/efd": "tap_efd",
    "tap/user": "tap_usr",
    "tap/history": "tap_hist",
    "workspace": "ws",
    "workspace/user": "ws_usr",
    "portal": "portal",
    "notebook": "nb"
}

OP_TO_ABSTRACT_GROUP_POSTFIX = {
    "read": "_r",
    "write": "_w",
    "exec": "_x"
}


# noinspection PyUnusedLocal
def lsst_group_membership_check_access(capability: str, request_method: str, request_path: str,
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
    user_groups = token.get("isMemberOf")
    capability_group = _group_membership_get_group(capability)
    if capability_group in user_groups:
        return True, "Success"
    return False, "No Capability group found in user's `isMemberOfGroups`"


def _group_membership_get_group(capability: str) -> str:
    """
    Given a capability, find a group that represents this capability.
    :param capability: The capability in question
    :return: A string value of the group for this capability.
    """
    (op, resource) = capability.split(":")

    prefix = RESOURCE_TO_ABSTRACT_GROUP_PREFIX[resource]
    postfix = OP_TO_ABSTRACT_GROUP_POSTFIX[op]
    abstract_group = f"{prefix}{postfix}"
    group = f"{Config.GROUP_DEPLOYMENT_PREFIX}{abstract_group}"
    return group
