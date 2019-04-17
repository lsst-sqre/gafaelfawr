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


from typing import Tuple, Any, Mapping

from flask import current_app

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
    "notebook": "nb",
}

OP_TO_ABSTRACT_GROUP_POSTFIX = {"read": "_r", "write": "_w", "exec": "_x"}


# noinspection PyUnusedLocal
def lsst_users_membership_check_access(
    capability: str, token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Check that a user is in the lsst_users group.
    :param capability: The capability we are checking against (Ignored)
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    user_group = "lsst_users"
    groups_for_user = token.get("isMemberOf")
    if not groups_for_user:
        return False, "No Groups found for user: user is not an LSST user"
    groups_set_for_user = {g["name"] for g in groups_for_user}
    if user_group in groups_set_for_user:
        return True, "Success"
    return False, f"No group {user_group} found in user's `isMemberOf`: user is not an LSST user"


def lsst_group_membership_check_access(
    capability: str, token: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Check that a user has access with the following operation to this service
    based on some form of group membership.
    :param capability: The capability we are checking against
    :param token: The token necessary
    :rtype: Tuple[bool, str]
    :returns: (successful, message) with successful as True if the
    scitoken allows for op and the user can read/write the file, otherwise
    return (False, message)
    """
    groups_for_user = token.get("isMemberOf")
    if not groups_for_user:
        return False, "No Groups found for user"
    capability_group = _group_membership_get_group(capability)
    groups_set_for_user = {g["name"] for g in groups_for_user}
    if capability_group in groups_set_for_user:
        return True, "Success"
    return False, "No Capability group found in user's `isMemberOf`"


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
    group = f"{current_app.config['GROUP_DEPLOYMENT_PREFIX']}{abstract_group}"
    return group
