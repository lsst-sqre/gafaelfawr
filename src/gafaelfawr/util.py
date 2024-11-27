"""General utility functions."""

from __future__ import annotations

import base64
import hashlib
import os
import re

from .constants import BOT_USERNAME_REGEX

__all__ = [
    "add_padding",
    "base64_to_number",
    "group_name_for_github_team",
    "is_bot_user",
    "normalize_scopes",
    "number_to_base64",
    "random_128_bits",
]


def add_padding(encoded: str) -> str:
    """Add padding to base64 encoded bytes.

    Parameters
    ----------
    encoded
        A base64-encoded string, possibly with the padding removed.

    Returns
    -------
    str
        A correctly-padded version of the encoded string.
    """
    underflow = len(encoded) % 4
    if underflow:
        return encoded + ("=" * (4 - underflow))
    else:
        return encoded


def base64_to_number(data: str) -> int:
    """Convert base64-encoded bytes to an integer.

    Parameters
    ----------
    data
        Base64-encoded number, possibly without padding.

    Returns
    -------
    int
        The result converted to a number.  Note that Python ints can be
        arbitrarily large.

    Notes
    -----
    Used for converting the modulus and exponent in a JWKS to integers in
    preparation for turning them into a public key.
    """
    decoded = base64.urlsafe_b64decode(add_padding(data))
    return int.from_bytes(decoded, byteorder="big")


def is_bot_user(username: str) -> bool:
    """Return whether the given username is a bot user.

    Parameters
    ----------
    username
        Username to check.
    """
    return re.search(BOT_USERNAME_REGEX, username) is not None


def group_name_for_github_team(organization: str, team: str) -> str:
    """Convert a GitHub organization and team to a group name.

    Paramters
    ---------
    organization
        Name of organization.
    team
        Slug of the team.

    Returns
    -------
    str
        Group name suitable for use as a Gafaelfawr group.

    Notes
    -----
    The default construction is the organization name (from the login field),
    a dash, and the team slug.  If this is over 32 characters, it will be
    truncated to 25 characters and the first six characters of a hash of the
    full name will be appended for uniqueness.
    """
    group_name = f"{organization.lower()}-{team}"
    if len(group_name) > 32:
        name_hash = hashlib.sha256(group_name.encode()).digest()
        suffix = base64.urlsafe_b64encode(name_hash).decode()[:6]
        group_name = group_name[:25] + "-" + suffix
    return group_name


def normalize_scopes(v: str | list[str] | None) -> list[str] | None:
    """Pydantic validator for scope fields.

    Scopes are stored in the database as a comma-delimited, sorted list.
    Convert to the list representation we want to use in Python, preserving
    `None`.

    Parameters
    ----------
    v
        The field representing token scopes.

    Returns
    -------
    list of str or None
        The scopes as a list.
    """
    if v is None:
        return None
    elif isinstance(v, str):
        return [] if not v else v.split(",")
    else:
        return v


def number_to_base64(data: int) -> bytes:
    """Convert an integer to base64-encoded bytes in big endian order.

    The base64 encoding used here is the Base64urlUInt encoding defined in RFC
    7515 and 7518, which uses the URL-safe encoding characters and omits all
    padding.

    Parameters
    ----------
    data
        Arbitrarily large number

    Returns
    -------
    bytes
        The equivalent URL-safe base64-encoded string corresponding to the
        number in big endian order.
    """
    bit_length = data.bit_length()
    byte_length = bit_length // 8 + 1
    data_as_bytes = data.to_bytes(byte_length, byteorder="big", signed=False)
    return base64.urlsafe_b64encode(data_as_bytes).rstrip(b"=")


def random_128_bits() -> str:
    """Generate random 128 bits encoded in base64 without padding."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
