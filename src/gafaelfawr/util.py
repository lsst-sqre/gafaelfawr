"""General utility functions."""

from __future__ import annotations

import base64
import os
import re
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from .constants import BOT_USERNAME_REGEX

__all__ = [
    "add_padding",
    "base64_to_number",
    "is_bot_user",
    "normalize_ip_address",
    "normalize_scopes",
    "normalize_timedelta",
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


def normalize_ip_address(
    v: str | IPv4Address | IPv6Address | None,
) -> str | None:
    """Pydantic validator for IP address fields.

    Convert the PostgreSQL INET type to `str` to support reading entries from
    a PostgreSQL database.

    Parameters
    ----------
    v
        The field representing an IP address.

    Returns
    -------
    str or None
        The converted IP address.
    """
    if v is None:
        return v
    elif isinstance(v, (IPv4Address, IPv6Address)):
        return str(v)
    else:
        return v


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
        return [] if v == "" else v.split(",")
    else:
        return v


def normalize_timedelta(v: int | None) -> timedelta | None:
    """Pydantic validator for timedelta fields.

    Parameters
    ----------
    v
        The field representing a duration, in seconds

    Returns
    -------
    datetime.timedelta or None
        The corresponding `datetime.timedelta` or `None` if the input was
        `None`.
    """
    if v is None:
        return v
    elif isinstance(v, int):
        return timedelta(seconds=v)
    else:
        raise ValueError("invalid timedelta (should be in seconds)")


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
