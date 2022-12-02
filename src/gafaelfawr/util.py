"""General utility functions."""

from __future__ import annotations

import base64
import os
import re
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Callable, Optional, Union

from safir.database import datetime_from_db

from .constants import BOT_USERNAME_REGEX

__all__ = [
    "add_padding",
    "base64_to_number",
    "current_datetime",
    "is_bot_user",
    "normalize_datetime",
    "normalize_ip_address",
    "normalize_scopes",
    "normalize_timedelta",
    "number_to_base64",
    "random_128_bits",
    "to_camel_case",
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


def current_datetime() -> datetime:
    """Return the current time without microseconds."""
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def format_datetime_for_logging(date: Optional[datetime]) -> Optional[str]:
    """Format a datetime for logging.

    Parameters
    ----------
    date
        The object to format.

    Returns
    -------
    str or None
        The datetime in ISO format with seconds, or `None` if the input was
        `None`.
    """
    if date:
        return date.isoformat(sep=" ", timespec="seconds")
    else:
        return None


def is_bot_user(username: str) -> bool:
    """Return whether the given username is a bot user.

    Parameters
    ----------
    username
        Username to check.
    """
    return re.search(BOT_USERNAME_REGEX, username) is not None


def normalize_datetime(
    v: Optional[Union[int, datetime]]
) -> Optional[datetime]:
    """Pydantic validator for datetime fields.

    This decodes fields encoded as seconds since epoch and ensures that
    datetimes are always stored in the model as timezone-aware UTC datetimes.

    Parameters
    ----------
    v
        The field representing a `datetime`

    Returns
    -------
    datetime.datetime or None
        The timezone-aware `datetime.datetime` or `None` if the input was
        `None`.
    """
    if v is None:
        return v
    elif isinstance(v, int):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    elif v.tzinfo and v.tzinfo.utcoffset(v) is not None:
        return v.astimezone(timezone.utc)
    else:
        return datetime_from_db(v)


def normalize_ip_address(
    v: Optional[Union[str, IPv4Address, IPv6Address]]
) -> Optional[str]:
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


def normalize_scopes(
    v: Optional[Union[str, list[str]]]
) -> Optional[list[str]]:
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


def normalize_timedelta(v: Optional[int]) -> Optional[timedelta]:
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


def to_camel_case(string: str) -> str:
    """Convert a string to camel case.

    Originally written for use with Pydantic as an alias generator so that the
    model can be initialized from camel-case input (such as Kubernetes
    objects).

    Parameters
    ----------
    string
        Input string

    Returns
    -------
    str
        String converted to camel-case with the first character in lowercase.
    """
    components = string.split("_")
    return components[0] + "".join(c.title() for c in components[1:])


def validate_exactly_one_of(
    *settings: str,
) -> Callable[[Any, dict[str, Any]], Any]:
    """Generate a validator imposing a one and only one constraint.

    Sometimes, models have a set of attributes of which one and only one may
    be set.  Ideally this is represented properly in the type system, but
    occasionally it's more convenient to use a validator.  This is a validator
    generator that can produce a validator function that ensures one and only
    one of an arbitrary set of attributes must be set.

    Parameters
    ----------
    *settings
        List of names of attributes, of which one and only one must be set.

    Returns
    -------
    Callable
        The validator.

    Examples
    --------
    Use this inside a Pydantic class as a validator as follows:

    .. code-block:: python

       class Foo(BaseModel):
           foo: Optional[str] = None
           bar: Optional[str] = None
           baz: Optional[str] = None

           _validate_options = validator("baz", always=True, allow_reuse=True)(
               validate_exactly_one_of("foo", "bar", "baz")
           )

    The attribute listed as the first argument to the ``validator`` call must
    be the last attribute in the model definition so that any other attributes
    have already been seen.
    """
    if len(settings) == 2:
        options = f"{settings[0]} and {settings[1]}"
    else:
        options = ", ".join(settings[:-1]) + ", and " + settings[-1]

    def validator(v: Any, values: dict[str, Any]) -> Any:
        seen = v is not None
        for setting in settings:
            if setting in values and values[setting] is not None:
                if seen:
                    raise ValueError(f"only one of {options} may be given")
                seen = True
        if not seen:
            raise ValueError(f"one of {options} must be given")
        return v

    return validator
