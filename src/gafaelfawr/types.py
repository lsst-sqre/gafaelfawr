"""Pydantic data types for Gafaelfawr models."""

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import BeforeValidator, PlainSerializer, PlainValidator
from safir.pydantic import UtcDatetime

__all__ = [
    "IpAddress",
    "Scopes",
    "Timestamp",
]


def _normalize_ip_address(v: str | IPv4Address | IPv6Address) -> str:
    """Pydantic validator for IP address fields.

    Convert the PostgreSQL INET type to `str` to support reading entries from
    a PostgreSQL database.

    Parameters
    ----------
    v
        Field representing an IP address.

    Returns
    -------
    str
        Converted IP address.
    """
    if isinstance(v, IPv4Address | IPv6Address):
        return str(v)
    else:
        return v


type IpAddress = Annotated[str, BeforeValidator(_normalize_ip_address)]
"""Type for an IP address.

Used instead of ``pydantic.networks.IPvAnyAddress`` because most of Gafaelfawr
deals with IP addresses as strings and the type conversion is tedious and
serves no real purpose.
"""


def _normalize_scopes(v: str | Iterable[str]) -> set[str]:
    """Pydantic validator for scope fields.

    Scopes are stored in the database as a comma-delimited, sorted list.
    Convert to the list representation we want to use in Python, ensuring the
    scopes remain sorted.

    Parameters
    ----------
    v
        Field representing token scopes.

    Returns
    -------
    set of str
        Scopes as a set.
    """
    if isinstance(v, str):
        return set() if not v else set(v.split(","))
    else:
        return set(v)


type Scopes = Annotated[
    set[str],
    PlainValidator(_normalize_scopes),
    PlainSerializer(
        lambda s: sorted(s), return_type=list[str], when_used="json"
    ),
]
"""Type for a list of scopes.

The scopes will be forced to sorted order on serialization.
"""


type Timestamp = Annotated[
    UtcDatetime,
    PlainSerializer(lambda t: int(t.timestamp()), return_type=int),
]
"""Type for a `datetime` field that serializes to seconds since epoch."""
