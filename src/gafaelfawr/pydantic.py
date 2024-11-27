"""Pydantic data types for Gafaelfawr models."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, TypeAlias

from pydantic import BeforeValidator, PlainSerializer
from safir.pydantic import UtcDatetime

__all__ = [
    "IpAddress",
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


IpAddress: TypeAlias = Annotated[str, BeforeValidator(_normalize_ip_address)]
"""Type for an IP address.

Used instead of ``pydantic.networks.IPvAnyAddress`` because most of Gafaelfawr
deals with IP addresses as strings and the type conversion is tedious and
serves no real purpose.
"""


Timestamp: TypeAlias = Annotated[
    UtcDatetime,
    PlainSerializer(lambda t: int(t.timestamp()), return_type=int),
]
"""Type for a `datetime` field that serializes to seconds since epoch."""
