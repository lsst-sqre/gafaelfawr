"""Pydantic utility functions for Gafaelfawr.

This module exists to work around the problems discussed in `Pydantic
discussion #6395 <https://github.com/pydantic/pydantic/discussions/6395>`__.
Pydantic has nice validators that verify the structure of URLs, but the type
of the resulting field is not `str` and must be manually converted to `str`
before being used. That manual conversion is error-prone since mypy won't
always catch the lack of a conversion, depending on context.

The ``*String`` types defined here perform the same validation as the
underlying Pydantic type (plus a few other types in the same style as the
Pydantic types), but then convert the resulting validated URL to `str` and
declare the type appropriately for mypy.
"""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import (
    HttpUrl,
    PostgresDsn,
    RedisDsn,
    TypeAdapter,
    UrlConstraints,
)
from pydantic_core import Url

__all__ = [
    "HttpUrlString",
    "HttpsUrl",
    "HttpsUrlString",
    "LdapDsn",
    "LdapDsnString",
    "PostgresDsnString",
    "RedisDsnString",
]

HttpsUrl: TypeAlias = Annotated[
    Url,
    UrlConstraints(
        allowed_schemes=["https"], host_required=True, max_length=2083
    ),
]
"""Type for an ``https`` URL."""

LdapDsn: TypeAlias = Annotated[
    Url,
    UrlConstraints(allowed_schemes=["ldap", "ldaps"], host_required=True),
]
"""Type for a URL specifying an LDAP data source."""

_http_url_adapter = TypeAdapter(HttpUrl)
_https_url_adapter = TypeAdapter(HttpsUrl)
_ldap_dsn_adapter = TypeAdapter(LdapDsn)
_postgres_dsn_adapter = TypeAdapter(PostgresDsn)
_redis_dsn_adapter = TypeAdapter(RedisDsn)

HttpUrlString: TypeAlias = Annotated[
    str, lambda v: str(_http_url_adapter.validate_python(v))
]
"""Type for an HTTP URL converted to a string."""

HttpsUrlString: TypeAlias = Annotated[
    str, lambda v: str(_https_url_adapter.validate_python(v))
]
"""Type for an ``https`` URL converted to a string."""

LdapDsnString: TypeAlias = Annotated[
    str, lambda v: str(_ldap_dsn_adapter.validate_python(v))
]
"""Type for an LDAP data source URL converted to a string."""

PostgresDsnString: TypeAlias = Annotated[
    str, lambda v: str(_postgres_dsn_adapter.validate_python(v))
]
"""Type for a PostgreSQL data source URL converted to a string."""

RedisDsnString: TypeAlias = Annotated[
    str, lambda v: str(_redis_dsn_adapter.validate_python(v))
]
"""Type for a Redis data source URL converted to a string."""
