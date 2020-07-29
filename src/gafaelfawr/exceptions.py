"""Exceptions for Gafaelfawr."""

from __future__ import annotations

__all__ = [
    "FetchKeysException",
    "GitHubException",
    "InvalidRequestException",
    "InvalidSessionHandleException",
    "InvalidTokenClaimsException",
    "InvalidTokenException",
    "MissingClaimsException",
    "OIDCException",
    "ProviderException",
    "UnknownAlgorithmException",
    "UnknownKeyIdException",
    "VerifyTokenException",
]


class InvalidRequestException(Exception):
    """The provided Authorization header could not be parsed.

    This corresponds to the ``invalid_request`` error in RFC 6750: "The
    request is missing a required parameter, includes an unsupported parameter
    or parameter value, repeats the same parameter, uses more than one method
    for including an access token, or is otherwise malformed."
    """


class InvalidSessionHandleException(Exception):
    """Session handle is not in expected format."""


class InvalidTokenClaimsException(Exception):
    """A token cannot be issued with the provided claims."""


class InvalidTokenException(Exception):
    """The provided token was invalid.

    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons."  The string form of this exception is suitable for use as the
    ``error_description`` attribute of a ``WWW-Authenticate`` header.
    """


class ProviderException(Exception):
    """An authentication provider returned an error from an API call."""


class GitHubException(ProviderException):
    """GitHub returned an error from an API call."""


class OIDCException(ProviderException):
    """The OpenID Connect provider returned an error from an API call."""


class VerifyTokenException(Exception):
    """Base exception class for failure in verifying a token."""


class FetchKeysException(VerifyTokenException):
    """Cannot retrieve the keys from an issuer."""


class MissingClaimsException(VerifyTokenException):
    """The token is missing required claims."""


class UnknownAlgorithmException(VerifyTokenException):
    """The issuer key was for an unsupported algorithm."""


class UnknownKeyIdException(VerifyTokenException):
    """The reqeusted key ID was not found for an issuer."""
