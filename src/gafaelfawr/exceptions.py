"""Exceptions for Gafaelfawr."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import ClassVar, Dict

    from structlog import BoundLogger

__all__ = [
    "DeserializeException",
    "FetchKeysException",
    "GitHubException",
    "InvalidClientError",
    "InvalidGrantError",
    "InvalidRequestError",
    "InvalidSessionHandleException",
    "InvalidTokenClaimsException",
    "InvalidTokenException",
    "MissingClaimsException",
    "OIDCException",
    "ProviderException",
    "UnauthorizedClientException",
    "UnknownAlgorithmException",
    "UnknownKeyIdException",
    "VerifyTokenException",
]


class DeserializeException(Exception):
    """A stored object could not be decrypted or deserialized.

    Used for data stored in the backing store, such as sessions or user
    tokens.  Should normally be treated the same as a missing object, but
    reported separately so that an error can be logged.
    """


class OIDCServerError(Exception):
    """An error occurred while processing an OpenID Connect server request."""

    # These class variables must be overridden in subclasses.
    error: ClassVar[str] = "unknown_error"
    message: ClassVar[str] = "Unknown error"

    def as_dict(self) -> Dict[str, str]:
        """Return the JSON form of this exception, ready for serialization."""
        return {
            "error": self.error,
            "error_description": str(self),
        }

    def log_warning(self, logger: BoundLogger) -> None:
        """Log this error to the provided logger."""
        logger.warning("%s", self.message, error=str(self))


class InvalidClientError(OIDCServerError):
    """The provided client_id and client_secret could not be validated.

    This corresponds to the ``invalid_client`` error in RFC 6749: "Client
    authentication failed (e.g., unknown client, no client authentication
    included, or unsupported authentication method)."
    """

    error = "invalid_client"
    message = "Unauthorized client"


class InvalidGrantError(OIDCServerError):
    """The provided authorization code is not valid.

    This corresponds to the ``invalid_grant`` error in RFC 6749: "The provided
    authorization grant (e.g., authorization code, resource owner credentials)
    or refresh token is invalid, expired, revoked, does not match the
    redirection URI used in the authorization request, or was issued to
    another client."
    """

    error = "invalid_grant"
    message = "Invalid authorization code"

    def as_dict(self) -> Dict[str, str]:
        return {
            "error": self.error,
            "error_description": self.message,
        }


class InvalidRequestError(OIDCServerError):
    """The provided Authorization header could not be parsed.

    This corresponds to the ``invalid_request`` error in RFC 6749 and 6750:
    "The request is missing a required parameter, includes an unsupported
    parameter or parameter value, repeats the same parameter, uses more than
    one method for including an access token, or is otherwise malformed."
    """

    error = "invalid_request"
    message = "Invalid request"


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


class UnauthorizedClientException(Exception):
    """The client is not authorized to request an authorization code.

    This corresponds to the ``unauthorized_client`` error in RFC 6749.
    """


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
