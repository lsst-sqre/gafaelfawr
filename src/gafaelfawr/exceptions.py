"""Exceptions for Gafaelfawr."""

from __future__ import annotations

from typing import ClassVar

import kopf
from fastapi import status
from pydantic import ValidationError
from safir.fastapi import ClientRequestError
from safir.models import ErrorLocation
from safir.slack.blockkit import SlackException, SlackWebException

__all__ = [
    "DuplicateTokenNameError",
    "ExternalUserInfoError",
    "FetchKeysError",
    "FirestoreError",
    "FirestoreNotInitializedError",
    "ForgeRockError",
    "ForgeRockWebError",
    "GitHubError",
    "GitHubWebError",
    "InputValidationError",
    "InsufficientScopeError",
    "InvalidClientError",
    "InvalidCSRFError",
    "InvalidCursorError",
    "InvalidDelegateToError",
    "InvalidExpiresError",
    "InvalidGrantError",
    "InvalidIPAddressError",
    "InvalidMinimumLifetimeError",
    "InvalidRequestError",
    "InvalidReturnURLError",
    "InvalidScopesError",
    "InvalidTokenClaimsError",
    "InvalidTokenError",
    "KubernetesError",
    "KubernetesObjectError",
    "LDAPError",
    "MissingGIDClaimError",
    "MissingUIDClaimError",
    "MissingUsernameClaimError",
    "NoAvailableGidError",
    "NoAvailableUidError",
    "NoScopesError",
    "NotConfiguredError",
    "NotFoundError",
    "OAuthError",
    "OAuthBearerError",
    "OIDCError",
    "OIDCNotEnrolledError",
    "OIDCWebError",
    "PermissionDeniedError",
    "ProviderError",
    "ProviderWebError",
    "UnauthorizedClientError",
    "UnknownAlgorithmError",
    "UnknownKeyIdError",
    "UnsupportedGrantTypeError",
    "VerifyTokenError",
]


class InputValidationError(ClientRequestError, kopf.PermanentError):
    """Represents an input validation error.

    This is a thin wrapper around `~safir.fastapi.ClientRequestError` to add
    inheritance from `kopf.PermanentError` for the Kubernetes operator.
    """


class DuplicateTokenNameError(InputValidationError):
    """The user tried to reuse the name of a token."""

    error = "duplicate_token_name"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, ["token_name"])


class InvalidCSRFError(InputValidationError):
    """Invalid or missing CSRF token."""

    error = "invalid_csrf"
    status_code = status.HTTP_403_FORBIDDEN

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.header, ["X-CSRF-Token"])


class InvalidCursorError(InputValidationError):
    """The provided cursor was invalid."""

    error = "invalid_cursor"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, ["cursor"])


class InvalidDelegateToError(InputValidationError):
    """The ``delegate_to`` parameter was set to an invalid value."""

    error = "invalid_delegate_to"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, ["delegate_to"])


class InvalidExpiresError(InputValidationError):
    """The provided token expiration time was invalid."""

    error = "invalid_expires"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, ["expires"])


class InvalidIPAddressError(InputValidationError):
    """The provided IP address has invalid syntax."""

    error = "invalid_ip_address"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, ["ip_address"])


class InvalidMinimumLifetimeError(InputValidationError):
    """The ``minimum_lifetime`` parameter was set to an invalid value."""

    error = "invalid_minimum_lifetime"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, ["minimum_lifetime"])


class InvalidReturnURLError(InputValidationError):
    """Client specified an unsafe return URL."""

    error = "invalid_return_url"

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message, ErrorLocation.query, [field])


class InvalidScopesError(InputValidationError):
    """The provided token scopes are invalid or not available."""

    error = "invalid_scopes"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, ["scopes"])


class NoScopesError(InputValidationError):
    """The user has no valid scopes and therefore cannot log in."""

    error = "permission_denied"
    status_code = status.HTTP_403_FORBIDDEN


class NotConfiguredError(InputValidationError):
    """The requested operation was not configured."""

    error = "not_supported"
    status_code = status.HTTP_404_NOT_FOUND


class NotFoundError(InputValidationError):
    """The named resource does not exist."""

    error = "not_found"
    status_code = status.HTTP_404_NOT_FOUND


class PermissionDeniedError(InputValidationError):
    """The user does not have permission to perform this operation."""

    error = "permission_denied"
    status_code = status.HTTP_403_FORBIDDEN


class OAuthError(Exception):
    """An OAuth-related error occurred.

    This class represents both OpenID Connect errors and OAuth 2.0 errors,
    including errors when parsing Authorization headers and bearer tokens.
    """

    error: ClassVar[str] = "invalid_request"
    """The RFC 6749 or RFC 6750 error code for this exception."""

    message: ClassVar[str] = "Unknown error"
    """The summary message to use when logging this error."""

    hide_error: ClassVar[bool] = False
    """Whether to hide the details of the error from the client."""


class InvalidClientError(OAuthError):
    """The provided client_id and client_secret could not be validated.

    This corresponds to the ``invalid_client`` error in RFC 6749: "Client
    authentication failed (e.g., unknown client, no client authentication
    included, or unsupported authentication method)."
    """

    error = "invalid_client"
    message = "Unauthorized client"


class InvalidGrantError(OAuthError):
    """The provided authorization code is not valid.

    This corresponds to the ``invalid_grant`` error in RFC 6749: "The provided
    authorization grant (e.g., authorization code, resource owner credentials)
    or refresh token is invalid, expired, revoked, does not match the
    redirection URI used in the authorization request, or was issued to
    another client."
    """

    error = "invalid_grant"
    message = "Invalid authorization code"
    hide_error = True


class UnsupportedGrantTypeError(OAuthError):
    """The grant type is not supported.

    This corresponds to the ``unsupported_grant_type`` error in RFC 6749: "The
    authorization grant type is not supported by the authorization server."
    """

    error = "unsupported_grant_type"
    message = "Unsupported grant type"


class OAuthBearerError(OAuthError):
    """An error that can be returned as a ``WWW-Authenticate`` challenge.

    Represents the subset of OAuth 2.0 errors defined in RFC 6750 as valid
    errors to return in a ``WWW-Authenticate`` header.  The string form of
    this exception is suitable for use as the ``error_description`` attribute
    of a ``WWW-Authenticate`` header.
    """

    status_code: int = status.HTTP_400_BAD_REQUEST
    """The status code to use for this HTTP error."""


class InvalidRequestError(OAuthBearerError):
    """The provided Authorization header could not be parsed.

    This corresponds to the ``invalid_request`` error in RFC 6749 and 6750:
    "The request is missing a required parameter, includes an unsupported
    parameter or parameter value, repeats the same parameter, uses more than
    one method for including an access token, or is otherwise malformed."
    """

    error = "invalid_request"
    message = "Invalid request"


class InvalidTokenError(OAuthBearerError):
    """The provided token was invalid.

    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons."
    """

    error = "invalid_token"
    message = "Invalid token"
    status_code = status.HTTP_401_UNAUTHORIZED


class InsufficientScopeError(OAuthBearerError):
    """The provided token does not have the right authorization scope.

    This corresponds to the ``insufficient_scope`` error in RFC 6750: "The
    request requires higher privileges than provided by the access token."
    """

    error = "insufficient_scope"
    message = "Permission denied"
    status_code = status.HTTP_403_FORBIDDEN


class ExternalUserInfoError(SlackException):
    """Error in external user information source.

    This is the base exception for any error in retrieving information from an
    external source of user data. External sources of data may be affected by
    an external outage, and we don't want to report uncaught exceptions for
    every attempt to query them (possibly multiple times per second), so this
    exception base class is used to catch those errors in the high-traffic
    ``/auth`` route and only log them.
    """


class FirestoreError(ExternalUserInfoError):
    """An error occurred while reading or updating Firestore data."""


class FirestoreNotInitializedError(FirestoreError):
    """Firestore has not been initialized."""


class ForgeRockError(ExternalUserInfoError):
    """An error occurred querying ForgeRock Identity Management."""


class ForgeRockWebError(ForgeRockError, SlackWebException):
    """An HTTP error occurred querying ForgeRock Identity Management."""


class NoAvailableGidError(FirestoreError):
    """The assigned UID space has been exhausted."""


class NoAvailableUidError(FirestoreError):
    """The assigned UID space has been exhausted."""


class LDAPError(ExternalUserInfoError):
    """User or group information in LDAP was invalid or LDAP calls failed."""


class KubernetesError(kopf.TemporaryError):
    """An error occurred during Kubernetes secret processing."""


class KubernetesObjectError(kopf.PermanentError):
    """A Kubernetes object could not be parsed.

    Parameters
    ----------
    kind
        Kind of the malformed Kubernetes object.
    name
        Name of the malformed Kubernetes object.
    namespace
        Namespace of the malformed Kubernetes object.
    exc
        Exception from attempting to parse the object.
    """

    def __init__(
        self,
        kind: str,
        name: str,
        namespace: str,
        exc: ValidationError,
    ) -> None:
        msg = f"{kind} {namespace}/{name} is malformed: {exc!s}"
        super().__init__(msg)


class ProviderError(SlackException):
    """Something failed while talking to an authentication provider."""


class ProviderWebError(SlackWebException, ProviderError):
    """A web request to an authentication provider failed."""


class GitHubError(ProviderError):
    """The response from GitHub for a request was invalid."""


class GitHubWebError(ProviderWebError):
    """A web request to GitHub failed."""


class OIDCError(ProviderError):
    """Response from the OpenID Connect provider was invalid or an error."""


class OIDCNotEnrolledError(OIDCError):
    """The user is not enrolled in the upstream OpenID Connect provider.

    This is raised when the username claim is missing from the ID token,
    which is how CILogon indicates that no matching enrolled user record
    could be found in LDAP for the federated identity.
    """


class OIDCWebError(ProviderWebError):
    """A web request to the OpenID Connect provider failed."""


class UnauthorizedClientError(Exception):
    """The client is not authorized to request an authorization code.

    This corresponds to the ``unauthorized_client`` error in RFC 6749.
    """


class VerifyTokenError(SlackException):
    """Base exception class for failure in verifying a token."""


class FetchKeysError(SlackWebException, VerifyTokenError):
    """Cannot retrieve the keys from an issuer."""


class InvalidTokenClaimsError(VerifyTokenError):
    """One of the claims in the token is of an invalid format."""


class MissingGIDClaimError(VerifyTokenError):
    """The token is missing the required GID claim."""


class MissingUIDClaimError(VerifyTokenError):
    """The token is missing the required UID claim."""


class MissingUsernameClaimError(VerifyTokenError):
    """The token is missing the required username claim."""


class UnknownAlgorithmError(VerifyTokenError):
    """The issuer key was for an unsupported algorithm."""


class UnknownKeyIdError(VerifyTokenError):
    """The reqeusted key ID was not found for an issuer."""
